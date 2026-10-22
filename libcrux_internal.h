/*  $OpenBSD: libcrux_internal.h,v 1.1 2026/06/14 03:59:34 djm Exp $ */

/* Extracted from libcrux revision c46481ce3cd1cc8315e90db114581d8c992c3d7d */

/*
 * MIT License
 *
 * Copyright (c) 2024 Cryspen
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#إذا !defined(__GNUC__) || (__GNUC__ < 2)
# define __attribute__(x)
#جے_انت
#تعریف_کرو KRML_MUSTINLINE مضمن
#تعریف_کرو KRML_NOINLINE __attribute__((noinline, بن_ورتیا))
#تعریف_کرو KRML_HOST_EPRINTF(...)
#تعریف_کرو KRML_HOST_EXIT(x) fatal_f("internal error")
#تعریف_کرو KRML_UNION_CONSTRUCTOR(T)

ساكن مضمن فراغ
store64_le(uint8_t dst[8], uint64_t src)
{
	dst[0] = src & 0xff;
	dst[1] = (src >> 8) & 0xff;
	dst[2] = (src >> 16) & 0xff;
	dst[3] = (src >> 24) & 0xff;
	dst[4] = (src >> 32) & 0xff;
	dst[5] = (src >> 40) & 0xff;
	dst[6] = (src >> 48) & 0xff;
	dst[7] = (src >> 56) & 0xff;
}

ساكن مضمن فراغ
store32_le(uint8_t dst[4], uint32_t src)
{
	dst[0] = src & 0xff;
	dst[1] = (src >> 8) & 0xff;
	dst[2] = (src >> 16) & 0xff;
	dst[3] = (src >> 24) & 0xff;
}

ساكن مضمن فراغ
store16_le(uint8_t dst[2], uint16_t src)
{
	dst[0] = src & 0xff;
	dst[1] = (src >> 8) & 0xff;
}

ساكن مضمن فراغ
store32_be(uint8_t dst[4], uint32_t src)
{
	dst[0] = (src >> 24) & 0xff;
	dst[1] = (src >> 16) & 0xff;
	dst[2] = (src >> 8) & 0xff;
	dst[3] = src & 0xff;
}

ساكن مضمن uint64_t
load64_le(uint8_t src[8])
{
	أرجع (uint64_t)(src[0]) |
	    ((uint64_t)(src[1]) << 8) |
	    ((uint64_t)(src[2]) << 16) |
	    ((uint64_t)(src[3]) << 24) |
	    ((uint64_t)(src[4]) << 32) |
	    ((uint64_t)(src[5]) << 40) |
	    ((uint64_t)(src[6]) << 48) |
	    ((uint64_t)(src[7]) << 56);
}

ساكن مضمن uint32_t
load32_le(uint8_t src[4])
{
	أرجع (uint32_t)(src[0]) |
	    ((uint32_t)(src[1]) << 8) |
	    ((uint32_t)(src[2]) << 16) |
	    ((uint32_t)(src[3]) << 24);
}

ساكن مضمن uint16_t
load16_le(uint8_t src[4])
{
	أرجع (uint16_t)(src[0]) |
	    ((uint16_t)(src[1]) << 8);
}

#جے_تعریف_شدہ MISSING_BUILTIN_POPCOUNT
ساكن مضمن بنانشانی صحيح
__builtin_popcount(بنانشانی صحيح عدد)
{
  ثابت صحيح v[16] = { 0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4 };
  أرجع v[عدد & 0xf] + v[(عدد >> 4) & 0xf];
}
#جے_انت

/* from libcrux/combined_extraction/generated/eurydice_glue.h */
#ہدایت once


#جے_تعریف_شدہ _MSC_VER
// For __popcnt
#جے_انت


// C++ HELPERS

#إذا defined(__cplusplus)

#جے_بنا_تعریف KRML_HOST_EPRINTF
#تعریف_کرو KRML_HOST_EPRINTF(...) fprintf(stderr, __VA_ARGS__)
#جے_انت


#جے_بنا_تعریف __cpp_lib_type_identity
سانچا <class T>
بنية type_پچھان_تت {
  using type = T;
};

سانچا <class T>
using type_پچھان_تت_t = typename type_پچھان_تت<T>::type;
#وإلا
using std::type_پچھان_تت_t;
#جے_انت

#تعریف_کرو KRML_UNION_CONSTRUCTOR(T)                              \
  سانچا <typename V>                                        \
  constexpr T(صحيح t, V U::*m, type_پچھان_تت_t<V> v) : ٹیگ(t) { \
    val.*m = std::move(v);                                     \
  }                                                            \
  T() = افتراضي;

#جے_انت

// GENERAL-PURPOSE STUFF

#تعریف_کرو کم_تارا_Ignore_ignore(e, t, _ret_t) ((فراغ)e)

#تعریف_کرو EURYDICE_ASSERT(test, پیغام)                                            \
  افعل {                                                                        \
    إذا (!(test)) {                                                            \
      fprintf(stderr, "assertion \"%s\" failed: file \"%s\", line %d\n", پیغام, \
              __FILE__, __LINE__);                                            \
      باہر_نکلو(255);                                                              \
    }                                                                         \
  } طالما (0)

// SIZEOF, ALIGNOF

#تعریف_کرو Eurydice_sizeof(t) حجم(t)

#تعریف_کرو Eurydice_alignof(t) alignof(t)

// SLICES, ARRAYS, ETC.

// For convenience, we give these common slice types, below, a distinguished
// status and rather than emit them in the client code, we skip their
// code-generation in Cleanup3.ml and write them by hand here. This makes it
// easy to write interop code that brings those definitions in scope.

// &[u8]
تعريفنوع بنية Eurydice_borrow_ٹکڑا_u8_s {
  ثابت uint8_t *ptr;
  ناپ_t meta;
} Eurydice_borrow_ٹکڑا_u8;

// &[u16]
تعريفنوع بنية Eurydice_borrow_ٹکڑا_i16_s {
  ثابت int16_t *ptr;
  ناپ_t meta;
} Eurydice_borrow_ٹکڑا_i16;

// &mut [u8]
تعريفنوع بنية Eurydice_mut_borrow_ٹکڑا_u8_s {
  uint8_t *ptr;
  ناپ_t meta;
} Eurydice_mut_borrow_ٹکڑا_u8;

// &mut [u16]
تعريفنوع بنية Eurydice_mut_borrow_ٹکڑا_i16_s {
  int16_t *ptr;
  ناپ_t meta;
} Eurydice_mut_borrow_ٹکڑا_i16;

#إذا defined(__cplusplus)
#تعریف_کرو KRML_CLITERAL(type) type
#وإلا
#تعریف_کرو KRML_CLITERAL(type) (type)
#جے_انت

#إذا defined(__cplusplus) && defined(__cpp_designated_initializers) || \
    !(defined(__cplusplus))
#تعریف_کرو EURYDICE_CFIELD(X) X
#وإلا
#تعریف_کرو EURYDICE_CFIELD(X)
#جے_انت

#تعریف_کرو Eurydice_array_repeat(dst, len, init, t) \
  ERROR "should've been desugared"

// Copy a slice with memcopy
#تعریف_کرو Eurydice_ٹکڑا_copy(dst, src, t) \
  حافظہ_نقل(dst.ptr, src.ptr, dst.meta * حجم(t))

#تعریف_کرو core_array_T_N_as_ٹکڑا(len_, ptr_, t, ret_t)   \
  (KRML_CLITERAL(ret_t){EURYDICE_CFIELD(.ptr =)(ptr_)->انکڑے, \
                        EURYDICE_CFIELD(.meta =) len_})

#تعریف_کرو core_array__core__clone__Clone_for__T__N___clone(len, src, elem_type, \
                                                         _ret_t)              \
  (*(src))
#تعریف_کرو Try_From_ٹکڑا_Error uint8_t
#تعریف_کرو core_array_Try_From_ٹکڑا_Error uint8_t

// Distinguished support for some PartialEq trait implementations
//
// core::cmp::PartialEq<@Array<U, N>> for @Array<T, N>
#تعریف_کرو Eurydice_array_eq(sz, a1, a2, t) \
  (memcmp((a1)->انکڑے, (a2)->انکڑے, sz * حجم(t)) == 0)
// core::cmp::PartialEq<&0 (@Slice<U>)> for @Array<T, N>
#تعریف_کرو Eurydice_array_eq_ٹکڑا_shared(sz, a1, s2, t, _) \
  (memcmp((a1)->انکڑے, (s2)->ptr, sz * حجم(t)) == 0)
#تعریف_کرو Eurydice_array_eq_ٹکڑا_mut(sz, a1, s2, t, _) \
  Eurydice_array_eq_ٹکڑا_shared(sz, a1, s2, t, _)

// DEPRECATED -- should no longer be generated
#تعریف_کرو core_array_equality__core__cmp__PartialEq__Array_U__N___for__Array_T__N___eq( \
    sz, a1, a2, t, _, _ret_t)                                                         \
  Eurydice_array_eq(sz, a1, a2, t)
#تعریف_کرو core_array_equality_core_cmp_Partial_Eq_0_ٹکڑا_U_for_Array_T_N_eq( \
    sz, a1, a2, t, _, _ret_t)                                                           \
  Eurydice_array_eq(sz, a1, ((a2)->ptr), t)
#تعریف_کرو core_cmp_impls__core__cmp__PartialEq__0_mut__B___for__1_mut__A___eq( \
    _m0, _m1, src1, src2, _0, _1, T)                                         \
  Eurydice_ٹکڑا_eq(src1, src2, _, _, T, _)

#تعریف_کرو Eurydice_ٹکڑا_ونڈو_at(ٹکڑا, mid, element_type, ret_t)        \
  KRML_CLITERAL(ret_t) {                                                \
    EURYDICE_CFIELD(.fst =){EURYDICE_CFIELD(.ptr =)((ٹکڑا).ptr),       \
                            EURYDICE_CFIELD(.meta =) mid},              \
        EURYDICE_CFIELD(.snd =) {                                       \
      EURYDICE_CFIELD(.ptr =)                                           \
      ((ٹکڑا).ptr + mid), EURYDICE_CFIELD(.meta =)((ٹکڑا).meta - mid) \
    }                                                                   \
  }

#تعریف_کرو Eurydice_ٹکڑا_ونڈو_at_mut(ٹکڑا, mid, element_type, ret_t)    \
  KRML_CLITERAL(ret_t) {                                                \
    EURYDICE_CFIELD(.fst =){EURYDICE_CFIELD(.ptr =)((ٹکڑا).ptr),       \
                            EURYDICE_CFIELD(.meta =) mid},              \
        EURYDICE_CFIELD(.snd =) {                                       \
      EURYDICE_CFIELD(.ptr =)                                           \
      ((ٹکڑا).ptr + mid), EURYDICE_CFIELD(.meta =)((ٹکڑا).meta - mid) \
    }                                                                   \
  }

// Conversion of slice to an array, rewritten (by Eurydice) to name the
// destination array, since arrays are not values in C.
// N.B.: see note in karamel/lib/Inlining.ml if you change this.

#تعریف_کرو Eurydice_ٹکڑا_منزل_ref_array2(len_, src, arr_ptr, t_ptr, t_arr, t_err, \
                                     t_res)                                   \
  (src.meta >= len_                                                           \
       ? ((t_res){.ٹیگ = core_نتیجہ_Ok, .val = {.case_Ok = arr_ptr}})        \
       : ((t_res){.ٹیگ = core_نتیجہ_Err, .val = {.case_Err = 0}}))

// CORE STUFF (conversions, endianness, ...)

// We slap extern "C" on declarations that intend to implement a prototype
// generated by Eurydice, because Eurydice prototypes are always emitted within
// an extern "C" block, UNLESS you use -fcxx17-compat, in which case, you must
// pass -DKRML_CXX17_COMPAT="" to your C++ compiler.
#إذا defined(__cplusplus) && !defined(KRML_CXX17_COMPAT)
خارجي "C" {
#جے_انت

#تعریف_کرو core_hint_black_box(X, _0, _1) (X)

// [ u8; 2 ]
تعريفنوع بنية Eurydice_array_u8x2_s {
  uint8_t انکڑے[2];
} Eurydice_array_u8x2;

// [ u8; 4 ]
تعريفنوع بنية Eurydice_array_u8x4_s {
  uint8_t انکڑے[4];
} Eurydice_array_u8x4;

// [ u8; 8 ]
تعريفنوع بنية Eurydice_array_u8x8_s {
  uint8_t انکڑے[8];
} Eurydice_array_u8x8;

ساكن مضمن uint16_t core_عدد_u16_from_le_بائٹاں(Eurydice_array_u8x2 buf) {
  أرجع load16_le(buf.انکڑے);
}

ساكن مضمن Eurydice_array_u8x4 core_عدد_u32_منزل_be_بائٹاں(uint32_t src) {
  // TODO: why not store32_be?
  Eurydice_array_u8x4 a;
  uint32_t x = htobe32(src);
  حافظہ_نقل(a.انکڑے, &x, 4);
  أرجع a;
}

ساكن مضمن Eurydice_array_u8x4 core_عدد_u32_منزل_le_بائٹاں(uint32_t src) {
  Eurydice_array_u8x4 a;
  store32_le(a.انکڑے, src);
  أرجع a;
}

ساكن مضمن uint32_t core_عدد_u32_from_le_بائٹاں(Eurydice_array_u8x4 buf) {
  أرجع load32_le(buf.انکڑے);
}

ساكن مضمن Eurydice_array_u8x8 core_عدد_u64_منزل_le_بائٹاں(uint64_t v) {
  Eurydice_array_u8x8 a;
  store64_le(a.انکڑے, v);
  أرجع a;
}

ساكن مضمن uint64_t core_عدد_u64_from_le_بائٹاں(Eurydice_array_u8x8 buf) {
  أرجع load64_le(buf.انکڑے);
}

ساكن مضمن int64_t core_convert_عدد_core_convert_From_i32_for_i64_from(
    int32_t x) {
  أرجع x;
}

ساكن مضمن uint64_t core_convert_عدد_core_convert_From_u8_for_u64_from(
    uint8_t x) {
  أرجع x;
}

ساكن مضمن uint64_t core_convert_عدد_core_convert_From_u16_for_u64_from(
    uint16_t x) {
  أرجع x;
}

ساكن مضمن ناپ_t core_convert_عدد_core_convert_From_u16_for_usize_from(
    uint16_t x) {
  أرجع x;
}

ساكن مضمن uint32_t core_عدد_u8_گنتی_ones(uint8_t x0) {
#جے_تعریف_شدہ _MSC_VER
  أرجع __popcnt(x0);
#وإلا
  أرجع __builtin_popcount(x0);
#جے_انت
}

ساكن مضمن uint32_t core_عدد_u32_گنتی_ones(uint32_t x0) {
#جے_تعریف_شدہ _MSC_VER
  أرجع __popcnt(x0);
#وإلا
  أرجع __builtin_popcount(x0);
#جے_انت
}

ساكن مضمن uint32_t core_عدد_i32_گنتی_ones(int32_t x0) {
#جے_تعریف_شدہ _MSC_VER
  أرجع __popcnt(x0);
#وإلا
  أرجع __builtin_popcount(x0);
#جے_انت
}

ساكن مضمن ناپ_t core_cmp_impls__core__cmp__Ord_for_usize__min(ناپ_t a,
                                                                   ناپ_t b) {
  إذا (a <= b)
    أرجع a;
  وإلا
    أرجع b;
}

// unsigned overflow wraparound semantics in C
ساكن مضمن uint8_t core_عدد_u8_wrapping_sub(uint8_t x, uint8_t y) {
  أرجع x - y;
}
ساكن مضمن uint8_t core_عدد_u8_wrapping_جوڑو(uint8_t x, uint8_t y) {
  أرجع x + y;
}
ساكن مضمن uint8_t core_عدد_u8_wrapping_mul(uint8_t x, uint8_t y) {
  أرجع x * y;
}
ساكن مضمن uint16_t core_عدد_u16_wrapping_sub(uint16_t x, uint16_t y) {
  أرجع x - y;
}
ساكن مضمن uint16_t core_عدد_u16_wrapping_جوڑو(uint16_t x, uint16_t y) {
  أرجع x + y;
}
ساكن مضمن uint16_t core_عدد_u16_wrapping_mul(uint16_t x, uint16_t y) {
  أرجع x * y;
}
ساكن مضمن uint32_t core_عدد_u32_wrapping_sub(uint32_t x, uint32_t y) {
  أرجع x - y;
}
ساكن مضمن uint32_t core_عدد_u32_wrapping_جوڑو(uint32_t x, uint32_t y) {
  أرجع x + y;
}
ساكن مضمن uint32_t core_عدد_u32_wrapping_mul(uint32_t x, uint32_t y) {
  أرجع x * y;
}
ساكن مضمن uint64_t core_عدد_u64_wrapping_sub(uint64_t x, uint64_t y) {
  أرجع x - y;
}
ساكن مضمن uint64_t core_عدد_u64_wrapping_جوڑو(uint64_t x, uint64_t y) {
  أرجع x + y;
}
ساكن مضمن uint64_t core_عدد_u64_wrapping_mul(uint64_t x, uint64_t y) {
  أرجع x * y;
}
ساكن مضمن ناپ_t core_عدد_usize_wrapping_sub(ناپ_t x, ناپ_t y) {
  أرجع x - y;
}
ساكن مضمن ناپ_t core_عدد_usize_wrapping_جوڑو(ناپ_t x, ناپ_t y) {
  أرجع x + y;
}
ساكن مضمن ناپ_t core_عدد_usize_wrapping_mul(ناپ_t x, ناپ_t y) {
  أرجع x * y;
}

ساكن مضمن int8_t core_عدد_i8_wrapping_جوڑو(int8_t x, int8_t y) {
  أرجع (int8_t)((uint8_t)x + (uint8_t)y);
}
ساكن مضمن int8_t core_عدد_i8_wrapping_sub(int8_t x, int8_t y) {
  أرجع (int8_t)((uint8_t)x - (uint8_t)y);
}
ساكن مضمن int8_t core_عدد_i8_wrapping_mul(int8_t x, int8_t y) {
  أرجع (int8_t)((uint8_t)x * (uint8_t)y);
}
ساكن مضمن int16_t core_عدد_i16_wrapping_جوڑو(int16_t x, int16_t y) {
  أرجع (int16_t)((uint16_t)x + (uint16_t)y);
}
ساكن مضمن int16_t core_عدد_i16_wrapping_sub(int16_t x, int16_t y) {
  أرجع (int16_t)((uint16_t)x - (uint16_t)y);
}
ساكن مضمن int16_t core_عدد_i16_wrapping_mul(int16_t x, int16_t y) {
  أرجع (int16_t)((uint16_t)x * (uint16_t)y);
}
ساكن مضمن int32_t core_عدد_i32_wrapping_جوڑو(int32_t x, int32_t y) {
  أرجع (int32_t)((uint32_t)x + (uint32_t)y);
}
ساكن مضمن int32_t core_عدد_i32_wrapping_sub(int32_t x, int32_t y) {
  أرجع (int32_t)((uint32_t)x - (uint32_t)y);
}
ساكن مضمن int32_t core_عدد_i32_wrapping_mul(int32_t x, int32_t y) {
  أرجع (int32_t)((uint32_t)x * (uint32_t)y);
}
ساكن مضمن int64_t core_عدد_i64_wrapping_جوڑو(int64_t x, int64_t y) {
  أرجع (int64_t)((uint64_t)x + (uint64_t)y);
}
ساكن مضمن int64_t core_عدد_i64_wrapping_sub(int64_t x, int64_t y) {
  أرجع (int64_t)((uint64_t)x - (uint64_t)y);
}
ساكن مضمن int64_t core_عدد_i64_wrapping_mul(int64_t x, int64_t y) {
  أرجع (int64_t)((uint64_t)x * (uint64_t)y);
}
ساكن مضمن int8_t core_عدد_i8_wrapping_neg(int8_t x) {
  أرجع (int8_t)(-(uint8_t)x);
}
ساكن مضمن int16_t core_عدد_i16_wrapping_neg(int16_t x) {
  أرجع (int16_t)(-(uint16_t)x);
}
ساكن مضمن int32_t core_عدد_i32_wrapping_neg(int32_t x) {
  أرجع (int32_t)(-(uint32_t)x);
}
ساكن مضمن int64_t core_عدد_i64_wrapping_neg(int64_t x) {
  أرجع (int64_t)(-(uint64_t)x);
}

ساكن مضمن uint64_t core_عدد_u64_rotate_بایاں(uint64_t x0, uint32_t x1) {
  أرجع (x0 << x1) | (x0 >> ((-x1) & 63));
}

ساكن مضمن فراغ core_ops_arith_i32_جوڑو_سونپو(int32_t *x0, int32_t *x1) {
  *x0 = *x0 + *x1;
}

ساكن مضمن uint8_t Eurydice_bitand_pv_u8(ثابت uint8_t *p, uint8_t v) {
  أرجع (*p) & v;
}
ساكن مضمن uint8_t Eurydice_shr_pv_u8(ثابت uint8_t *p, int32_t v) {
  أرجع (*p) >> v;
}
ساكن مضمن uint32_t Eurydice_min_u32(uint32_t x, uint32_t y) {
  أرجع x < y ? x : y;
}

ساكن مضمن uint8_t
core_ops_ثنائی_ہندسہ_core_ops_ثنائی_ہندسہ_ثنائی_ہندسہ_And_u8_u8_for_0_u8_bitand(
    ثابت uint8_t *x0, uint8_t x1) {
  أرجع Eurydice_bitand_pv_u8(x0, x1);
}

ساكن مضمن uint8_t
core_ops_ثنائی_ہندسہ_core_ops_ثنائی_ہندسہ_Shr_i32_u8_for_0_u8_shr(ثابت uint8_t *x0,
                                                            int32_t x1) {
  أرجع Eurydice_shr_pv_u8(x0, x1);
}

#تعریف_کرو core_عدد_nonzero_نجی_Non_Zero_Usize_Inner ناپ_t
ساكن مضمن core_عدد_nonzero_نجی_Non_Zero_Usize_Inner
core_عدد_nonzero_نجی_core_clone_Clone_for_core_عدد_nonzero_نجی_Non_Zero_Usize_Inner_clone(
    core_عدد_nonzero_نجی_Non_Zero_Usize_Inner *x0) {
  أرجع *x0;
}

#إذا defined(__cplusplus) && !defined(KRML_CXX17_COMPAT)
}
#جے_انت

// ITERATORS

#تعریف_کرو Eurydice_range_iter_اگلا(iter_ptr, t, ret_t)      \
  (((iter_ptr)->شروع >= (iter_ptr)->سرا)                 \
       ? (KRML_CLITERAL(ret_t){EURYDICE_CFIELD(.ٹیگ =) 0, \
                               EURYDICE_CFIELD(.f0 =) 0}) \
       : (KRML_CLITERAL(ret_t){EURYDICE_CFIELD(.ٹیگ =) 1, \
                               EURYDICE_CFIELD(.f0 =)(iter_ptr)->شروع++}))

#تعریف_کرو core_iter_range_core_iter_traits_iterator_Iterator_A_for_core_ops_range_Range_A_Trait_Clause_0_اگلا \
  Eurydice_range_iter_اگلا

// See note in karamel/lib/Inlining.ml if you change this
#تعریف_کرو Eurydice_into_iter(x, t, _ret_t, _) (x)
#تعریف_کرو core_iter_traits_collect_core_iter_traits_collect_Into_Iterator_Clause1_شے_I_for_I_into_iter \
  Eurydice_into_iter

//لڑیاں

تعريفنوع حرف Eurydice_c_char_t;
تعريفنوع ثابت Eurydice_c_char_t *Prims_string;
تعريفنوع فراغ Eurydice_c_void_t;

// UNSAFE CODE

#تعریف_کرو core_ٹکڑا_ٹکڑا_T_as_mut_ptr(x, t, _) (x.ptr)
#تعریف_کرو core_mem_ناپ_دا(t, _) (حجم(t))
#تعریف_کرو core_ٹکڑا_raw_from_raw_parts_mut(ptr, len, _0, _1) \
  (KRML_CLITERAL(Eurydice_ٹکڑا){(فراغ *)(ptr), len})
#تعریف_کرو core_ٹکڑا_raw_from_raw_parts(ptr, len, _0, _1) \
  (KRML_CLITERAL(Eurydice_ٹکڑا){(فراغ *)(ptr), len})

// FIXME: add dedicated extraction to extract NonNull<T> as T*
#تعریف_کرو core_ptr_non_null_NonNull فراغ *

// PRINTING
//
// This is temporary. Ultimately we want to be able to extract all of this.

تعريفنوع فراغ *core_fmt_Formatter;
#تعریف_کرو core_fmt_rt_core_fmt_rt_دلیل_a_new_display(x1, x2, x3, x4) \
  عدم

// BOXES

#جے_بنا_تعریف EURYDICE_MALLOC
#تعریف_کرو EURYDICE_MALLOC حافظہ_دیو
#جے_انت

#جے_بنا_تعریف EURYDICE_REALLOC
#تعریف_کرو EURYDICE_REALLOC realloc
#جے_انت

ساكن مضمن حرف *malloc_and_init(ناپ_t sz, حرف *init) {
  حرف *ptr = (حرف *)EURYDICE_MALLOC(sz);
  إذا (ptr != عدم) حافظہ_نقل(ptr, init, sz);
  أرجع ptr;
}

#تعریف_کرو Eurydice_box_new(init, t, t_dst) \
  ((t_dst)(malloc_and_init(حجم(t), (حرف *)(&init))))

// Initializer for array of size zero
#تعریف_کرو Eurydice_خالی_تھاواں_array(dummy, t, t_dst) ((t_dst){.انکڑے = {}})

#تعریف_کرو Eurydice_box_new_array(len, ptr, t, t_dst) \
  ((t_dst)(malloc_and_init(len * حجم(t), (حرف *)(ptr))))

// FIXME this needs to handle allocation failure errors, but this seems hard to
// do without evaluating malloc_and_init twice...
#تعریف_کرو alloc_boxed__alloc__boxed__Box_T___try_new(init, t, t_ret) \
  ((t_ret){.ٹیگ = core_نتیجہ_Ok,                                  \
           .f0 = (t *)malloc_and_init(حجم(t), (حرف *)(&init))})

// OPTIONS

#تعریف_کرو core_option__core__option__Option_T__TraitClause_0___is_some( \
    x, دا_type, _)                                                   \
  x->ٹیگ

/* from libcrux/combined_extraction/generated/combined_core.h */
/*
 * SPDX-FileCopyrightText: 2025 Cryspen Sarl <info@cryspen.com>
 *
 * SPDX-License-Identifier: MIT or Apache-2.0
 *
 * This code was generated with the following revisions:
 * Charon: e656e17bff6ca5efac8ab6919b9b74cb9a8dd8ad
 * Eurydice: aaa9fa657fb6f09802edb890252040d94cd93982
 * Karamel: 8c19d41458ce5cbfea029ebc03334ba96d149039
 * F*: unset
 * Libcrux: c4e5e5e511bbc4c53f826163f57bfd10e9228911
 */


#جے_بنا_تعریف combined_core_H
#تعریف_کرو combined_core_H



#إذا defined(__cplusplus)
خارجي "C" {
#جے_انت

ساكن مضمن uint32_t core_عدد_i32_گنتی_ones(int32_t x0);

ساكن مضمن uint16_t core_عدد_u16_wrapping_جوڑو(uint16_t x0, uint16_t x1);

ساكن مضمن uint64_t core_عدد_u64_from_le_بائٹاں(Eurydice_array_u8x8 x0);

ساكن مضمن uint64_t core_عدد_u64_rotate_بایاں(uint64_t x0, uint32_t x1);

ساكن مضمن Eurydice_array_u8x8 core_عدد_u64_منزل_le_بائٹاں(uint64_t x0);

ساكن مضمن uint32_t core_عدد_u8_گنتی_ones(uint8_t x0);

ساكن مضمن uint8_t core_عدد_u8_wrapping_sub(uint8_t x0, uint8_t x1);

ساكن مضمن uint8_t
core_ops_ثنائی_ہندسہ_core_ops_ثنائی_ہندسہ_ثنائی_ہندسہ_And_u8_u8_for_0_u8_bitand(ثابت uint8_t *x0, uint8_t x1);

ساكن مضمن uint8_t
core_ops_ثنائی_ہندسہ_core_ops_ثنائی_ہندسہ_Shr_i32_u8_for_0_u8_shr(ثابت uint8_t *x0, int32_t x1);

/**
A monomorphic instance of core.ops.range.Range
with types size_t

*/
تعريفنوع بنية core_ops_range_Range_87_s
{
  ناپ_t شروع;
  ناپ_t سرا;
}
core_ops_range_Range_87;

/**
A monomorphic instance of Eurydice.slice_subslice_mut
with types int16_t, core_ops_range_Range size_t, Eurydice_derefed_slice int16_t

*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_i16
Eurydice_ٹکڑا_subslice_mut_a6(Eurydice_mut_borrow_ٹکڑا_i16 s, core_ops_range_Range_87 r)
{
  أرجع
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ٹکڑا_i16){
        .ptr = s.ptr + r.شروع,
        .meta = r.سرا - r.شروع
      }
    );
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $16size_t
*/
تعريفنوع بنية Eurydice_arr_b2_s { uint8_t انکڑے[16U]; } Eurydice_arr_b2;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_b2
with const generics
- $256size_t
*/
تعريفنوع بنية Eurydice_arr_87_s { Eurydice_arr_b2 انکڑے[256U]; } Eurydice_arr_87;

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $24size_t
*/
تعريفنوع بنية Eurydice_arr_94_s { uint8_t انکڑے[24U]; } Eurydice_arr_94;

#تعریف_کرو core_نتیجہ_Ok 0
#تعریف_کرو core_نتیجہ_Err 1

تعريفنوع uint8_t core_نتیجہ_نتیجہ_57_ٹیگ_سوچی;

/**
A monomorphic instance of core.result.Result
with types Eurydice_arr_94, core_array_TryFromSliceError

*/
تعريفنوع بنية core_نتیجہ_نتیجہ_57_s
{
  core_نتیجہ_نتیجہ_57_ٹیگ_سوچی ٹیگ;
  اتحاد {
    Eurydice_arr_94 case_Ok;
    core_array_Try_From_ٹکڑا_Error case_Err;
  }
  val;
}
core_نتیجہ_نتیجہ_57;

/**
This function found in impl {core::result::Result<T, E>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of core.result.unwrap_26
with types Eurydice_arr uint8_t[[$24size_t]], core_array_TryFromSliceError

*/
ساكن مضمن Eurydice_arr_94 core_نتیجہ_unwrap_26_78(core_نتیجہ_نتیجہ_57 self)
{
  إذا (self.ٹیگ == core_نتیجہ_Ok)
  {
    أرجع self.val.case_Ok;
  }
  وإلا
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __FILE__, __LINE__, "unwrap not Ok");
    KRML_HOST_EXIT(255U);
  }
}

/**
A monomorphic instance of Eurydice.arr
with types int16_t
with const generics
- $16size_t
*/
تعريفنوع بنية Eurydice_arr_d6_s { int16_t انکڑے[16U]; } Eurydice_arr_d6;

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $20size_t
*/
تعريفنوع بنية Eurydice_arr_fc_s { uint8_t انکڑے[20U]; } Eurydice_arr_fc;

/**
A monomorphic instance of core.result.Result
with types Eurydice_arr_fc, core_array_TryFromSliceError

*/
تعريفنوع بنية core_نتیجہ_نتیجہ_83_s
{
  core_نتیجہ_نتیجہ_57_ٹیگ_سوچی ٹیگ;
  اتحاد {
    Eurydice_arr_fc case_Ok;
    core_array_Try_From_ٹکڑا_Error case_Err;
  }
  val;
}
core_نتیجہ_نتیجہ_83;

/**
This function found in impl {core::result::Result<T, E>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of core.result.unwrap_26
with types Eurydice_arr uint8_t[[$20size_t]], core_array_TryFromSliceError

*/
ساكن مضمن Eurydice_arr_fc core_نتیجہ_unwrap_26_7d(core_نتیجہ_نتیجہ_83 self)
{
  إذا (self.ٹیگ == core_نتیجہ_Ok)
  {
    أرجع self.val.case_Ok;
  }
  وإلا
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __FILE__, __LINE__, "unwrap not Ok");
    KRML_HOST_EXIT(255U);
  }
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $1184size_t
*/
تعريفنوع بنية Eurydice_arr_5f_s { uint8_t انکڑے[1184U]; } Eurydice_arr_5f;

/**
A monomorphic instance of Eurydice.array_to_subslice_from_shared
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1184
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_subslice_from_shared_5f2(ثابت Eurydice_arr_5f *a, ناپ_t r)
{
  أرجع
    (KRML_CLITERAL(Eurydice_borrow_ٹکڑا_u8){ .ptr = a->انکڑے + r, .meta = (ناپ_t)1184U - r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_to_shared
with types uint8_t, core_ops_range_RangeTo size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1184
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_subslice_منزل_shared_210(ثابت Eurydice_arr_5f *a, ناپ_t r)
{
  Eurydice_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = r;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $2400size_t
*/
تعريفنوع بنية Eurydice_arr_7d_s { uint8_t انکڑے[2400U]; } Eurydice_arr_7d;

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 2400
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_subslice_shared_d48(ثابت Eurydice_arr_7d *a, core_ops_range_Range_87 r)
{
  أرجع
    (KRML_CLITERAL(Eurydice_borrow_ٹکڑا_u8){ .ptr = a->انکڑے + r.شروع, .meta = r.سرا - r.شروع });
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $1152size_t
*/
تعريفنوع بنية Eurydice_arr_0e_s { uint8_t انکڑے[1152U]; } Eurydice_arr_0e;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 1152
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_ٹکڑا_shared_f4(ثابت Eurydice_arr_0e *a)
{
  Eurydice_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)1152U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 2400
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8
Eurydice_array_منزل_subslice_mut_d417(Eurydice_arr_7d *a, core_ops_range_Range_87 r)
{
  أرجع
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ٹکڑا_u8){
        .ptr = a->انکڑے + r.شروع,
        .meta = r.سرا - r.شروع
      }
    );
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 1152
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8 Eurydice_array_منزل_ٹکڑا_mut_f4(Eurydice_arr_0e *a)
{
  Eurydice_mut_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)1152U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_from_mut
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1184
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8
Eurydice_array_منزل_subslice_from_mut_5f4(Eurydice_arr_5f *a, ناپ_t r)
{
  أرجع
    (KRML_CLITERAL(Eurydice_mut_borrow_ٹکڑا_u8){ .ptr = a->انکڑے + r, .meta = (ناپ_t)1184U - r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1184
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8
Eurydice_array_منزل_subslice_mut_d416(Eurydice_arr_5f *a, core_ops_range_Range_87 r)
{
  أرجع
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ٹکڑا_u8){
        .ptr = a->انکڑے + r.شروع,
        .meta = r.سرا - r.شروع
      }
    );
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 24
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_ٹکڑا_shared_ed(ثابت Eurydice_arr_94 *a)
{
  Eurydice_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)24U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $384size_t
*/
تعريفنوع بنية Eurydice_arr_b20_s { uint8_t انکڑے[384U]; } Eurydice_arr_b20;

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 384
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8
Eurydice_array_منزل_subslice_mut_d415(Eurydice_arr_b20 *a, core_ops_range_Range_87 r)
{
  أرجع
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ٹکڑا_u8){
        .ptr = a->انکڑے + r.شروع,
        .meta = r.سرا - r.شروع
      }
    );
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 384
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_ٹکڑا_shared_a9(ثابت Eurydice_arr_b20 *a)
{
  Eurydice_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)384U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $32size_t
*/
تعريفنوع بنية Eurydice_arr_ec_s { uint8_t انکڑے[32U]; } Eurydice_arr_ec;

/**
A monomorphic instance of core.result.Result
with types Eurydice_arr_ec, core_array_TryFromSliceError

*/
تعريفنوع بنية core_نتیجہ_نتیجہ_07_s
{
  core_نتیجہ_نتیجہ_57_ٹیگ_سوچی ٹیگ;
  اتحاد {
    Eurydice_arr_ec case_Ok;
    core_array_Try_From_ٹکڑا_Error case_Err;
  }
  val;
}
core_نتیجہ_نتیجہ_07;

/**
This function found in impl {core::result::Result<T, E>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of core.result.unwrap_26
with types Eurydice_arr uint8_t[[$32size_t]], core_array_TryFromSliceError

*/
ساكن مضمن Eurydice_arr_ec core_نتیجہ_unwrap_26_39(core_نتیجہ_نتیجہ_07 self)
{
  إذا (self.ٹیگ == core_نتیجہ_Ok)
  {
    أرجع self.val.case_Ok;
  }
  وإلا
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __FILE__, __LINE__, "unwrap not Ok");
    KRML_HOST_EXIT(255U);
  }
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $64size_t
*/
تعريفنوع بنية Eurydice_arr_c7_s { uint8_t انکڑے[64U]; } Eurydice_arr_c7;

/**
A monomorphic instance of Eurydice.array_to_subslice_from_shared
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 64
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_subslice_from_shared_5f1(ثابت Eurydice_arr_c7 *a, ناپ_t r)
{
  أرجع
    (KRML_CLITERAL(Eurydice_borrow_ٹکڑا_u8){ .ptr = a->انکڑے + r, .meta = (ناپ_t)64U - r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 64
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_subslice_shared_d47(ثابت Eurydice_arr_c7 *a, core_ops_range_Range_87 r)
{
  أرجع
    (KRML_CLITERAL(Eurydice_borrow_ٹکڑا_u8){ .ptr = a->انکڑے + r.شروع, .meta = r.سرا - r.شروع });
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 1184
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_ٹکڑا_shared_ff(ثابت Eurydice_arr_5f *a)
{
  Eurydice_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)1184U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $1088size_t
*/
تعريفنوع بنية Eurydice_arr_2b_s { uint8_t انکڑے[1088U]; } Eurydice_arr_2b;

/**
A monomorphic instance of Eurydice.array_to_subslice_from_mut
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1088
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8
Eurydice_array_منزل_subslice_from_mut_5f3(Eurydice_arr_2b *a, ناپ_t r)
{
  أرجع
    (KRML_CLITERAL(Eurydice_mut_borrow_ٹکڑا_u8){ .ptr = a->انکڑے + r, .meta = (ناپ_t)1088U - r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1088
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8
Eurydice_array_منزل_subslice_mut_d414(Eurydice_arr_2b *a, core_ops_range_Range_87 r)
{
  أرجع
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ٹکڑا_u8){
        .ptr = a->انکڑے + r.شروع,
        .meta = r.سرا - r.شروع
      }
    );
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 20
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_ٹکڑا_shared_8f(ثابت Eurydice_arr_fc *a)
{
  Eurydice_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)20U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $320size_t
*/
تعريفنوع بنية Eurydice_arr_b0_s { uint8_t انکڑے[320U]; } Eurydice_arr_b0;

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 320
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8
Eurydice_array_منزل_subslice_mut_d413(Eurydice_arr_b0 *a, core_ops_range_Range_87 r)
{
  أرجع
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ٹکڑا_u8){
        .ptr = a->انکڑے + r.شروع,
        .meta = r.سرا - r.شروع
      }
    );
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 320
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_ٹکڑا_shared_56(ثابت Eurydice_arr_b0 *a)
{
  Eurydice_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)320U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.arr
with types int16_t
with const generics
- $256size_t
*/
تعريفنوع بنية Eurydice_arr_04_s { int16_t انکڑے[256U]; } Eurydice_arr_04;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types int16_t
with const generics
- N= 256
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_i16
Eurydice_array_منزل_ٹکڑا_shared_99(ثابت Eurydice_arr_04 *a)
{
  Eurydice_borrow_ٹکڑا_i16 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)256U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $128size_t
*/
تعريفنوع بنية Eurydice_arr_89_s { uint8_t انکڑے[128U]; } Eurydice_arr_89;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_89
with const generics
- $3size_t
*/
تعريفنوع بنية Eurydice_arr_58_s { Eurydice_arr_89 انکڑے[3U]; } Eurydice_arr_58;

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $33size_t
*/
تعريفنوع بنية Eurydice_arr_fa0_s { uint8_t انکڑے[33U]; } Eurydice_arr_fa0;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 33
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_ٹکڑا_shared_b5(ثابت Eurydice_arr_fa0 *a)
{
  Eurydice_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)33U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_fa0
with const generics
- $3size_t
*/
تعريفنوع بنية Eurydice_arr_fd_s { Eurydice_arr_fa0 انکڑے[3U]; } Eurydice_arr_fd;

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 33
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8
Eurydice_array_منزل_subslice_mut_d412(Eurydice_arr_fa0 *a, core_ops_range_Range_87 r)
{
  أرجع
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ٹکڑا_u8){
        .ptr = a->انکڑے + r.شروع,
        .meta = r.سرا - r.شروع
      }
    );
}

/**
A monomorphic instance of Eurydice.arr
with types int16_t
with const generics
- $272size_t
*/
تعريفنوع بنية Eurydice_arr_5b_s { int16_t انکڑے[272U]; } Eurydice_arr_5b;

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types int16_t, core_ops_range_Range size_t, Eurydice_derefed_slice int16_t
with const generics
- N= 272
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_i16
Eurydice_array_منزل_subslice_shared_e70(ثابت Eurydice_arr_5b *a, core_ops_range_Range_87 r)
{
  أرجع
    (KRML_CLITERAL(Eurydice_borrow_ٹکڑا_i16){ .ptr = a->انکڑے + r.شروع, .meta = r.سرا - r.شروع });
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $168size_t
*/
تعريفنوع بنية Eurydice_arr_c5_s { uint8_t انکڑے[168U]; } Eurydice_arr_c5;

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 168
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_subslice_shared_d46(ثابت Eurydice_arr_c5 *a, core_ops_range_Range_87 r)
{
  أرجع
    (KRML_CLITERAL(Eurydice_borrow_ٹکڑا_u8){ .ptr = a->انکڑے + r.شروع, .meta = r.سرا - r.شروع });
}

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_c5
with const generics
- $3size_t
*/
تعريفنوع بنية Eurydice_arr_2c_s { Eurydice_arr_c5 انکڑے[3U]; } Eurydice_arr_2c;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_5b
with const generics
- $3size_t
*/
تعريفنوع بنية Eurydice_arr_b1_s { Eurydice_arr_5b انکڑے[3U]; } Eurydice_arr_b1;

/**
A monomorphic instance of Eurydice.arr
with types size_t
with const generics
- $3size_t
*/
تعريفنوع بنية Eurydice_arr_eb_s { ناپ_t انکڑے[3U]; } Eurydice_arr_eb;

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types int16_t, core_ops_range_Range size_t, Eurydice_derefed_slice int16_t
with const generics
- N= 272
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_i16
Eurydice_array_منزل_subslice_mut_e7(Eurydice_arr_5b *a, core_ops_range_Range_87 r)
{
  أرجع
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ٹکڑا_i16){
        .ptr = a->انکڑے + r.شروع,
        .meta = r.سرا - r.شروع
      }
    );
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $504size_t
*/
تعريفنوع بنية Eurydice_arr_79_s { uint8_t انکڑے[504U]; } Eurydice_arr_79;

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 504
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_subslice_shared_d45(ثابت Eurydice_arr_79 *a, core_ops_range_Range_87 r)
{
  أرجع
    (KRML_CLITERAL(Eurydice_borrow_ٹکڑا_u8){ .ptr = a->انکڑے + r.شروع, .meta = r.سرا - r.شروع });
}

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_79
with const generics
- $3size_t
*/
تعريفنوع بنية Eurydice_arr_7e_s { Eurydice_arr_79 انکڑے[3U]; } Eurydice_arr_7e;

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 504
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8 Eurydice_array_منزل_ٹکڑا_mut_48(Eurydice_arr_79 *a)
{
  Eurydice_mut_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)504U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $34size_t
*/
تعريفنوع بنية Eurydice_arr_31_s { uint8_t انکڑے[34U]; } Eurydice_arr_31;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_31
with const generics
- $3size_t
*/
تعريفنوع بنية Eurydice_arr_810_s { Eurydice_arr_31 انکڑے[3U]; } Eurydice_arr_810;

/**
A monomorphic instance of Eurydice.slice_subslice_from_shared
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t

*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_ٹکڑا_subslice_from_shared_6d(Eurydice_borrow_ٹکڑا_u8 s, ناپ_t r)
{
  أرجع (KRML_CLITERAL(Eurydice_borrow_ٹکڑا_u8){ .ptr = s.ptr + r, .meta = s.meta - r });
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $1120size_t
*/
تعريفنوع بنية Eurydice_arr_af_s { uint8_t انکڑے[1120U]; } Eurydice_arr_af;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 1120
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_ٹکڑا_shared_81(ثابت Eurydice_arr_af *a)
{
  Eurydice_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)1120U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 1088
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_ٹکڑا_shared_06(ثابت Eurydice_arr_2b *a)
{
  Eurydice_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)1088U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_from_mut
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1120
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8
Eurydice_array_منزل_subslice_from_mut_5f2(Eurydice_arr_af *a, ناپ_t r)
{
  أرجع
    (KRML_CLITERAL(Eurydice_mut_borrow_ٹکڑا_u8){ .ptr = a->انکڑے + r, .meta = (ناپ_t)1120U - r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1120
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8
Eurydice_array_منزل_subslice_mut_d411(Eurydice_arr_af *a, core_ops_range_Range_87 r)
{
  أرجع
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ٹکڑا_u8){
        .ptr = a->انکڑے + r.شروع,
        .meta = r.سرا - r.شروع
      }
    );
}

/**
A monomorphic instance of Eurydice.array_to_subslice_from_mut
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 64
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8
Eurydice_array_منزل_subslice_from_mut_5f1(Eurydice_arr_c7 *a, ناپ_t r)
{
  أرجع
    (KRML_CLITERAL(Eurydice_mut_borrow_ٹکڑا_u8){ .ptr = a->انکڑے + r, .meta = (ناپ_t)64U - r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 64
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8
Eurydice_array_منزل_subslice_mut_d410(Eurydice_arr_c7 *a, core_ops_range_Range_87 r)
{
  أرجع
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ٹکڑا_u8){
        .ptr = a->انکڑے + r.شروع,
        .meta = r.سرا - r.شروع
      }
    );
}

/**
A monomorphic instance of Eurydice.array_to_subslice_from_shared
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1088
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_subslice_from_shared_5f0(ثابت Eurydice_arr_2b *a, ناپ_t r)
{
  أرجع
    (KRML_CLITERAL(Eurydice_borrow_ٹکڑا_u8){ .ptr = a->انکڑے + r, .meta = (ناپ_t)1088U - r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1088
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_subslice_shared_d44(ثابت Eurydice_arr_2b *a, core_ops_range_Range_87 r)
{
  أرجع
    (KRML_CLITERAL(Eurydice_borrow_ٹکڑا_u8){ .ptr = a->انکڑے + r.شروع, .meta = r.سرا - r.شروع });
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 2400
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_ٹکڑا_shared_51(ثابت Eurydice_arr_7d *a)
{
  Eurydice_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)2400U;
  أرجع lit;
}

تعريفنوع بنية int16_t_x2_s
{
  int16_t fst;
  int16_t snd;
}
int16_t_x2;

/**
This function found in impl {libcrux_secrets::traits::Declassify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.declassify_d8
with types Eurydice_arr uint8_t[[$24size_t]]

*/
ساكن KRML_MUSTINLINE Eurydice_arr_94
libcrux_secrets_int_عوامی_integers_declassify_d8_40(Eurydice_arr_94 self)
{
  أرجع self;
}

تعريفنوع بنية uint8_t_x3_s
{
  uint8_t fst;
  uint8_t snd;
  uint8_t thd;
}
uint8_t_x3;

/**
This function found in impl {libcrux_secrets::traits::Declassify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.declassify_d8
with types Eurydice_arr uint8_t[[$20size_t]]

*/
ساكن KRML_MUSTINLINE Eurydice_arr_fc
libcrux_secrets_int_عوامی_integers_declassify_d8_2b(Eurydice_arr_fc self)
{
  أرجع self;
}

تعريفنوع بنية uint8_t_x5_s
{
  uint8_t fst;
  uint8_t snd;
  uint8_t thd;
  uint8_t f3;
  uint8_t f4;
}
uint8_t_x5;

/**
This function found in impl {libcrux_secrets::traits::Declassify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.declassify_d8
with types Eurydice_arr uint8_t[[$8size_t]]

*/
ساكن KRML_MUSTINLINE Eurydice_array_u8x8
libcrux_secrets_int_عوامی_integers_declassify_d8_52(Eurydice_array_u8x8 self)
{
  أرجع self;
}

تعريفنوع بنية uint8_t_x4_s
{
  uint8_t fst;
  uint8_t snd;
  uint8_t thd;
  uint8_t f3;
}
uint8_t_x4;

/**
This function found in impl {libcrux_secrets::traits::Declassify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.declassify_d8
with types Eurydice_arr uint8_t[[$2size_t]]

*/
ساكن KRML_MUSTINLINE Eurydice_array_u8x2
libcrux_secrets_int_عوامی_integers_declassify_d8_75(Eurydice_array_u8x2 self)
{
  أرجع self;
}

/**
This function found in impl {libcrux_secrets::traits::Classify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.classify_27
with types Eurydice_arr int16_t[[$16size_t]]

*/
ساكن KRML_MUSTINLINE Eurydice_arr_d6
libcrux_secrets_int_عوامی_integers_classify_27_4b(Eurydice_arr_d6 self)
{
  أرجع self;
}

/**
This function found in impl {libcrux_secrets::traits::ClassifyRef<&'a ([T])> for &'a ([T])}
*/
/**
A monomorphic instance of libcrux_secrets.int.classify_public.classify_ref_6d
with types uint8_t

*/
ساكن KRML_MUSTINLINE Eurydice_borrow_ٹکڑا_u8
libcrux_secrets_int_classify_عوامی_classify_ref_6d_90(Eurydice_borrow_ٹکڑا_u8 self)
{
  أرجع self;
}

تعريفنوع بنية int16_t_x8_s
{
  int16_t fst;
  int16_t snd;
  int16_t thd;
  int16_t f3;
  int16_t f4;
  int16_t f5;
  int16_t f6;
  int16_t f7;
}
int16_t_x8;

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types int16_t, core_ops_range_Range size_t, Eurydice_derefed_slice int16_t
with const generics
- N= 16
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_i16
Eurydice_array_منزل_subslice_shared_e7(ثابت Eurydice_arr_d6 *a, core_ops_range_Range_87 r)
{
  أرجع
    (KRML_CLITERAL(Eurydice_borrow_ٹکڑا_i16){ .ptr = a->انکڑے + r.شروع, .meta = r.سرا - r.شروع });
}

/**
This function found in impl {libcrux_secrets::traits::ClassifyRef<&'a ([T])> for &'a ([T])}
*/
/**
A monomorphic instance of libcrux_secrets.int.classify_public.classify_ref_6d
with types int16_t

*/
ساكن KRML_MUSTINLINE Eurydice_borrow_ٹکڑا_i16
libcrux_secrets_int_classify_عوامی_classify_ref_6d_39(Eurydice_borrow_ٹکڑا_i16 self)
{
  أرجع self;
}

/**
A monomorphic instance of Eurydice.slice_subslice_shared
with types int16_t, core_ops_range_Range size_t, Eurydice_derefed_slice int16_t

*/
ساكن مضمن Eurydice_borrow_ٹکڑا_i16
Eurydice_ٹکڑا_subslice_shared_a6(Eurydice_borrow_ٹکڑا_i16 s, core_ops_range_Range_87 r)
{
  أرجع
    (KRML_CLITERAL(Eurydice_borrow_ٹکڑا_i16){ .ptr = s.ptr + r.شروع, .meta = r.سرا - r.شروع });
}

/**
A monomorphic instance of core.result.Result
with types Eurydice_arr_d6, core_array_TryFromSliceError

*/
تعريفنوع بنية core_نتیجہ_نتیجہ_ec_s
{
  core_نتیجہ_نتیجہ_57_ٹیگ_سوچی ٹیگ;
  اتحاد {
    Eurydice_arr_d6 case_Ok;
    core_array_Try_From_ٹکڑا_Error case_Err;
  }
  val;
}
core_نتیجہ_نتیجہ_ec;

/**
This function found in impl {core::result::Result<T, E>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of core.result.unwrap_26
with types Eurydice_arr int16_t[[$16size_t]], core_array_TryFromSliceError

*/
ساكن مضمن Eurydice_arr_d6 core_نتیجہ_unwrap_26_d3(core_نتیجہ_نتیجہ_ec self)
{
  إذا (self.ٹیگ == core_نتیجہ_Ok)
  {
    أرجع self.val.case_Ok;
  }
  وإلا
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __FILE__, __LINE__, "unwrap not Ok");
    KRML_HOST_EXIT(255U);
  }
}

/**
A monomorphic instance of Eurydice.arr
with types int16_t
with const generics
- $128size_t
*/
تعريفنوع بنية Eurydice_arr_34_s { int16_t انکڑے[128U]; } Eurydice_arr_34;

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 24
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_subslice_shared_d43(ثابت Eurydice_arr_94 *a, core_ops_range_Range_87 r)
{
  أرجع
    (KRML_CLITERAL(Eurydice_borrow_ٹکڑا_u8){ .ptr = a->انکڑے + r.شروع, .meta = r.سرا - r.شروع });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 24
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8
Eurydice_array_منزل_subslice_mut_d49(Eurydice_arr_94 *a, core_ops_range_Range_87 r)
{
  أرجع
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ٹکڑا_u8){
        .ptr = a->انکڑے + r.شروع,
        .meta = r.سرا - r.شروع
      }
    );
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 16
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8 Eurydice_array_منزل_ٹکڑا_mut_29(Eurydice_arr_b2 *a)
{
  Eurydice_mut_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)16U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 16
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_subslice_shared_d42(ثابت Eurydice_arr_b2 *a, core_ops_range_Range_87 r)
{
  أرجع
    (KRML_CLITERAL(Eurydice_borrow_ٹکڑا_u8){ .ptr = a->انکڑے + r.شروع, .meta = r.سرا - r.شروع });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 16
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8
Eurydice_array_منزل_subslice_mut_d48(Eurydice_arr_b2 *a, core_ops_range_Range_87 r)
{
  أرجع
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ٹکڑا_u8){
        .ptr = a->انکڑے + r.شروع,
        .meta = r.سرا - r.شروع
      }
    );
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $19size_t
*/
تعريفنوع بنية Eurydice_arr_38_s { uint8_t انکڑے[19U]; } Eurydice_arr_38;

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 19
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_subslice_shared_d41(ثابت Eurydice_arr_38 *a, core_ops_range_Range_87 r)
{
  أرجع
    (KRML_CLITERAL(Eurydice_borrow_ٹکڑا_u8){ .ptr = a->انکڑے + r.شروع, .meta = r.سرا - r.شروع });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 19
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8
Eurydice_array_منزل_subslice_mut_d47(Eurydice_arr_38 *a, core_ops_range_Range_87 r)
{
  أرجع
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ٹکڑا_u8){
        .ptr = a->انکڑے + r.شروع,
        .meta = r.سرا - r.شروع
      }
    );
}

/**
A monomorphic instance of Eurydice.dst_ref_mut
with types int32_t, size_t

*/
تعريفنوع بنية Eurydice_dst_ref_mut_83_s
{
  int32_t *ptr;
  ناپ_t meta;
}
Eurydice_dst_ref_mut_83;

/**
A monomorphic instance of Eurydice.slice_subslice_mut
with types int32_t, core_ops_range_Range size_t, Eurydice_derefed_slice int32_t

*/
ساكن مضمن Eurydice_dst_ref_mut_83
Eurydice_ٹکڑا_subslice_mut_47(Eurydice_dst_ref_mut_83 s, core_ops_range_Range_87 r)
{
  أرجع
    (KRML_CLITERAL(Eurydice_dst_ref_mut_83){ .ptr = s.ptr + r.شروع, .meta = r.سرا - r.شروع });
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 16
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_ٹکڑا_shared_29(ثابت Eurydice_arr_b2 *a)
{
  Eurydice_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)16U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_b2
with const generics
- $16size_t
*/
تعريفنوع بنية Eurydice_arr_a30_s { Eurydice_arr_b2 انکڑے[16U]; } Eurydice_arr_a30;

/**
A monomorphic instance of Eurydice.array_to_subslice_to_mut
with types uint8_t, core_ops_range_RangeTo size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 32
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8
Eurydice_array_منزل_subslice_منزل_mut_21(Eurydice_arr_ec *a, ناپ_t r)
{
  Eurydice_mut_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = r;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $4627size_t
*/
تعريفنوع بنية Eurydice_arr_93_s { uint8_t انکڑے[4627U]; } Eurydice_arr_93;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 4627
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_ٹکڑا_shared_11(ثابت Eurydice_arr_93 *a)
{
  Eurydice_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)4627U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $2592size_t
*/
تعريفنوع بنية Eurydice_arr_43_s { uint8_t انکڑے[2592U]; } Eurydice_arr_43;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 2592
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_ٹکڑا_shared_fc(ثابت Eurydice_arr_43 *a)
{
  Eurydice_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)2592U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $4896size_t
*/
تعريفنوع بنية Eurydice_arr_e2_s { uint8_t انکڑے[4896U]; } Eurydice_arr_e2;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 4896
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_ٹکڑا_shared_f7(ثابت Eurydice_arr_e2 *a)
{
  Eurydice_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)4896U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.arr
with types int32_t
with const generics
- $256size_t
*/
تعريفنوع بنية Eurydice_arr_6c_s { int32_t انکڑے[256U]; } Eurydice_arr_6c;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_6c
with const generics
- $8size_t
*/
تعريفنوع بنية Eurydice_arr_81_s { Eurydice_arr_6c انکڑے[8U]; } Eurydice_arr_81;

#تعریف_کرو core_option_None 0
#تعریف_کرو core_option_Some 1

تعريفنوع uint8_t core_option_Option_45_ٹیگ_سوچی;

/**
A monomorphic instance of core.option.Option
with types Eurydice_arr_81

*/
تعريفنوع بنية core_option_Option_45_s
{
  core_option_Option_45_ٹیگ_سوچی ٹیگ;
  Eurydice_arr_81 f0;
}
core_option_Option_45;

/**
A monomorphic instance of core.option.Option
with types Eurydice_arr_c7

*/
تعريفنوع بنية core_option_Option_b2_s
{
  core_option_Option_45_ٹیگ_سوچی ٹیگ;
  Eurydice_arr_c7 f0;
}
core_option_Option_b2;

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 4627
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8 Eurydice_array_منزل_ٹکڑا_mut_11(Eurydice_arr_93 *a)
{
  Eurydice_mut_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)4627U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.dst_ref_shared
with types Eurydice_arr_6c, size_t

*/
تعريفنوع بنية Eurydice_dst_ref_shared_20_s
{
  ثابت Eurydice_arr_6c *ptr;
  ناپ_t meta;
}
Eurydice_dst_ref_shared_20;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types Eurydice_arr int32_t[[$256size_t]]
with const generics
- N= 8
*/
ساكن مضمن Eurydice_dst_ref_shared_20
Eurydice_array_منزل_ٹکڑا_shared_861(ثابت Eurydice_arr_81 *a)
{
  Eurydice_dst_ref_shared_20 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)8U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.dst_ref_mut
with types Eurydice_arr_6c, size_t

*/
تعريفنوع بنية Eurydice_dst_ref_mut_20_s
{
  Eurydice_arr_6c *ptr;
  ناپ_t meta;
}
Eurydice_dst_ref_mut_20;

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types Eurydice_arr int32_t[[$256size_t]]
with const generics
- N= 8
*/
ساكن مضمن Eurydice_dst_ref_mut_20 Eurydice_array_منزل_ٹکڑا_mut_861(Eurydice_arr_81 *a)
{
  Eurydice_dst_ref_mut_20 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)8U;
  أرجع lit;
}

/**
 Declassify secret memory.

 No-op if `valgrind_ct_test` cfg is not enabled.
*/
/**
A monomorphic instance of libcrux_secrets.mem_requests.ct_declassify
with types Eurydice_arr uint8_t[[$64size_t]]

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_secrets_mem_بینتیاں_ct_declassify_56(ثابت Eurydice_arr_c7 *val)
{

}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $1024size_t
*/
تعريفنوع بنية Eurydice_arr_1b_s { uint8_t انکڑے[1024U]; } Eurydice_arr_1b;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 1024
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_ٹکڑا_shared_68(ثابت Eurydice_arr_1b *a)
{
  Eurydice_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)1024U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 1024
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8 Eurydice_array_منزل_ٹکڑا_mut_68(Eurydice_arr_1b *a)
{
  Eurydice_mut_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)1024U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 2592
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8 Eurydice_array_منزل_ٹکڑا_mut_fc(Eurydice_arr_43 *a)
{
  Eurydice_mut_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)2592U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 4896
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8 Eurydice_array_منزل_ٹکڑا_mut_f7(Eurydice_arr_e2 *a)
{
  Eurydice_mut_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)4896U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $3309size_t
*/
تعريفنوع بنية Eurydice_arr_0c_s { uint8_t انکڑے[3309U]; } Eurydice_arr_0c;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 3309
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_ٹکڑا_shared_6b(ثابت Eurydice_arr_0c *a)
{
  Eurydice_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)3309U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $1952size_t
*/
تعريفنوع بنية Eurydice_arr_29_s { uint8_t انکڑے[1952U]; } Eurydice_arr_29;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 1952
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_ٹکڑا_shared_37(ثابت Eurydice_arr_29 *a)
{
  Eurydice_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)1952U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $4032size_t
*/
تعريفنوع بنية Eurydice_arr_24_s { uint8_t انکڑے[4032U]; } Eurydice_arr_24;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 4032
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_ٹکڑا_shared_98(ثابت Eurydice_arr_24 *a)
{
  Eurydice_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)4032U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_6c
with const generics
- $6size_t
*/
تعريفنوع بنية Eurydice_arr_5d0_s { Eurydice_arr_6c انکڑے[6U]; } Eurydice_arr_5d0;

/**
A monomorphic instance of core.option.Option
with types Eurydice_arr_5d0

*/
تعريفنوع بنية core_option_Option_05_s
{
  core_option_Option_45_ٹیگ_سوچی ٹیگ;
  Eurydice_arr_5d0 f0;
}
core_option_Option_05;

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $48size_t
*/
تعريفنوع بنية Eurydice_arr_65_s { uint8_t انکڑے[48U]; } Eurydice_arr_65;

/**
A monomorphic instance of core.option.Option
with types Eurydice_arr_65

*/
تعريفنوع بنية core_option_Option_81_s
{
  core_option_Option_45_ٹیگ_سوچی ٹیگ;
  Eurydice_arr_65 f0;
}
core_option_Option_81;

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 3309
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8 Eurydice_array_منزل_ٹکڑا_mut_6b(Eurydice_arr_0c *a)
{
  Eurydice_mut_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)3309U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types Eurydice_arr int32_t[[$256size_t]]
with const generics
- N= 6
*/
ساكن مضمن Eurydice_dst_ref_shared_20
Eurydice_array_منزل_ٹکڑا_shared_860(ثابت Eurydice_arr_5d0 *a)
{
  Eurydice_dst_ref_shared_20 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)6U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types Eurydice_arr int32_t[[$256size_t]]
with const generics
- N= 6
*/
ساكن مضمن Eurydice_dst_ref_mut_20 Eurydice_array_منزل_ٹکڑا_mut_860(Eurydice_arr_5d0 *a)
{
  Eurydice_dst_ref_mut_20 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)6U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 48
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_ٹکڑا_shared_9f0(ثابت Eurydice_arr_65 *a)
{
  Eurydice_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)48U;
  أرجع lit;
}

/**
 Declassify secret memory.

 No-op if `valgrind_ct_test` cfg is not enabled.
*/
/**
A monomorphic instance of libcrux_secrets.mem_requests.ct_declassify
with types Eurydice_arr uint8_t[[$48size_t]]

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_secrets_mem_بینتیاں_ct_declassify_69(ثابت Eurydice_arr_65 *val)
{

}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 1952
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8 Eurydice_array_منزل_ٹکڑا_mut_37(Eurydice_arr_29 *a)
{
  Eurydice_mut_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)1952U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 4032
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8 Eurydice_array_منزل_ٹکڑا_mut_98(Eurydice_arr_24 *a)
{
  Eurydice_mut_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)4032U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $2420size_t
*/
تعريفنوع بنية Eurydice_arr_85_s { uint8_t انکڑے[2420U]; } Eurydice_arr_85;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 2420
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_ٹکڑا_shared_0d(ثابت Eurydice_arr_85 *a)
{
  Eurydice_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)2420U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $1312size_t
*/
تعريفنوع بنية Eurydice_arr_02_s { uint8_t انکڑے[1312U]; } Eurydice_arr_02;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 1312
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_ٹکڑا_shared_9f(ثابت Eurydice_arr_02 *a)
{
  Eurydice_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)1312U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $2560size_t
*/
تعريفنوع بنية Eurydice_arr_10_s { uint8_t انکڑے[2560U]; } Eurydice_arr_10;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 2560
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_ٹکڑا_shared_34(ثابت Eurydice_arr_10 *a)
{
  Eurydice_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)2560U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_6c
with const generics
- $4size_t
*/
تعريفنوع بنية Eurydice_arr_b7_s { Eurydice_arr_6c انکڑے[4U]; } Eurydice_arr_b7;

/**
A monomorphic instance of core.option.Option
with types Eurydice_arr_b7

*/
تعريفنوع بنية core_option_Option_51_s
{
  core_option_Option_45_ٹیگ_سوچی ٹیگ;
  Eurydice_arr_b7 f0;
}
core_option_Option_51;

/**
A monomorphic instance of core.option.Option
with types Eurydice_arr_ec

*/
تعريفنوع بنية core_option_Option_14_s
{
  core_option_Option_45_ٹیگ_سوچی ٹیگ;
  Eurydice_arr_ec f0;
}
core_option_Option_14;

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 2420
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8 Eurydice_array_منزل_ٹکڑا_mut_0d(Eurydice_arr_85 *a)
{
  Eurydice_mut_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)2420U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types Eurydice_arr int32_t[[$256size_t]]
with const generics
- N= 4
*/
ساكن مضمن Eurydice_dst_ref_shared_20
Eurydice_array_منزل_ٹکڑا_shared_86(ثابت Eurydice_arr_b7 *a)
{
  Eurydice_dst_ref_shared_20 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)4U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types Eurydice_arr int32_t[[$256size_t]]
with const generics
- N= 4
*/
ساكن مضمن Eurydice_dst_ref_mut_20 Eurydice_array_منزل_ٹکڑا_mut_86(Eurydice_arr_b7 *a)
{
  Eurydice_dst_ref_mut_20 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)4U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types int32_t, core_ops_range_Range size_t, Eurydice_derefed_slice int32_t
with const generics
- N= 256
*/
ساكن مضمن Eurydice_dst_ref_mut_83
Eurydice_array_منزل_subslice_mut_44(Eurydice_arr_6c *a, core_ops_range_Range_87 r)
{
  أرجع
    (KRML_CLITERAL(Eurydice_dst_ref_mut_83){ .ptr = a->انکڑے + r.شروع, .meta = r.سرا - r.شروع });
}

/**
A monomorphic instance of Eurydice.dst_ref_shared
with types int32_t, size_t

*/
تعريفنوع بنية Eurydice_dst_ref_shared_83_s
{
  ثابت int32_t *ptr;
  ناپ_t meta;
}
Eurydice_dst_ref_shared_83;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types int32_t
with const generics
- N= 256
*/
ساكن مضمن Eurydice_dst_ref_shared_83
Eurydice_array_منزل_ٹکڑا_shared_af(ثابت Eurydice_arr_6c *a)
{
  Eurydice_dst_ref_shared_83 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)256U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $136size_t
*/
تعريفنوع بنية Eurydice_arr_ff_s { uint8_t انکڑے[136U]; } Eurydice_arr_ff;

/**
A monomorphic instance of Eurydice.array_to_subslice_from_shared
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 136
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_subslice_from_shared_5f(ثابت Eurydice_arr_ff *a, ناپ_t r)
{
  أرجع
    (KRML_CLITERAL(Eurydice_borrow_ٹکڑا_u8){ .ptr = a->انکڑے + r, .meta = (ناپ_t)136U - r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 136
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_subslice_shared_d40(ثابت Eurydice_arr_ff *a, core_ops_range_Range_87 r)
{
  أرجع
    (KRML_CLITERAL(Eurydice_borrow_ٹکڑا_u8){ .ptr = a->انکڑے + r.شروع, .meta = r.سرا - r.شروع });
}

/**
 Declassify secret memory.

 No-op if `valgrind_ct_test` cfg is not enabled.
*/
/**
A monomorphic instance of libcrux_secrets.mem_requests.ct_declassify
with types Eurydice_arr uint8_t[[$32size_t]]

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_secrets_mem_بینتیاں_ct_declassify_4b(ثابت Eurydice_arr_ec *val)
{

}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $768size_t
*/
تعريفنوع بنية Eurydice_arr_d2_s { uint8_t انکڑے[768U]; } Eurydice_arr_d2;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 768
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_ٹکڑا_shared_27(ثابت Eurydice_arr_d2 *a)
{
  Eurydice_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)768U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 768
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8 Eurydice_array_منزل_ٹکڑا_mut_27(Eurydice_arr_d2 *a)
{
  Eurydice_mut_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)768U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $640size_t
*/
تعريفنوع بنية Eurydice_arr_20_s { uint8_t انکڑے[640U]; } Eurydice_arr_20;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 640
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_ٹکڑا_shared_4f(ثابت Eurydice_arr_20 *a)
{
  Eurydice_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)640U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 640
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8 Eurydice_array_منزل_ٹکڑا_mut_4f(Eurydice_arr_20 *a)
{
  Eurydice_mut_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)640U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $576size_t
*/
تعريفنوع بنية Eurydice_arr_220_s { uint8_t انکڑے[576U]; } Eurydice_arr_220;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 576
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_ٹکڑا_shared_8a(ثابت Eurydice_arr_220 *a)
{
  Eurydice_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)576U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 576
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8 Eurydice_array_منزل_ٹکڑا_mut_8a(Eurydice_arr_220 *a)
{
  Eurydice_mut_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)576U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $11size_t
*/
تعريفنوع بنية Eurydice_arr_c9_s { uint8_t انکڑے[11U]; } Eurydice_arr_c9;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 11
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_ٹکڑا_shared_2f(ثابت Eurydice_arr_c9 *a)
{
  Eurydice_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)11U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $1size_t
*/
تعريفنوع بنية Eurydice_arr_82_s { uint8_t انکڑے[1U]; } Eurydice_arr_82;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 1
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_ٹکڑا_shared_79(ثابت Eurydice_arr_82 *a)
{
  Eurydice_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)1U;
  أرجع lit;
}

/**
 Mark memory as secret.

 No-op if `valgrind_ct_test` cfg is not enabled.
*/
/**
A monomorphic instance of libcrux_secrets.mem_requests.ct_classify
with types Eurydice_derefed_slice uint8_t

*/
ساكن KRML_MUSTINLINE فراغ libcrux_secrets_mem_بینتیاں_ct_classify_45(ثابت uint8_t (*val)[])
{

}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 1312
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8 Eurydice_array_منزل_ٹکڑا_mut_9f0(Eurydice_arr_02 *a)
{
  Eurydice_mut_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)1312U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 2560
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8 Eurydice_array_منزل_ٹکڑا_mut_34(Eurydice_arr_10 *a)
{
  Eurydice_mut_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)2560U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 64
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_ٹکڑا_shared_17(ثابت Eurydice_arr_c7 *a)
{
  Eurydice_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)64U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.arr
with types int32_t
with const generics
- $263size_t
*/
تعريفنوع بنية Eurydice_arr_d0_s { int32_t انکڑے[263U]; } Eurydice_arr_d0;

/**
A monomorphic instance of Eurydice.dst_ref_mut
with types Eurydice_arr_d0, size_t

*/
تعريفنوع بنية Eurydice_dst_ref_mut_33_s
{
  Eurydice_arr_d0 *ptr;
  ناپ_t meta;
}
Eurydice_dst_ref_mut_33;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_d0
with const generics
- $4size_t
*/
تعريفنوع بنية Eurydice_arr_930_s { Eurydice_arr_d0 انکڑے[4U]; } Eurydice_arr_930;

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types Eurydice_arr int32_t[[$263size_t]]
with const generics
- N= 4
*/
ساكن مضمن Eurydice_dst_ref_mut_33 Eurydice_array_منزل_ٹکڑا_mut_7e(Eurydice_arr_930 *a)
{
  Eurydice_dst_ref_mut_33 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)4U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.dst_ref_shared
with types Eurydice_arr_d0, size_t

*/
تعريفنوع بنية Eurydice_dst_ref_shared_33_s
{
  ثابت Eurydice_arr_d0 *ptr;
  ناپ_t meta;
}
Eurydice_dst_ref_shared_33;

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $840size_t
*/
تعريفنوع بنية Eurydice_arr_d10_s { uint8_t انکڑے[840U]; } Eurydice_arr_d10;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 840
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_ٹکڑا_shared_4c(ثابت Eurydice_arr_d10 *a)
{
  Eurydice_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)840U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 34
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_ٹکڑا_shared_e9(ثابت Eurydice_arr_31 *a)
{
  Eurydice_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)34U;
  أرجع lit;
}

/**
 Declassify secret memory.

 No-op if `valgrind_ct_test` cfg is not enabled.
*/
/**
A monomorphic instance of libcrux_secrets.mem_requests.ct_declassify
with types Eurydice_derefed_slice uint8_t

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_secrets_mem_بینتیاں_ct_declassify_45(ثابت uint8_t (*val)[])
{

}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types int32_t
with const generics
- N= 263
*/
ساكن مضمن Eurydice_dst_ref_shared_83
Eurydice_array_منزل_ٹکڑا_shared_2c0(ثابت Eurydice_arr_d0 *a)
{
  Eurydice_dst_ref_shared_83 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)263U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_from_mut
with types int32_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice int32_t
with const generics
- N= 263
*/
ساكن مضمن Eurydice_dst_ref_mut_83
Eurydice_array_منزل_subslice_from_mut_11(Eurydice_arr_d0 *a, ناپ_t r)
{
  أرجع
    (KRML_CLITERAL(Eurydice_dst_ref_mut_83){ .ptr = a->انکڑے + r, .meta = (ناپ_t)263U - r });
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $66size_t
*/
تعريفنوع بنية Eurydice_arr_91_s { uint8_t انکڑے[66U]; } Eurydice_arr_91;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 66
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_ٹکڑا_shared_f1(ثابت Eurydice_arr_91 *a)
{
  Eurydice_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)66U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 128
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_ٹکڑا_shared_78(ثابت Eurydice_arr_89 *a)
{
  Eurydice_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)128U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 128
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8 Eurydice_array_منزل_ٹکڑا_mut_78(Eurydice_arr_89 *a)
{
  Eurydice_mut_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)128U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 2
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_ٹکڑا_shared_82(ثابت Eurydice_array_u8x2 *a)
{
  Eurydice_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)2U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 32
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_ٹکڑا_shared_01(ثابت Eurydice_arr_ec *a)
{
  Eurydice_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)32U;
  أرجع lit;
}

/**
 Mark memory as secret.

 No-op if `valgrind_ct_test` cfg is not enabled.
*/
/**
A monomorphic instance of libcrux_secrets.mem_requests.ct_classify
with types Eurydice_arr uint8_t[[$32size_t]]

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_secrets_mem_بینتیاں_ct_classify_4b(ثابت Eurydice_arr_ec *val)
{

}

تعريفنوع بنية Eurydice_arr_c5_x4_s
{
  Eurydice_arr_c5 fst;
  Eurydice_arr_c5 snd;
  Eurydice_arr_c5 thd;
  Eurydice_arr_c5 f3;
}
Eurydice_arr_c5_x4;

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 168
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8 Eurydice_array_منزل_ٹکڑا_mut_2c(Eurydice_arr_c5 *a)
{
  Eurydice_mut_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)168U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 840
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8 Eurydice_array_منزل_ٹکڑا_mut_4c(Eurydice_arr_d10 *a)
{
  Eurydice_mut_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)840U;
  أرجع lit;
}

تعريفنوع بنية Eurydice_arr_ff_x4_s
{
  Eurydice_arr_ff fst;
  Eurydice_arr_ff snd;
  Eurydice_arr_ff thd;
  Eurydice_arr_ff f3;
}
Eurydice_arr_ff_x4;

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 136
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8 Eurydice_array_منزل_ٹکڑا_mut_58(Eurydice_arr_ff *a)
{
  Eurydice_mut_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)136U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 32
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_subslice_shared_d4(ثابت Eurydice_arr_ec *a, core_ops_range_Range_87 r)
{
  أرجع
    (KRML_CLITERAL(Eurydice_borrow_ٹکڑا_u8){ .ptr = a->انکڑے + r.شروع, .meta = r.سرا - r.شروع });
}

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_ff
with const generics
- $4size_t
*/
تعريفنوع بنية Eurydice_arr_dc0_s { Eurydice_arr_ff انکڑے[4U]; } Eurydice_arr_dc0;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_c5
with const generics
- $4size_t
*/
تعريفنوع بنية Eurydice_arr_9c_s { Eurydice_arr_c5 انکڑے[4U]; } Eurydice_arr_9c;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_borrow_slice_u8
with const generics
- $4size_t
*/
تعريفنوع بنية Eurydice_arr_68_s { Eurydice_borrow_ٹکڑا_u8 انکڑے[4U]; } Eurydice_arr_68;

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 32
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8
Eurydice_array_منزل_subslice_mut_d46(Eurydice_arr_ec *a, core_ops_range_Range_87 r)
{
  أرجع
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ٹکڑا_u8){
        .ptr = a->انکڑے + r.شروع,
        .meta = r.سرا - r.شروع
      }
    );
}

/**
A monomorphic instance of Eurydice.array_to_subslice_from_mut
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 168
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8
Eurydice_array_منزل_subslice_from_mut_5f0(Eurydice_arr_c5 *a, ناپ_t r)
{
  أرجع
    (KRML_CLITERAL(Eurydice_mut_borrow_ٹکڑا_u8){ .ptr = a->انکڑے + r, .meta = (ناپ_t)168U - r });
}

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_c5
with const generics
- $1size_t
*/
تعريفنوع بنية Eurydice_arr_88_s { Eurydice_arr_c5 انکڑے[1U]; } Eurydice_arr_88;

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 64
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8 Eurydice_array_منزل_ٹکڑا_mut_17(Eurydice_arr_c7 *a)
{
  Eurydice_mut_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)64U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 48
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8 Eurydice_array_منزل_ٹکڑا_mut_9f(Eurydice_arr_65 *a)
{
  Eurydice_mut_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)48U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 32
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8 Eurydice_array_منزل_ٹکڑا_mut_01(Eurydice_arr_ec *a)
{
  Eurydice_mut_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)32U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $28size_t
*/
تعريفنوع بنية Eurydice_arr_a2_s { uint8_t انکڑے[28U]; } Eurydice_arr_a2;

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 28
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8 Eurydice_array_منزل_ٹکڑا_mut_5e(Eurydice_arr_a2 *a)
{
  Eurydice_mut_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)28U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $104size_t
*/
تعريفنوع بنية Eurydice_arr_c4_s { uint8_t انکڑے[104U]; } Eurydice_arr_c4;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 104
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_ٹکڑا_shared_72(ثابت Eurydice_arr_c4 *a)
{
  Eurydice_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)104U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 104
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8
Eurydice_array_منزل_subslice_mut_d45(Eurydice_arr_c4 *a, core_ops_range_Range_87 r)
{
  أرجع
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ٹکڑا_u8){
        .ptr = a->انکڑے + r.شروع,
        .meta = r.سرا - r.شروع
      }
    );
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $144size_t
*/
تعريفنوع بنية Eurydice_arr_f4_s { uint8_t انکڑے[144U]; } Eurydice_arr_f4;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 144
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_ٹکڑا_shared_38(ثابت Eurydice_arr_f4 *a)
{
  Eurydice_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)144U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 144
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8
Eurydice_array_منزل_subslice_mut_d44(Eurydice_arr_f4 *a, core_ops_range_Range_87 r)
{
  أرجع
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ٹکڑا_u8){
        .ptr = a->انکڑے + r.شروع,
        .meta = r.سرا - r.شروع
      }
    );
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $72size_t
*/
تعريفنوع بنية Eurydice_arr_ab_s { uint8_t انکڑے[72U]; } Eurydice_arr_ab;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 72
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_ٹکڑا_shared_e2(ثابت Eurydice_arr_ab *a)
{
  Eurydice_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)72U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 72
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8
Eurydice_array_منزل_subslice_mut_d43(Eurydice_arr_ab *a, core_ops_range_Range_87 r)
{
  أرجع
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ٹکڑا_u8){
        .ptr = a->انکڑے + r.شروع,
        .meta = r.سرا - r.شروع
      }
    );
}

/**
A monomorphic instance of Eurydice.slice_subslice_to_shared
with types uint8_t, core_ops_range_RangeTo size_t, Eurydice_derefed_slice uint8_t

*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_ٹکڑا_subslice_منزل_shared_72(Eurydice_borrow_ٹکڑا_u8 s, ناپ_t r)
{
  أرجع (KRML_CLITERAL(Eurydice_borrow_ٹکڑا_u8){ .ptr = s.ptr, .meta = r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_from_mut
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 136
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8
Eurydice_array_منزل_subslice_from_mut_5f(Eurydice_arr_ff *a, ناپ_t r)
{
  أرجع
    (KRML_CLITERAL(Eurydice_mut_borrow_ٹکڑا_u8){ .ptr = a->انکڑے + r, .meta = (ناپ_t)136U - r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_to_shared
with types uint8_t, core_ops_range_RangeTo size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 8
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_subslice_منزل_shared_21(ثابت Eurydice_array_u8x8 *a, ناپ_t r)
{
  Eurydice_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = r;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 8
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_ٹکڑا_shared_6e(ثابت Eurydice_array_u8x8 *a)
{
  Eurydice_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)8U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.slice_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t

*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8
Eurydice_ٹکڑا_subslice_mut_c8(Eurydice_mut_borrow_ٹکڑا_u8 s, core_ops_range_Range_87 r)
{
  أرجع
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ٹکڑا_u8){ .ptr = s.ptr + r.شروع, .meta = r.سرا - r.شروع }
    );
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 136
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_ٹکڑا_shared_58(ثابت Eurydice_arr_ff *a)
{
  Eurydice_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)136U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 136
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8
Eurydice_array_منزل_subslice_mut_d42(Eurydice_arr_ff *a, core_ops_range_Range_87 r)
{
  أرجع
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ٹکڑا_u8){
        .ptr = a->انکڑے + r.شروع,
        .meta = r.سرا - r.شروع
      }
    );
}

/**
A monomorphic instance of Eurydice.arr
with types uint64_t
with const generics
- $5size_t
*/
تعريفنوع بنية Eurydice_arr_84_s { uint64_t انکڑے[5U]; } Eurydice_arr_84;

تعريفنوع بنية ناپ_t_x2_s
{
  ناپ_t fst;
  ناپ_t snd;
}
ناپ_t_x2;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_borrow_slice_u8
with const generics
- $1size_t
*/
تعريفنوع بنية Eurydice_arr_dc_s { Eurydice_borrow_ٹکڑا_u8 انکڑے[1U]; } Eurydice_arr_dc;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 168
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_array_منزل_ٹکڑا_shared_2c(ثابت Eurydice_arr_c5 *a)
{
  Eurydice_borrow_ٹکڑا_u8 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)168U;
  أرجع lit;
}

/**
A monomorphic instance of core.result.Result
with types Eurydice_array_u8x8, core_array_TryFromSliceError

*/
تعريفنوع بنية core_نتیجہ_نتیجہ_8e_s
{
  core_نتیجہ_نتیجہ_57_ٹیگ_سوچی ٹیگ;
  اتحاد {
    Eurydice_array_u8x8 case_Ok;
    core_array_Try_From_ٹکڑا_Error case_Err;
  }
  val;
}
core_نتیجہ_نتیجہ_8e;

/**
This function found in impl {core::result::Result<T, E>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of core.result.unwrap_26
with types Eurydice_arr uint8_t[[$8size_t]], core_array_TryFromSliceError

*/
ساكن مضمن Eurydice_array_u8x8 core_نتیجہ_unwrap_26_e0(core_نتیجہ_نتیجہ_8e self)
{
  إذا (self.ٹیگ == core_نتیجہ_Ok)
  {
    أرجع self.val.case_Ok;
  }
  وإلا
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __FILE__, __LINE__, "unwrap not Ok");
    KRML_HOST_EXIT(255U);
  }
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 168
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8
Eurydice_array_منزل_subslice_mut_d41(Eurydice_arr_c5 *a, core_ops_range_Range_87 r)
{
  أرجع
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ٹکڑا_u8){
        .ptr = a->انکڑے + r.شروع,
        .meta = r.سرا - r.شروع
      }
    );
}

/**
A monomorphic instance of Eurydice.arr
with types uint64_t
with const generics
- $24size_t
*/
تعريفنوع بنية Eurydice_arr_22_s { uint64_t انکڑے[24U]; } Eurydice_arr_22;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_ff
with const generics
- $1size_t
*/
تعريفنوع بنية Eurydice_arr_0b_s { Eurydice_arr_ff انکڑے[1U]; } Eurydice_arr_0b;

/**
A monomorphic instance of Eurydice.arr
with types uint64_t
with const generics
- $25size_t
*/
تعريفنوع بنية Eurydice_arr_7c_s { uint64_t انکڑے[25U]; } Eurydice_arr_7c;

/**
A monomorphic instance of Eurydice.slice_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t

*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
Eurydice_ٹکڑا_subslice_shared_c8(Eurydice_borrow_ٹکڑا_u8 s, core_ops_range_Range_87 r)
{
  أرجع
    (KRML_CLITERAL(Eurydice_borrow_ٹکڑا_u8){ .ptr = s.ptr + r.شروع, .meta = r.سرا - r.شروع });
}

/**
A monomorphic instance of Eurydice.arr
with types int32_t
with const generics
- $8size_t
*/
تعريفنوع بنية Eurydice_arr_4d_s { int32_t انکڑے[8U]; } Eurydice_arr_4d;

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types int32_t, core_ops_range_Range size_t, Eurydice_derefed_slice int32_t
with const generics
- N= 8
*/
ساكن مضمن Eurydice_dst_ref_shared_83
Eurydice_array_منزل_subslice_shared_44(ثابت Eurydice_arr_4d *a, core_ops_range_Range_87 r)
{
  أرجع
    (
      KRML_CLITERAL(Eurydice_dst_ref_shared_83){ .ptr = a->انکڑے + r.شروع, .meta = r.سرا - r.شروع }
    );
}

/**
 Declassify secret memory.

 No-op if `valgrind_ct_test` cfg is not enabled.
*/
/**
A monomorphic instance of libcrux_secrets.mem_requests.ct_declassify
with types bool

*/
ساكن KRML_MUSTINLINE فراغ libcrux_secrets_mem_بینتیاں_ct_declassify_5f(ثابت bool *val)
{

}

تعريفنوع بنية int32_t_x2_s
{
  int32_t fst;
  int32_t snd;
}
int32_t_x2;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types int32_t
with const generics
- N= 8
*/
ساكن مضمن Eurydice_dst_ref_shared_83
Eurydice_array_منزل_ٹکڑا_shared_fd(ثابت Eurydice_arr_4d *a)
{
  Eurydice_dst_ref_shared_83 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)8U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.slice_subslice_shared
with types int32_t, core_ops_range_Range size_t, Eurydice_derefed_slice int32_t

*/
ساكن مضمن Eurydice_dst_ref_shared_83
Eurydice_ٹکڑا_subslice_shared_47(Eurydice_dst_ref_shared_83 s, core_ops_range_Range_87 r)
{
  أرجع
    (KRML_CLITERAL(Eurydice_dst_ref_shared_83){ .ptr = s.ptr + r.شروع, .meta = r.سرا - r.شروع });
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types int32_t
with const generics
- N= 8
*/
ساكن مضمن Eurydice_dst_ref_mut_83 Eurydice_array_منزل_ٹکڑا_mut_fd(Eurydice_arr_4d *a)
{
  Eurydice_dst_ref_mut_83 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)8U;
  أرجع lit;
}

/**
A monomorphic instance of core.option.Option
with types Eurydice_arr_c9

*/
تعريفنوع بنية core_option_Option_57_s
{
  core_option_Option_45_ٹیگ_سوچی ٹیگ;
  Eurydice_arr_c9 f0;
}
core_option_Option_57;

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 34
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8
Eurydice_array_منزل_subslice_mut_d40(Eurydice_arr_31 *a, core_ops_range_Range_87 r)
{
  أرجع
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ٹکڑا_u8){
        .ptr = a->انکڑے + r.شروع,
        .meta = r.سرا - r.شروع
      }
    );
}

تعريفنوع بنية uint8_t_x2_s
{
  uint8_t fst;
  uint8_t snd;
}
uint8_t_x2;

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 66
*/
ساكن مضمن Eurydice_mut_borrow_ٹکڑا_u8
Eurydice_array_منزل_subslice_mut_d4(Eurydice_arr_91 *a, core_ops_range_Range_87 r)
{
  أرجع
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ٹکڑا_u8){
        .ptr = a->انکڑے + r.شروع,
        .meta = r.سرا - r.شروع
      }
    );
}

تعريفنوع بنية libcrux_ml_kem_utils_extraction_helper_Keypair768_s
{
  Eurydice_arr_0e fst;
  Eurydice_arr_5f snd;
}
libcrux_ml_kem_utils_extraction_helper_Keypair768;

/**
This function found in impl {libcrux_secrets::traits::Declassify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.declassify_d8
with types uint64_t

*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_secrets_int_عوامی_integers_declassify_d8_49(uint64_t self)
{
  أرجع self;
}

/**
This function found in impl {libcrux_secrets::traits::Classify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.classify_27
with types uint32_t

*/
ساكن KRML_MUSTINLINE uint32_t
libcrux_secrets_int_عوامی_integers_classify_27_df(uint32_t self)
{
  أرجع self;
}

/**
This function found in impl {libcrux_secrets::traits::Classify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.classify_27
with types uint64_t

*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_secrets_int_عوامی_integers_classify_27_49(uint64_t self)
{
  أرجع self;
}

/**
This function found in impl {libcrux_secrets::traits::Declassify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.declassify_d8
with types uint16_t

*/
ساكن KRML_MUSTINLINE uint16_t
libcrux_secrets_int_عوامی_integers_declassify_d8_de(uint16_t self)
{
  أرجع self;
}

/**
This function found in impl {libcrux_secrets::traits::Classify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.classify_27
with types uint16_t

*/
ساكن KRML_MUSTINLINE uint16_t
libcrux_secrets_int_عوامی_integers_classify_27_de(uint16_t self)
{
  أرجع self;
}

/**
This function found in impl {libcrux_secrets::traits::Declassify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.declassify_d8
with types uint32_t

*/
ساكن KRML_MUSTINLINE uint32_t
libcrux_secrets_int_عوامی_integers_declassify_d8_df(uint32_t self)
{
  أرجع self;
}

/**
This function found in impl {libcrux_secrets::traits::Declassify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.declassify_d8
with types int32_t

*/
ساكن KRML_MUSTINLINE int32_t
libcrux_secrets_int_عوامی_integers_declassify_d8_a8(int32_t self)
{
  أرجع self;
}

/**
This function found in impl {libcrux_secrets::traits::Classify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.classify_27
with types int32_t

*/
ساكن KRML_MUSTINLINE int32_t libcrux_secrets_int_عوامی_integers_classify_27_a8(int32_t self)
{
  أرجع self;
}

/**
This function found in impl {libcrux_secrets::traits::Declassify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.declassify_d8
with types uint8_t

*/
ساكن KRML_MUSTINLINE uint8_t
libcrux_secrets_int_عوامی_integers_declassify_d8_90(uint8_t self)
{
  أرجع self;
}

/**
This function found in impl {libcrux_secrets::traits::Classify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.classify_27
with types int16_t

*/
ساكن KRML_MUSTINLINE int16_t libcrux_secrets_int_عوامی_integers_classify_27_39(int16_t self)
{
  أرجع self;
}

/**
This function found in impl {libcrux_secrets::traits::Declassify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.declassify_d8
with types int16_t

*/
ساكن KRML_MUSTINLINE int16_t
libcrux_secrets_int_عوامی_integers_declassify_d8_39(int16_t self)
{
  أرجع self;
}

/**
This function found in impl {libcrux_secrets::traits::Classify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.classify_27
with types uint8_t

*/
ساكن KRML_MUSTINLINE uint8_t libcrux_secrets_int_عوامی_integers_classify_27_90(uint8_t self)
{
  أرجع self;
}

#إذا defined(__cplusplus)
}
#جے_انت

#تعریف_کرو combined_core_H_DEFINED
#جے_انت /* combined_core_H */

/* from libcrux/combined_extraction/generated/libcrux_sha3_portable.h */
/*
 * SPDX-FileCopyrightText: 2025 Cryspen Sarl <info@cryspen.com>
 *
 * SPDX-License-Identifier: MIT or Apache-2.0
 *
 * This code was generated with the following revisions:
 * Charon: e656e17bff6ca5efac8ab6919b9b74cb9a8dd8ad
 * Eurydice: aaa9fa657fb6f09802edb890252040d94cd93982
 * Karamel: 8c19d41458ce5cbfea029ebc03334ba96d149039
 * F*: unset
 * Libcrux: c4e5e5e511bbc4c53f826163f57bfd10e9228911
 */


#جے_بنا_تعریف libcrux_sha3_portable_H
#تعریف_کرو libcrux_sha3_portable_H



#إذا defined(__cplusplus)
خارجي "C" {
#جے_انت


/**
A monomorphic instance of libcrux_sha3.generic_keccak.KeccakState
with types uint64_t
with const generics
- $1size_t
*/
تعريفنوع Eurydice_arr_7c libcrux_sha3_generic_keccak_KeccakState_f3;

تعريفنوع libcrux_sha3_generic_keccak_KeccakState_f3 libcrux_sha3_portable_KeccakState;

/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.KeccakXofState
with types uint64_t
with const generics
- $1size_t
- $136size_t
*/
تعريفنوع بنية libcrux_sha3_generic_keccak_xof_KeccakXofState_8d_s
{
  Eurydice_arr_7c inner;
  Eurydice_arr_0b buf;
  ناپ_t buf_len;
  bool sponge;
}
libcrux_sha3_generic_keccak_xof_KeccakXofState_8d;

تعريفنوع libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
libcrux_sha3_portable_incremental_Shake256Xof;

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
ساكن KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_zero_d2(فراغ)
{
  أرجع 0ULL;
}

ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__veor5q_u64(
  uint64_t a,
  uint64_t b,
  uint64_t c,
  uint64_t d,
  uint64_t e
)
{
  أرجع (((a ^ b) ^ c) ^ d) ^ e;
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor5_d2(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e)
{
  أرجع libcrux_sha3_simd_portable__veor5q_u64(a, b, c, d, e);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 1
- RIGHT= 63
*/
ساكن KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_بایاں_76(uint64_t x)
{
  أرجع core_عدد_u64_rotate_بایاں(x, (uint32_t)1);
}

ساكن KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable__vrax1q_u64(uint64_t a, uint64_t b)
{
  أرجع a ^ libcrux_sha3_simd_portable_rotate_بایاں_76(b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_rotate_left1_and_xor_d2(uint64_t a, uint64_t b)
{
  أرجع libcrux_sha3_simd_portable__vrax1q_u64(a, b);
}

ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vbcaxq_u64(uint64_t a, uint64_t b, uint64_t c)
{
  أرجع a ^ (b & ~c);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_and_not_xor_d2(uint64_t a, uint64_t b, uint64_t c)
{
  أرجع libcrux_sha3_simd_portable__vbcaxq_u64(a, b, c);
}

ساكن KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable__veorq_n_u64(uint64_t a, uint64_t c)
{
  أرجع a ^ c;
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_constant_d2(uint64_t a, uint64_t c)
{
  أرجع libcrux_sha3_simd_portable__veorq_n_u64(a, c);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
ساكن KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_xor_d2(uint64_t a, uint64_t b)
{
  أرجع a ^ b;
}

/**
 Create a new Shake128 x4 state.
*/
/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.new_80
with types uint64_t
with const generics
- N= 1
*/
ساكن KRML_MUSTINLINE Eurydice_arr_7c libcrux_sha3_generic_keccak_new_80_71(فراغ)
{
  Eurydice_arr_7c lit;
  uint64_t repeat_عبارت[25U];
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)25U; i++)
  {
    repeat_عبارت[i] = libcrux_sha3_simd_portable_zero_d2();
  }
  حافظہ_نقل(lit.انکڑے, repeat_عبارت, (ناپ_t)25U * حجم (uint64_t));
  أرجع lit;
}

/**
 Create a new SHAKE-128 state object.
*/
ساكن KRML_MUSTINLINE Eurydice_arr_7c libcrux_sha3_portable_incremental_shake128_init(فراغ)
{
  أرجع libcrux_sha3_generic_keccak_new_80_71();
}

#تعریف_کرو LIBCRUX_SHA3_GENERIC_KECCAK_CONSTANTS_ROUNDCONSTANTS ((KRML_CLITERAL(Eurydice_arr_22){ .انکڑے = { 1ULL, 32898ULL, 9223372036854808714ULL, 9223372039002292224ULL, 32907ULL, 2147483649ULL, 9223372039002292353ULL, 9223372036854808585ULL, 138ULL, 136ULL, 2147516425ULL, 2147483658ULL, 2147516555ULL, 9223372036854775947ULL, 9223372036854808713ULL, 9223372036854808579ULL, 9223372036854808578ULL, 9223372036854775936ULL, 32778ULL, 9223372039002259466ULL, 9223372039002292353ULL, 9223372036854808704ULL, 2147483649ULL, 9223372039002292232ULL } }))

/**
A monomorphic instance of libcrux_sha3.traits.get_ij
with types uint64_t
with const generics
- N= 1
*/
ساكن KRML_MUSTINLINE ثابت
uint64_t
*libcrux_sha3_traits_get_ij_71(ثابت Eurydice_arr_7c *arr, ناپ_t i, ناپ_t j)
{
  أرجع &arr->انکڑے[(ناپ_t)5U * j + i];
}

/**
A monomorphic instance of libcrux_sha3.traits.set_ij
with types uint64_t
with const generics
- N= 1
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_traits_سیٹ_ij_71(Eurydice_arr_7c *arr, ناپ_t i, ناپ_t j, uint64_t قدر)
{
  arr->انکڑے[(ناپ_t)5U * j + i] = قدر;
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_block
with const generics
- RATE= 168
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_simd_portable_لدو_بلاک_60(
  Eurydice_arr_7c *state,
  Eurydice_borrow_ٹکڑا_u8 بلاکاں,
  ناپ_t شروع
)
{
  Eurydice_arr_7c state_flat = { .انکڑے = { 0U } };
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)168U / (ناپ_t)8U; i++)
  {
    ناپ_t i0 = i;
    ناپ_t وتھ = شروع + (ناپ_t)8U * i0;
    Eurydice_array_u8x8 arr;
    حافظہ_نقل(arr.انکڑے,
      Eurydice_ٹکڑا_subslice_shared_c8(بلاکاں,
        (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = وتھ, .سرا = وتھ + (ناپ_t)8U })).ptr,
      (ناپ_t)8U * حجم (uint8_t));
    Eurydice_array_u8x8
    uu____0 =
      core_نتیجہ_unwrap_26_e0((
          KRML_CLITERAL(core_نتیجہ_نتیجہ_8e){ .ٹیگ = core_نتیجہ_Ok, .val = { .case_Ok = arr } }
        ));
    state_flat.انکڑے[i0] = core_عدد_u64_from_le_بائٹاں(uu____0);
  }
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)168U / (ناپ_t)8U; i++)
  {
    ناپ_t i0 = i;
    libcrux_sha3_traits_سیٹ_ij_71(state,
      i0 / (ناپ_t)5U,
      i0 % (ناپ_t)5U,
      libcrux_sha3_traits_get_ij_71(state, i0 / (ناپ_t)5U, i0 % (ناپ_t)5U)[0U] ^
        state_flat.انکڑے[i0]);
  }
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_last
with const generics
- RATE= 168
- DELIMITER= 31
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_simd_portable_لدو_آخری_37(
  Eurydice_arr_7c *state,
  Eurydice_borrow_ٹکڑا_u8 بلاکاں,
  ناپ_t شروع,
  ناپ_t len
)
{
  Eurydice_arr_c5 بفر = { .انکڑے = { 0U } };
  Eurydice_ٹکڑا_copy(Eurydice_array_منزل_subslice_mut_d41(&بفر,
      (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = (ناپ_t)0U, .سرا = len })),
    Eurydice_ٹکڑا_subslice_shared_c8(بلاکاں,
      (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = شروع, .سرا = شروع + len })),
    uint8_t);
  بفر.انکڑے[len] = 31U;
  ناپ_t uu____0 = (ناپ_t)168U - (ناپ_t)1U;
  بفر.انکڑے[uu____0] = (uint32_t)بفر.انکڑے[uu____0] | 128U;
  libcrux_sha3_simd_portable_لدو_بلاک_60(state,
    Eurydice_array_منزل_ٹکڑا_shared_2c(&بفر),
    (ناپ_t)0U);
}

/**
This function found in impl {libcrux_sha3::traits::Absorb<1usize> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.load_last_a1
with const generics
- RATE= 168
- DELIMITER= 31
*/
ساكن مضمن فراغ
libcrux_sha3_simd_portable_لدو_آخری_a1_37(
  Eurydice_arr_7c *self,
  ثابت Eurydice_arr_dc *داخلہ,
  ناپ_t شروع,
  ناپ_t len
)
{
  libcrux_sha3_simd_portable_لدو_آخری_37(self, داخلہ->انکڑے[0U], شروع, len);
}

/**
 Get element `[i, j]`.
*/
/**
This function found in impl {core::ops::index::Index<(usize, usize), T> for libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.index_c2
with types uint64_t
with const generics
- N= 1
*/
ساكن مضمن ثابت
uint64_t
*libcrux_sha3_generic_keccak_اشاریہ_c2_71(ثابت Eurydice_arr_7c *self, ناپ_t_x2 index)
{
  أرجع libcrux_sha3_traits_get_ij_71(self, index.fst, index.snd);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.theta_80
with types uint64_t
with const generics
- N= 1
*/
ساكن KRML_MUSTINLINE Eurydice_arr_84
libcrux_sha3_generic_keccak_theta_80_71(Eurydice_arr_7c *self)
{
  Eurydice_arr_84
  c =
    {
      .انکڑے = {
        libcrux_sha3_simd_portable_xor5_d2(libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
            (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)0U, .snd = (ناپ_t)0U }))[0U],
          libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
            (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)1U, .snd = (ناپ_t)0U }))[0U],
          libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
            (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)2U, .snd = (ناپ_t)0U }))[0U],
          libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
            (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)3U, .snd = (ناپ_t)0U }))[0U],
          libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
            (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)4U, .snd = (ناپ_t)0U }))[0U]),
        libcrux_sha3_simd_portable_xor5_d2(libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
            (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)0U, .snd = (ناپ_t)1U }))[0U],
          libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
            (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)1U, .snd = (ناپ_t)1U }))[0U],
          libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
            (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)2U, .snd = (ناپ_t)1U }))[0U],
          libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
            (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)3U, .snd = (ناپ_t)1U }))[0U],
          libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
            (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)4U, .snd = (ناپ_t)1U }))[0U]),
        libcrux_sha3_simd_portable_xor5_d2(libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
            (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)0U, .snd = (ناپ_t)2U }))[0U],
          libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
            (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)1U, .snd = (ناپ_t)2U }))[0U],
          libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
            (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)2U, .snd = (ناپ_t)2U }))[0U],
          libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
            (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)3U, .snd = (ناپ_t)2U }))[0U],
          libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
            (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)4U, .snd = (ناپ_t)2U }))[0U]),
        libcrux_sha3_simd_portable_xor5_d2(libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
            (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)0U, .snd = (ناپ_t)3U }))[0U],
          libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
            (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)1U, .snd = (ناپ_t)3U }))[0U],
          libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
            (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)2U, .snd = (ناپ_t)3U }))[0U],
          libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
            (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)3U, .snd = (ناپ_t)3U }))[0U],
          libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
            (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)4U, .snd = (ناپ_t)3U }))[0U]),
        libcrux_sha3_simd_portable_xor5_d2(libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
            (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)0U, .snd = (ناپ_t)4U }))[0U],
          libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
            (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)1U, .snd = (ناپ_t)4U }))[0U],
          libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
            (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)2U, .snd = (ناپ_t)4U }))[0U],
          libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
            (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)3U, .snd = (ناپ_t)4U }))[0U],
          libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
            (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)4U, .snd = (ناپ_t)4U }))[0U])
      }
    };
  أرجع
    (
      KRML_CLITERAL(Eurydice_arr_84){
        .انکڑے = {
          libcrux_sha3_simd_portable_rotate_left1_and_xor_d2(c.انکڑے[((ناپ_t)0U + (ناپ_t)4U) %
              (ناپ_t)5U],
            c.انکڑے[((ناپ_t)0U + (ناپ_t)1U) % (ناپ_t)5U]),
          libcrux_sha3_simd_portable_rotate_left1_and_xor_d2(c.انکڑے[((ناپ_t)1U + (ناپ_t)4U) %
              (ناپ_t)5U],
            c.انکڑے[((ناپ_t)1U + (ناپ_t)1U) % (ناپ_t)5U]),
          libcrux_sha3_simd_portable_rotate_left1_and_xor_d2(c.انکڑے[((ناپ_t)2U + (ناپ_t)4U) %
              (ناپ_t)5U],
            c.انکڑے[((ناپ_t)2U + (ناپ_t)1U) % (ناپ_t)5U]),
          libcrux_sha3_simd_portable_rotate_left1_and_xor_d2(c.انکڑے[((ناپ_t)3U + (ناپ_t)4U) %
              (ناپ_t)5U],
            c.انکڑے[((ناپ_t)3U + (ناپ_t)1U) % (ناپ_t)5U]),
          libcrux_sha3_simd_portable_rotate_left1_and_xor_d2(c.انکڑے[((ناپ_t)4U + (ناپ_t)4U) %
              (ناپ_t)5U],
            c.انکڑے[((ناپ_t)4U + (ناپ_t)1U) % (ناپ_t)5U])
        }
      }
    );
}

/**
 Set element `[i, j] = v`.
*/
/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.set_80
with types uint64_t
with const generics
- N= 1
*/
ساكن مضمن فراغ
libcrux_sha3_generic_keccak_سیٹ_80_71(Eurydice_arr_7c *self, ناپ_t i, ناپ_t j, uint64_t v)
{
  libcrux_sha3_traits_سیٹ_ij_71(self, i, j, v);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 36
- RIGHT= 28
*/
ساكن KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_بایاں_02(uint64_t x)
{
  أرجع core_عدد_u64_rotate_بایاں(x, (uint32_t)36);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 36
- RIGHT= 28
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_02(uint64_t a, uint64_t b)
{
  أرجع libcrux_sha3_simd_portable_rotate_بایاں_02(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 36
- RIGHT= 28
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_02(uint64_t a, uint64_t b)
{
  أرجع libcrux_sha3_simd_portable__vxarq_u64_02(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 3
- RIGHT= 61
*/
ساكن KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_بایاں_ac(uint64_t x)
{
  أرجع core_عدد_u64_rotate_بایاں(x, (uint32_t)3);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 3
- RIGHT= 61
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_ac(uint64_t a, uint64_t b)
{
  أرجع libcrux_sha3_simd_portable_rotate_بایاں_ac(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 3
- RIGHT= 61
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_ac(uint64_t a, uint64_t b)
{
  أرجع libcrux_sha3_simd_portable__vxarq_u64_ac(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 41
- RIGHT= 23
*/
ساكن KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_بایاں_020(uint64_t x)
{
  أرجع core_عدد_u64_rotate_بایاں(x, (uint32_t)41);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 41
- RIGHT= 23
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_020(uint64_t a, uint64_t b)
{
  أرجع libcrux_sha3_simd_portable_rotate_بایاں_020(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 41
- RIGHT= 23
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_020(uint64_t a, uint64_t b)
{
  أرجع libcrux_sha3_simd_portable__vxarq_u64_020(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 18
- RIGHT= 46
*/
ساكن KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_بایاں_a9(uint64_t x)
{
  أرجع core_عدد_u64_rotate_بایاں(x, (uint32_t)18);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 18
- RIGHT= 46
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_a9(uint64_t a, uint64_t b)
{
  أرجع libcrux_sha3_simd_portable_rotate_بایاں_a9(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 18
- RIGHT= 46
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_a9(uint64_t a, uint64_t b)
{
  أرجع libcrux_sha3_simd_portable__vxarq_u64_a9(a, b);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.rho_0_80
with types uint64_t
with const generics
- N= 1
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_generic_keccak_rho_0_80_71(Eurydice_arr_7c *self, Eurydice_arr_84 t)
{
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)0U,
    (ناپ_t)0U,
    libcrux_sha3_simd_portable_xor_d2(libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
        (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)0U, .snd = (ناپ_t)0U }))[0U],
      t.انکڑے[0U]));
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)1U,
    (ناپ_t)0U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_02(libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
        (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)1U, .snd = (ناپ_t)0U }))[0U],
      t.انکڑے[0U]));
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)2U,
    (ناپ_t)0U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_ac(libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
        (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)2U, .snd = (ناپ_t)0U }))[0U],
      t.انکڑے[0U]));
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)3U,
    (ناپ_t)0U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_020(libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
        (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)3U, .snd = (ناپ_t)0U }))[0U],
      t.انکڑے[0U]));
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)4U,
    (ناپ_t)0U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_a9(libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
        (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)4U, .snd = (ناپ_t)0U }))[0U],
      t.انکڑے[0U]));
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 1
- RIGHT= 63
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_76(uint64_t a, uint64_t b)
{
  أرجع libcrux_sha3_simd_portable_rotate_بایاں_76(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 1
- RIGHT= 63
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_76(uint64_t a, uint64_t b)
{
  أرجع libcrux_sha3_simd_portable__vxarq_u64_76(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 44
- RIGHT= 20
*/
ساكن KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_بایاں_58(uint64_t x)
{
  أرجع core_عدد_u64_rotate_بایاں(x, (uint32_t)44);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 44
- RIGHT= 20
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_58(uint64_t a, uint64_t b)
{
  أرجع libcrux_sha3_simd_portable_rotate_بایاں_58(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 44
- RIGHT= 20
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_58(uint64_t a, uint64_t b)
{
  أرجع libcrux_sha3_simd_portable__vxarq_u64_58(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 10
- RIGHT= 54
*/
ساكن KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_بایاں_e0(uint64_t x)
{
  أرجع core_عدد_u64_rotate_بایاں(x, (uint32_t)10);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 10
- RIGHT= 54
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_e0(uint64_t a, uint64_t b)
{
  أرجع libcrux_sha3_simd_portable_rotate_بایاں_e0(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 10
- RIGHT= 54
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_e0(uint64_t a, uint64_t b)
{
  أرجع libcrux_sha3_simd_portable__vxarq_u64_e0(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 45
- RIGHT= 19
*/
ساكن KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_بایاں_63(uint64_t x)
{
  أرجع core_عدد_u64_rotate_بایاں(x, (uint32_t)45);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 45
- RIGHT= 19
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_63(uint64_t a, uint64_t b)
{
  أرجع libcrux_sha3_simd_portable_rotate_بایاں_63(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 45
- RIGHT= 19
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_63(uint64_t a, uint64_t b)
{
  أرجع libcrux_sha3_simd_portable__vxarq_u64_63(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 2
- RIGHT= 62
*/
ساكن KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_بایاں_6a(uint64_t x)
{
  أرجع core_عدد_u64_rotate_بایاں(x, (uint32_t)2);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 2
- RIGHT= 62
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_6a(uint64_t a, uint64_t b)
{
  أرجع libcrux_sha3_simd_portable_rotate_بایاں_6a(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 2
- RIGHT= 62
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_6a(uint64_t a, uint64_t b)
{
  أرجع libcrux_sha3_simd_portable__vxarq_u64_6a(a, b);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.rho_1_80
with types uint64_t
with const generics
- N= 1
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_generic_keccak_rho_1_80_71(Eurydice_arr_7c *self, Eurydice_arr_84 t)
{
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)0U,
    (ناپ_t)1U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_76(libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
        (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)0U, .snd = (ناپ_t)1U }))[0U],
      t.انکڑے[1U]));
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)1U,
    (ناپ_t)1U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_58(libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
        (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)1U, .snd = (ناپ_t)1U }))[0U],
      t.انکڑے[1U]));
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)2U,
    (ناپ_t)1U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_e0(libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
        (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)2U, .snd = (ناپ_t)1U }))[0U],
      t.انکڑے[1U]));
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)3U,
    (ناپ_t)1U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_63(libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
        (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)3U, .snd = (ناپ_t)1U }))[0U],
      t.انکڑے[1U]));
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)4U,
    (ناپ_t)1U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_6a(libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
        (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)4U, .snd = (ناپ_t)1U }))[0U],
      t.انکڑے[1U]));
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 62
- RIGHT= 2
*/
ساكن KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_بایاں_ab(uint64_t x)
{
  أرجع core_عدد_u64_rotate_بایاں(x, (uint32_t)62);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 62
- RIGHT= 2
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_ab(uint64_t a, uint64_t b)
{
  أرجع libcrux_sha3_simd_portable_rotate_بایاں_ab(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 62
- RIGHT= 2
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_ab(uint64_t a, uint64_t b)
{
  أرجع libcrux_sha3_simd_portable__vxarq_u64_ab(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 6
- RIGHT= 58
*/
ساكن KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_بایاں_5b(uint64_t x)
{
  أرجع core_عدد_u64_rotate_بایاں(x, (uint32_t)6);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 6
- RIGHT= 58
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_5b(uint64_t a, uint64_t b)
{
  أرجع libcrux_sha3_simd_portable_rotate_بایاں_5b(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 6
- RIGHT= 58
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_5b(uint64_t a, uint64_t b)
{
  أرجع libcrux_sha3_simd_portable__vxarq_u64_5b(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 43
- RIGHT= 21
*/
ساكن KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_بایاں_6f(uint64_t x)
{
  أرجع core_عدد_u64_rotate_بایاں(x, (uint32_t)43);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 43
- RIGHT= 21
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_6f(uint64_t a, uint64_t b)
{
  أرجع libcrux_sha3_simd_portable_rotate_بایاں_6f(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 43
- RIGHT= 21
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_6f(uint64_t a, uint64_t b)
{
  أرجع libcrux_sha3_simd_portable__vxarq_u64_6f(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 15
- RIGHT= 49
*/
ساكن KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_بایاں_62(uint64_t x)
{
  أرجع core_عدد_u64_rotate_بایاں(x, (uint32_t)15);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 15
- RIGHT= 49
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_62(uint64_t a, uint64_t b)
{
  أرجع libcrux_sha3_simd_portable_rotate_بایاں_62(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 15
- RIGHT= 49
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_62(uint64_t a, uint64_t b)
{
  أرجع libcrux_sha3_simd_portable__vxarq_u64_62(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 61
- RIGHT= 3
*/
ساكن KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_بایاں_23(uint64_t x)
{
  أرجع core_عدد_u64_rotate_بایاں(x, (uint32_t)61);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 61
- RIGHT= 3
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_23(uint64_t a, uint64_t b)
{
  أرجع libcrux_sha3_simd_portable_rotate_بایاں_23(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 61
- RIGHT= 3
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_23(uint64_t a, uint64_t b)
{
  أرجع libcrux_sha3_simd_portable__vxarq_u64_23(a, b);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.rho_2_80
with types uint64_t
with const generics
- N= 1
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_generic_keccak_rho_2_80_71(Eurydice_arr_7c *self, Eurydice_arr_84 t)
{
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)0U,
    (ناپ_t)2U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_ab(libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
        (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)0U, .snd = (ناپ_t)2U }))[0U],
      t.انکڑے[2U]));
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)1U,
    (ناپ_t)2U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_5b(libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
        (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)1U, .snd = (ناپ_t)2U }))[0U],
      t.انکڑے[2U]));
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)2U,
    (ناپ_t)2U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_6f(libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
        (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)2U, .snd = (ناپ_t)2U }))[0U],
      t.انکڑے[2U]));
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)3U,
    (ناپ_t)2U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_62(libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
        (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)3U, .snd = (ناپ_t)2U }))[0U],
      t.انکڑے[2U]));
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)4U,
    (ناپ_t)2U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_23(libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
        (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)4U, .snd = (ناپ_t)2U }))[0U],
      t.انکڑے[2U]));
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 28
- RIGHT= 36
*/
ساكن KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_بایاں_37(uint64_t x)
{
  أرجع core_عدد_u64_rotate_بایاں(x, (uint32_t)28);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 28
- RIGHT= 36
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_37(uint64_t a, uint64_t b)
{
  أرجع libcrux_sha3_simd_portable_rotate_بایاں_37(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 28
- RIGHT= 36
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_37(uint64_t a, uint64_t b)
{
  أرجع libcrux_sha3_simd_portable__vxarq_u64_37(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 55
- RIGHT= 9
*/
ساكن KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_بایاں_bb(uint64_t x)
{
  أرجع core_عدد_u64_rotate_بایاں(x, (uint32_t)55);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 55
- RIGHT= 9
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_bb(uint64_t a, uint64_t b)
{
  أرجع libcrux_sha3_simd_portable_rotate_بایاں_bb(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 55
- RIGHT= 9
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_bb(uint64_t a, uint64_t b)
{
  أرجع libcrux_sha3_simd_portable__vxarq_u64_bb(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 25
- RIGHT= 39
*/
ساكن KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_بایاں_b9(uint64_t x)
{
  أرجع core_عدد_u64_rotate_بایاں(x, (uint32_t)25);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 25
- RIGHT= 39
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_b9(uint64_t a, uint64_t b)
{
  أرجع libcrux_sha3_simd_portable_rotate_بایاں_b9(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 25
- RIGHT= 39
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_b9(uint64_t a, uint64_t b)
{
  أرجع libcrux_sha3_simd_portable__vxarq_u64_b9(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 21
- RIGHT= 43
*/
ساكن KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_بایاں_54(uint64_t x)
{
  أرجع core_عدد_u64_rotate_بایاں(x, (uint32_t)21);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 21
- RIGHT= 43
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_54(uint64_t a, uint64_t b)
{
  أرجع libcrux_sha3_simd_portable_rotate_بایاں_54(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 21
- RIGHT= 43
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_54(uint64_t a, uint64_t b)
{
  أرجع libcrux_sha3_simd_portable__vxarq_u64_54(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 56
- RIGHT= 8
*/
ساكن KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_بایاں_4c(uint64_t x)
{
  أرجع core_عدد_u64_rotate_بایاں(x, (uint32_t)56);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 56
- RIGHT= 8
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_4c(uint64_t a, uint64_t b)
{
  أرجع libcrux_sha3_simd_portable_rotate_بایاں_4c(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 56
- RIGHT= 8
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_4c(uint64_t a, uint64_t b)
{
  أرجع libcrux_sha3_simd_portable__vxarq_u64_4c(a, b);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.rho_3_80
with types uint64_t
with const generics
- N= 1
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_generic_keccak_rho_3_80_71(Eurydice_arr_7c *self, Eurydice_arr_84 t)
{
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)0U,
    (ناپ_t)3U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_37(libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
        (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)0U, .snd = (ناپ_t)3U }))[0U],
      t.انکڑے[3U]));
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)1U,
    (ناپ_t)3U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_bb(libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
        (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)1U, .snd = (ناپ_t)3U }))[0U],
      t.انکڑے[3U]));
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)2U,
    (ناپ_t)3U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_b9(libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
        (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)2U, .snd = (ناپ_t)3U }))[0U],
      t.انکڑے[3U]));
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)3U,
    (ناپ_t)3U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_54(libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
        (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)3U, .snd = (ناپ_t)3U }))[0U],
      t.انکڑے[3U]));
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)4U,
    (ناپ_t)3U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_4c(libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
        (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)4U, .snd = (ناپ_t)3U }))[0U],
      t.انکڑے[3U]));
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 27
- RIGHT= 37
*/
ساكن KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_بایاں_ce(uint64_t x)
{
  أرجع core_عدد_u64_rotate_بایاں(x, (uint32_t)27);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 27
- RIGHT= 37
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_ce(uint64_t a, uint64_t b)
{
  أرجع libcrux_sha3_simd_portable_rotate_بایاں_ce(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 27
- RIGHT= 37
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_ce(uint64_t a, uint64_t b)
{
  أرجع libcrux_sha3_simd_portable__vxarq_u64_ce(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 20
- RIGHT= 44
*/
ساكن KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_بایاں_77(uint64_t x)
{
  أرجع core_عدد_u64_rotate_بایاں(x, (uint32_t)20);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 20
- RIGHT= 44
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_77(uint64_t a, uint64_t b)
{
  أرجع libcrux_sha3_simd_portable_rotate_بایاں_77(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 20
- RIGHT= 44
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_77(uint64_t a, uint64_t b)
{
  أرجع libcrux_sha3_simd_portable__vxarq_u64_77(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 39
- RIGHT= 25
*/
ساكن KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_بایاں_25(uint64_t x)
{
  أرجع core_عدد_u64_rotate_بایاں(x, (uint32_t)39);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 39
- RIGHT= 25
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_25(uint64_t a, uint64_t b)
{
  أرجع libcrux_sha3_simd_portable_rotate_بایاں_25(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 39
- RIGHT= 25
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_25(uint64_t a, uint64_t b)
{
  أرجع libcrux_sha3_simd_portable__vxarq_u64_25(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 8
- RIGHT= 56
*/
ساكن KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_بایاں_af(uint64_t x)
{
  أرجع core_عدد_u64_rotate_بایاں(x, (uint32_t)8);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 8
- RIGHT= 56
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_af(uint64_t a, uint64_t b)
{
  أرجع libcrux_sha3_simd_portable_rotate_بایاں_af(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 8
- RIGHT= 56
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_af(uint64_t a, uint64_t b)
{
  أرجع libcrux_sha3_simd_portable__vxarq_u64_af(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 14
- RIGHT= 50
*/
ساكن KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_بایاں_fd(uint64_t x)
{
  أرجع core_عدد_u64_rotate_بایاں(x, (uint32_t)14);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 14
- RIGHT= 50
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_fd(uint64_t a, uint64_t b)
{
  أرجع libcrux_sha3_simd_portable_rotate_بایاں_fd(a ^ b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.xor_and_rotate_d2
with const generics
- LEFT= 14
- RIGHT= 50
*/
ساكن KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_fd(uint64_t a, uint64_t b)
{
  أرجع libcrux_sha3_simd_portable__vxarq_u64_fd(a, b);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.rho_4_80
with types uint64_t
with const generics
- N= 1
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_generic_keccak_rho_4_80_71(Eurydice_arr_7c *self, Eurydice_arr_84 t)
{
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)0U,
    (ناپ_t)4U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_ce(libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
        (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)0U, .snd = (ناپ_t)4U }))[0U],
      t.انکڑے[4U]));
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)1U,
    (ناپ_t)4U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_77(libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
        (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)1U, .snd = (ناپ_t)4U }))[0U],
      t.انکڑے[4U]));
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)2U,
    (ناپ_t)4U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_25(libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
        (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)2U, .snd = (ناپ_t)4U }))[0U],
      t.انکڑے[4U]));
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)3U,
    (ناپ_t)4U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_af(libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
        (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)3U, .snd = (ناپ_t)4U }))[0U],
      t.انکڑے[4U]));
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)4U,
    (ناپ_t)4U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_fd(libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
        (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)4U, .snd = (ناپ_t)4U }))[0U],
      t.انکڑے[4U]));
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.rho_80
with types uint64_t
with const generics
- N= 1
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_generic_keccak_rho_80_71(Eurydice_arr_7c *self, Eurydice_arr_84 t)
{
  libcrux_sha3_generic_keccak_rho_0_80_71(self, t);
  libcrux_sha3_generic_keccak_rho_1_80_71(self, t);
  libcrux_sha3_generic_keccak_rho_2_80_71(self, t);
  libcrux_sha3_generic_keccak_rho_3_80_71(self, t);
  libcrux_sha3_generic_keccak_rho_4_80_71(self, t);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.pi_0_80
with types uint64_t
with const generics
- N= 1
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_generic_keccak_pi_0_80_71(Eurydice_arr_7c *self, Eurydice_arr_7c old)
{
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)1U,
    (ناپ_t)0U,
    libcrux_sha3_generic_keccak_اشاریہ_c2_71(&old,
      (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)0U, .snd = (ناپ_t)3U }))[0U]);
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)2U,
    (ناپ_t)0U,
    libcrux_sha3_generic_keccak_اشاریہ_c2_71(&old,
      (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)0U, .snd = (ناپ_t)1U }))[0U]);
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)3U,
    (ناپ_t)0U,
    libcrux_sha3_generic_keccak_اشاریہ_c2_71(&old,
      (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)0U, .snd = (ناپ_t)4U }))[0U]);
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)4U,
    (ناپ_t)0U,
    libcrux_sha3_generic_keccak_اشاریہ_c2_71(&old,
      (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)0U, .snd = (ناپ_t)2U }))[0U]);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.pi_1_80
with types uint64_t
with const generics
- N= 1
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_generic_keccak_pi_1_80_71(Eurydice_arr_7c *self, Eurydice_arr_7c old)
{
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)0U,
    (ناپ_t)1U,
    libcrux_sha3_generic_keccak_اشاریہ_c2_71(&old,
      (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)1U, .snd = (ناپ_t)1U }))[0U]);
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)1U,
    (ناپ_t)1U,
    libcrux_sha3_generic_keccak_اشاریہ_c2_71(&old,
      (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)1U, .snd = (ناپ_t)4U }))[0U]);
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)2U,
    (ناپ_t)1U,
    libcrux_sha3_generic_keccak_اشاریہ_c2_71(&old,
      (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)1U, .snd = (ناپ_t)2U }))[0U]);
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)3U,
    (ناپ_t)1U,
    libcrux_sha3_generic_keccak_اشاریہ_c2_71(&old,
      (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)1U, .snd = (ناپ_t)0U }))[0U]);
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)4U,
    (ناپ_t)1U,
    libcrux_sha3_generic_keccak_اشاریہ_c2_71(&old,
      (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)1U, .snd = (ناپ_t)3U }))[0U]);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.pi_2_80
with types uint64_t
with const generics
- N= 1
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_generic_keccak_pi_2_80_71(Eurydice_arr_7c *self, Eurydice_arr_7c old)
{
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)0U,
    (ناپ_t)2U,
    libcrux_sha3_generic_keccak_اشاریہ_c2_71(&old,
      (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)2U, .snd = (ناپ_t)2U }))[0U]);
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)1U,
    (ناپ_t)2U,
    libcrux_sha3_generic_keccak_اشاریہ_c2_71(&old,
      (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)2U, .snd = (ناپ_t)0U }))[0U]);
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)2U,
    (ناپ_t)2U,
    libcrux_sha3_generic_keccak_اشاریہ_c2_71(&old,
      (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)2U, .snd = (ناپ_t)3U }))[0U]);
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)3U,
    (ناپ_t)2U,
    libcrux_sha3_generic_keccak_اشاریہ_c2_71(&old,
      (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)2U, .snd = (ناپ_t)1U }))[0U]);
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)4U,
    (ناپ_t)2U,
    libcrux_sha3_generic_keccak_اشاریہ_c2_71(&old,
      (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)2U, .snd = (ناپ_t)4U }))[0U]);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.pi_3_80
with types uint64_t
with const generics
- N= 1
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_generic_keccak_pi_3_80_71(Eurydice_arr_7c *self, Eurydice_arr_7c old)
{
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)0U,
    (ناپ_t)3U,
    libcrux_sha3_generic_keccak_اشاریہ_c2_71(&old,
      (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)3U, .snd = (ناپ_t)3U }))[0U]);
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)1U,
    (ناپ_t)3U,
    libcrux_sha3_generic_keccak_اشاریہ_c2_71(&old,
      (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)3U, .snd = (ناپ_t)1U }))[0U]);
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)2U,
    (ناپ_t)3U,
    libcrux_sha3_generic_keccak_اشاریہ_c2_71(&old,
      (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)3U, .snd = (ناپ_t)4U }))[0U]);
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)3U,
    (ناپ_t)3U,
    libcrux_sha3_generic_keccak_اشاریہ_c2_71(&old,
      (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)3U, .snd = (ناپ_t)2U }))[0U]);
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)4U,
    (ناپ_t)3U,
    libcrux_sha3_generic_keccak_اشاریہ_c2_71(&old,
      (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)3U, .snd = (ناپ_t)0U }))[0U]);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.pi_4_80
with types uint64_t
with const generics
- N= 1
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_generic_keccak_pi_4_80_71(Eurydice_arr_7c *self, Eurydice_arr_7c old)
{
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)0U,
    (ناپ_t)4U,
    libcrux_sha3_generic_keccak_اشاریہ_c2_71(&old,
      (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)4U, .snd = (ناپ_t)4U }))[0U]);
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)1U,
    (ناپ_t)4U,
    libcrux_sha3_generic_keccak_اشاریہ_c2_71(&old,
      (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)4U, .snd = (ناپ_t)2U }))[0U]);
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)2U,
    (ناپ_t)4U,
    libcrux_sha3_generic_keccak_اشاریہ_c2_71(&old,
      (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)4U, .snd = (ناپ_t)0U }))[0U]);
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)3U,
    (ناپ_t)4U,
    libcrux_sha3_generic_keccak_اشاریہ_c2_71(&old,
      (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)4U, .snd = (ناپ_t)3U }))[0U]);
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)4U,
    (ناپ_t)4U,
    libcrux_sha3_generic_keccak_اشاریہ_c2_71(&old,
      (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)4U, .snd = (ناپ_t)1U }))[0U]);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.pi_80
with types uint64_t
with const generics
- N= 1
*/
ساكن KRML_MUSTINLINE فراغ libcrux_sha3_generic_keccak_pi_80_71(Eurydice_arr_7c *self)
{
  Eurydice_arr_7c old = self[0U];
  libcrux_sha3_generic_keccak_pi_0_80_71(self, old);
  libcrux_sha3_generic_keccak_pi_1_80_71(self, old);
  libcrux_sha3_generic_keccak_pi_2_80_71(self, old);
  libcrux_sha3_generic_keccak_pi_3_80_71(self, old);
  libcrux_sha3_generic_keccak_pi_4_80_71(self, old);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.chi_80
with types uint64_t
with const generics
- N= 1
*/
ساكن KRML_MUSTINLINE فراغ libcrux_sha3_generic_keccak_chi_80_71(Eurydice_arr_7c *self)
{
  Eurydice_arr_7c old = self[0U];
  لكل (ناپ_t i0 = (ناپ_t)0U; i0 < (ناپ_t)5U; i0++)
  {
    ناپ_t i1 = i0;
    لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)5U; i++)
    {
      ناپ_t j = i;
      libcrux_sha3_generic_keccak_سیٹ_80_71(self,
        i1,
        j,
        libcrux_sha3_simd_portable_and_not_xor_d2(libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
            (KRML_CLITERAL(ناپ_t_x2){ .fst = i1, .snd = j }))[0U],
          libcrux_sha3_generic_keccak_اشاریہ_c2_71(&old,
            (KRML_CLITERAL(ناپ_t_x2){ .fst = i1, .snd = (j + (ناپ_t)2U) % (ناپ_t)5U }))[0U],
          libcrux_sha3_generic_keccak_اشاریہ_c2_71(&old,
            (KRML_CLITERAL(ناپ_t_x2){ .fst = i1, .snd = (j + (ناپ_t)1U) % (ناپ_t)5U }))[0U]));
    }
  }
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.iota_80
with types uint64_t
with const generics
- N= 1
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_generic_keccak_iota_80_71(Eurydice_arr_7c *self, ناپ_t i)
{
  libcrux_sha3_generic_keccak_سیٹ_80_71(self,
    (ناپ_t)0U,
    (ناپ_t)0U,
    libcrux_sha3_simd_portable_xor_constant_d2(libcrux_sha3_generic_keccak_اشاریہ_c2_71(self,
        (KRML_CLITERAL(ناپ_t_x2){ .fst = (ناپ_t)0U, .snd = (ناپ_t)0U }))[0U],
      LIBCRUX_SHA3_GENERIC_KECCAK_CONSTANTS_ROUNDCONSTANTS.انکڑے[i]));
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.keccakf1600_80
with types uint64_t
with const generics
- N= 1
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_generic_keccak_keccakf1600_80_71(Eurydice_arr_7c *self)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)24U; i++)
  {
    ناپ_t i0 = i;
    Eurydice_arr_84 t = libcrux_sha3_generic_keccak_theta_80_71(self);
    libcrux_sha3_generic_keccak_rho_80_71(self, t);
    libcrux_sha3_generic_keccak_pi_80_71(self);
    libcrux_sha3_generic_keccak_chi_80_71(self);
    libcrux_sha3_generic_keccak_iota_80_71(self, i0);
  }
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.absorb_final_80
with types uint64_t
with const generics
- N= 1
- RATE= 168
- DELIM= 31
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_generic_keccak_absorb_final_80_bd(
  Eurydice_arr_7c *self,
  ثابت Eurydice_arr_dc *داخلہ,
  ناپ_t شروع,
  ناپ_t len
)
{
  libcrux_sha3_simd_portable_لدو_آخری_a1_37(self, داخلہ, شروع, len);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
}

/**
 Absorb
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_portable_incremental_shake128_absorb_final(
  Eurydice_arr_7c *s,
  Eurydice_borrow_ٹکڑا_u8 data0
)
{
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_dc lvalue = { .انکڑے = { data0 } };
  libcrux_sha3_generic_keccak_absorb_final_80_bd(s, &lvalue, (ناپ_t)0U, data0.meta);
}

/**
 Create a new SHAKE-256 state object.
*/
ساكن KRML_MUSTINLINE Eurydice_arr_7c libcrux_sha3_portable_incremental_shake256_init(فراغ)
{
  أرجع libcrux_sha3_generic_keccak_new_80_71();
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_block
with const generics
- RATE= 136
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_simd_portable_لدو_بلاک_b2(
  Eurydice_arr_7c *state,
  Eurydice_borrow_ٹکڑا_u8 بلاکاں,
  ناپ_t شروع
)
{
  Eurydice_arr_7c state_flat = { .انکڑے = { 0U } };
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)136U / (ناپ_t)8U; i++)
  {
    ناپ_t i0 = i;
    ناپ_t وتھ = شروع + (ناپ_t)8U * i0;
    Eurydice_array_u8x8 arr;
    حافظہ_نقل(arr.انکڑے,
      Eurydice_ٹکڑا_subslice_shared_c8(بلاکاں,
        (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = وتھ, .سرا = وتھ + (ناپ_t)8U })).ptr,
      (ناپ_t)8U * حجم (uint8_t));
    Eurydice_array_u8x8
    uu____0 =
      core_نتیجہ_unwrap_26_e0((
          KRML_CLITERAL(core_نتیجہ_نتیجہ_8e){ .ٹیگ = core_نتیجہ_Ok, .val = { .case_Ok = arr } }
        ));
    state_flat.انکڑے[i0] = core_عدد_u64_from_le_بائٹاں(uu____0);
  }
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)136U / (ناپ_t)8U; i++)
  {
    ناپ_t i0 = i;
    libcrux_sha3_traits_سیٹ_ij_71(state,
      i0 / (ناپ_t)5U,
      i0 % (ناپ_t)5U,
      libcrux_sha3_traits_get_ij_71(state, i0 / (ناپ_t)5U, i0 % (ناپ_t)5U)[0U] ^
        state_flat.انکڑے[i0]);
  }
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_last
with const generics
- RATE= 136
- DELIMITER= 31
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_simd_portable_لدو_آخری_22(
  Eurydice_arr_7c *state,
  Eurydice_borrow_ٹکڑا_u8 بلاکاں,
  ناپ_t شروع,
  ناپ_t len
)
{
  Eurydice_arr_ff بفر = { .انکڑے = { 0U } };
  Eurydice_ٹکڑا_copy(Eurydice_array_منزل_subslice_mut_d42(&بفر,
      (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = (ناپ_t)0U, .سرا = len })),
    Eurydice_ٹکڑا_subslice_shared_c8(بلاکاں,
      (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = شروع, .سرا = شروع + len })),
    uint8_t);
  بفر.انکڑے[len] = 31U;
  ناپ_t uu____0 = (ناپ_t)136U - (ناپ_t)1U;
  بفر.انکڑے[uu____0] = (uint32_t)بفر.انکڑے[uu____0] | 128U;
  libcrux_sha3_simd_portable_لدو_بلاک_b2(state,
    Eurydice_array_منزل_ٹکڑا_shared_58(&بفر),
    (ناپ_t)0U);
}

/**
This function found in impl {libcrux_sha3::traits::Absorb<1usize> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.load_last_a1
with const generics
- RATE= 136
- DELIMITER= 31
*/
ساكن مضمن فراغ
libcrux_sha3_simd_portable_لدو_آخری_a1_22(
  Eurydice_arr_7c *self,
  ثابت Eurydice_arr_dc *داخلہ,
  ناپ_t شروع,
  ناپ_t len
)
{
  libcrux_sha3_simd_portable_لدو_آخری_22(self, داخلہ->انکڑے[0U], شروع, len);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.absorb_final_80
with types uint64_t
with const generics
- N= 1
- RATE= 136
- DELIM= 31
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_generic_keccak_absorb_final_80_bd0(
  Eurydice_arr_7c *self,
  ثابت Eurydice_arr_dc *داخلہ,
  ناپ_t شروع,
  ناپ_t len
)
{
  libcrux_sha3_simd_portable_لدو_آخری_a1_22(self, داخلہ, شروع, len);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
}

/**
 Absorb some data for SHAKE-256 for the last time
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_portable_incremental_shake256_absorb_final(
  Eurydice_arr_7c *s,
  Eurydice_borrow_ٹکڑا_u8 انکڑے
)
{
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_dc lvalue = { .انکڑے = { انکڑے } };
  libcrux_sha3_generic_keccak_absorb_final_80_bd0(s, &lvalue, (ناپ_t)0U, انکڑے.meta);
}

/**
This function found in impl {libcrux_sha3::traits::Absorb<1usize> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.load_block_a1
with const generics
- RATE= 168
*/
ساكن مضمن فراغ
libcrux_sha3_simd_portable_لدو_بلاک_a1_60(
  Eurydice_arr_7c *self,
  ثابت Eurydice_arr_dc *داخلہ,
  ناپ_t شروع
)
{
  libcrux_sha3_simd_portable_لدو_بلاک_60(self, داخلہ->انکڑے[0U], شروع);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.absorb_block_80
with types uint64_t
with const generics
- N= 1
- RATE= 168
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_generic_keccak_absorb_بلاک_80_e9(
  Eurydice_arr_7c *self,
  ثابت Eurydice_arr_dc *داخلہ,
  ناپ_t شروع
)
{
  libcrux_sha3_simd_portable_لدو_بلاک_a1_60(self, داخلہ, شروع);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.store_block
with const generics
- RATE= 168
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_simd_portable_store_بلاک_60(
  ثابت Eurydice_arr_7c *s,
  Eurydice_mut_borrow_ٹکڑا_u8 باہرلا,
  ناپ_t شروع,
  ناپ_t len
)
{
  ناپ_t octets = len / (ناپ_t)8U;
  لكل (ناپ_t i = (ناپ_t)0U; i < octets; i++)
  {
    ناپ_t i0 = i;
    Eurydice_array_u8x8
    بائٹاں =
      core_عدد_u64_منزل_le_بائٹاں(libcrux_sha3_traits_get_ij_71(s,
          i0 / (ناپ_t)5U,
          i0 % (ناپ_t)5U)[0U]);
    ناپ_t باہرلا_pos = شروع + (ناپ_t)8U * i0;
    Eurydice_ٹکڑا_copy(Eurydice_ٹکڑا_subslice_mut_c8(باہرلا,
        (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = باہرلا_pos, .سرا = باہرلا_pos + (ناپ_t)8U })),
      Eurydice_array_منزل_ٹکڑا_shared_6e(&بائٹاں),
      uint8_t);
  }
  ناپ_t بچیا = len % (ناپ_t)8U;
  إذا (بچیا > (ناپ_t)0U)
  {
    Eurydice_array_u8x8
    بائٹاں =
      core_عدد_u64_منزل_le_بائٹاں(libcrux_sha3_traits_get_ij_71(s,
          octets / (ناپ_t)5U,
          octets % (ناپ_t)5U)[0U]);
    ناپ_t باہرلا_pos = شروع + len - بچیا;
    Eurydice_mut_borrow_ٹکڑا_u8
    uu____0 =
      Eurydice_ٹکڑا_subslice_mut_c8(باہرلا,
        (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = باہرلا_pos, .سرا = باہرلا_pos + بچیا }));
    Eurydice_ٹکڑا_copy(uu____0,
      Eurydice_array_منزل_subslice_منزل_shared_21(&بائٹاں, بچیا),
      uint8_t);
  }
}

/**
This function found in impl {libcrux_sha3::traits::Squeeze<u64> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.squeeze_9b
with const generics
- RATE= 168
*/
ساكن مضمن فراغ
libcrux_sha3_simd_portable_squeeze_9b_60(
  ثابت Eurydice_arr_7c *self,
  Eurydice_mut_borrow_ٹکڑا_u8 باہرلا,
  ناپ_t شروع,
  ناپ_t len
)
{
  libcrux_sha3_simd_portable_store_بلاک_60(self, باہرلا, شروع, len);
}

/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.keccak1
with const generics
- RATE= 168
- DELIM= 31
*/
ساكن مضمن فراغ
libcrux_sha3_generic_keccak_portable_keccak1_37(
  Eurydice_borrow_ٹکڑا_u8 داخلہ,
  Eurydice_mut_borrow_ٹکڑا_u8 output
)
{
  Eurydice_arr_7c s = libcrux_sha3_generic_keccak_new_80_71();
  ناپ_t داخلہ_len = داخلہ.meta;
  ناپ_t داخلہ_بلاکاں = داخلہ_len / (ناپ_t)168U;
  ناپ_t داخلہ_rem = داخلہ_len % (ناپ_t)168U;
  لكل (ناپ_t i = (ناپ_t)0U; i < داخلہ_بلاکاں; i++)
  {
    ناپ_t i0 = i;
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_dc lvalue = { .انکڑے = { داخلہ } };
    libcrux_sha3_generic_keccak_absorb_بلاک_80_e9(&s, &lvalue, i0 * (ناپ_t)168U);
  }
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_dc lvalue = { .انکڑے = { داخلہ } };
  libcrux_sha3_generic_keccak_absorb_final_80_bd(&s, &lvalue, داخلہ_len - داخلہ_rem, داخلہ_rem);
  ناپ_t output_len = output.meta;
  ناپ_t output_بلاکاں = output_len / (ناپ_t)168U;
  ناپ_t output_rem = output_len % (ناپ_t)168U;
  إذا (output_بلاکاں == (ناپ_t)0U)
  {
    libcrux_sha3_simd_portable_squeeze_9b_60(&s, output, (ناپ_t)0U, output_len);
  }
  وإلا
  {
    libcrux_sha3_simd_portable_squeeze_9b_60(&s, output, (ناپ_t)0U, (ناپ_t)168U);
    لكل (ناپ_t i = (ناپ_t)1U; i < output_بلاکاں; i++)
    {
      ناپ_t i0 = i;
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&s);
      libcrux_sha3_simd_portable_squeeze_9b_60(&s, output, i0 * (ناپ_t)168U, (ناپ_t)168U);
    }
    إذا (output_rem != (ناپ_t)0U)
    {
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&s);
      libcrux_sha3_simd_portable_squeeze_9b_60(&s, output, output_len - output_rem, output_rem);
    }
  }
}

/**
 A portable SHAKE128 implementation.
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_portable_shake128(
  Eurydice_mut_borrow_ٹکڑا_u8 digest,
  Eurydice_borrow_ٹکڑا_u8 انکڑے
)
{
  libcrux_sha3_generic_keccak_portable_keccak1_37(انکڑے, digest);
}

/**
This function found in impl {libcrux_sha3::traits::Absorb<1usize> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.load_block_a1
with const generics
- RATE= 136
*/
ساكن مضمن فراغ
libcrux_sha3_simd_portable_لدو_بلاک_a1_b2(
  Eurydice_arr_7c *self,
  ثابت Eurydice_arr_dc *داخلہ,
  ناپ_t شروع
)
{
  libcrux_sha3_simd_portable_لدو_بلاک_b2(self, داخلہ->انکڑے[0U], شروع);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.absorb_block_80
with types uint64_t
with const generics
- N= 1
- RATE= 136
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_generic_keccak_absorb_بلاک_80_e90(
  Eurydice_arr_7c *self,
  ثابت Eurydice_arr_dc *داخلہ,
  ناپ_t شروع
)
{
  libcrux_sha3_simd_portable_لدو_بلاک_a1_b2(self, داخلہ, شروع);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.store_block
with const generics
- RATE= 136
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_simd_portable_store_بلاک_b2(
  ثابت Eurydice_arr_7c *s,
  Eurydice_mut_borrow_ٹکڑا_u8 باہرلا,
  ناپ_t شروع,
  ناپ_t len
)
{
  ناپ_t octets = len / (ناپ_t)8U;
  لكل (ناپ_t i = (ناپ_t)0U; i < octets; i++)
  {
    ناپ_t i0 = i;
    Eurydice_array_u8x8
    بائٹاں =
      core_عدد_u64_منزل_le_بائٹاں(libcrux_sha3_traits_get_ij_71(s,
          i0 / (ناپ_t)5U,
          i0 % (ناپ_t)5U)[0U]);
    ناپ_t باہرلا_pos = شروع + (ناپ_t)8U * i0;
    Eurydice_ٹکڑا_copy(Eurydice_ٹکڑا_subslice_mut_c8(باہرلا,
        (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = باہرلا_pos, .سرا = باہرلا_pos + (ناپ_t)8U })),
      Eurydice_array_منزل_ٹکڑا_shared_6e(&بائٹاں),
      uint8_t);
  }
  ناپ_t بچیا = len % (ناپ_t)8U;
  إذا (بچیا > (ناپ_t)0U)
  {
    Eurydice_array_u8x8
    بائٹاں =
      core_عدد_u64_منزل_le_بائٹاں(libcrux_sha3_traits_get_ij_71(s,
          octets / (ناپ_t)5U,
          octets % (ناپ_t)5U)[0U]);
    ناپ_t باہرلا_pos = شروع + len - بچیا;
    Eurydice_mut_borrow_ٹکڑا_u8
    uu____0 =
      Eurydice_ٹکڑا_subslice_mut_c8(باہرلا,
        (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = باہرلا_pos, .سرا = باہرلا_pos + بچیا }));
    Eurydice_ٹکڑا_copy(uu____0,
      Eurydice_array_منزل_subslice_منزل_shared_21(&بائٹاں, بچیا),
      uint8_t);
  }
}

/**
This function found in impl {libcrux_sha3::traits::Squeeze<u64> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.squeeze_9b
with const generics
- RATE= 136
*/
ساكن مضمن فراغ
libcrux_sha3_simd_portable_squeeze_9b_b2(
  ثابت Eurydice_arr_7c *self,
  Eurydice_mut_borrow_ٹکڑا_u8 باہرلا,
  ناپ_t شروع,
  ناپ_t len
)
{
  libcrux_sha3_simd_portable_store_بلاک_b2(self, باہرلا, شروع, len);
}

/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.keccak1
with const generics
- RATE= 136
- DELIM= 31
*/
ساكن مضمن فراغ
libcrux_sha3_generic_keccak_portable_keccak1_22(
  Eurydice_borrow_ٹکڑا_u8 داخلہ,
  Eurydice_mut_borrow_ٹکڑا_u8 output
)
{
  Eurydice_arr_7c s = libcrux_sha3_generic_keccak_new_80_71();
  ناپ_t داخلہ_len = داخلہ.meta;
  ناپ_t داخلہ_بلاکاں = داخلہ_len / (ناپ_t)136U;
  ناپ_t داخلہ_rem = داخلہ_len % (ناپ_t)136U;
  لكل (ناپ_t i = (ناپ_t)0U; i < داخلہ_بلاکاں; i++)
  {
    ناپ_t i0 = i;
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_dc lvalue = { .انکڑے = { داخلہ } };
    libcrux_sha3_generic_keccak_absorb_بلاک_80_e90(&s, &lvalue, i0 * (ناپ_t)136U);
  }
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_dc lvalue = { .انکڑے = { داخلہ } };
  libcrux_sha3_generic_keccak_absorb_final_80_bd0(&s, &lvalue, داخلہ_len - داخلہ_rem, داخلہ_rem);
  ناپ_t output_len = output.meta;
  ناپ_t output_بلاکاں = output_len / (ناپ_t)136U;
  ناپ_t output_rem = output_len % (ناپ_t)136U;
  إذا (output_بلاکاں == (ناپ_t)0U)
  {
    libcrux_sha3_simd_portable_squeeze_9b_b2(&s, output, (ناپ_t)0U, output_len);
  }
  وإلا
  {
    libcrux_sha3_simd_portable_squeeze_9b_b2(&s, output, (ناپ_t)0U, (ناپ_t)136U);
    لكل (ناپ_t i = (ناپ_t)1U; i < output_بلاکاں; i++)
    {
      ناپ_t i0 = i;
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&s);
      libcrux_sha3_simd_portable_squeeze_9b_b2(&s, output, i0 * (ناپ_t)136U, (ناپ_t)136U);
    }
    إذا (output_rem != (ناپ_t)0U)
    {
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&s);
      libcrux_sha3_simd_portable_squeeze_9b_b2(&s, output, output_len - output_rem, output_rem);
    }
  }
}

/**
 A portable SHAKE256 implementation.
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_portable_shake256(
  Eurydice_mut_borrow_ٹکڑا_u8 digest,
  Eurydice_borrow_ٹکڑا_u8 انکڑے
)
{
  libcrux_sha3_generic_keccak_portable_keccak1_22(انکڑے, digest);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.squeeze_first_block_b4
with const generics
- RATE= 136
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_generic_keccak_portable_squeeze_پہلا_بلاک_b4_b2(
  ثابت Eurydice_arr_7c *self,
  Eurydice_mut_borrow_ٹکڑا_u8 باہرلا
)
{
  libcrux_sha3_simd_portable_squeeze_9b_b2(self, باہرلا, (ناپ_t)0U, (ناپ_t)136U);
}

/**
 Squeeze the first SHAKE-256 block
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_portable_incremental_shake256_squeeze_پہلا_بلاک(
  Eurydice_arr_7c *s,
  Eurydice_mut_borrow_ٹکڑا_u8 باہرلا
)
{
  libcrux_sha3_generic_keccak_portable_squeeze_پہلا_بلاک_b4_b2(&s[0U], باہرلا);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.squeeze_first_five_blocks_b4
with const generics
- RATE= 168
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_generic_keccak_portable_squeeze_پہلا_five_بلاکاں_b4_60(
  Eurydice_arr_7c *self,
  Eurydice_mut_borrow_ٹکڑا_u8 باہرلا
)
{
  libcrux_sha3_simd_portable_squeeze_9b_60(self, باہرلا, (ناپ_t)0U, (ناپ_t)168U);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
  libcrux_sha3_simd_portable_squeeze_9b_60(self, باہرلا, (ناپ_t)168U, (ناپ_t)168U);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
  libcrux_sha3_simd_portable_squeeze_9b_60(self, باہرلا, (ناپ_t)2U * (ناپ_t)168U, (ناپ_t)168U);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
  libcrux_sha3_simd_portable_squeeze_9b_60(self, باہرلا, (ناپ_t)3U * (ناپ_t)168U, (ناپ_t)168U);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
  libcrux_sha3_simd_portable_squeeze_9b_60(self, باہرلا, (ناپ_t)4U * (ناپ_t)168U, (ناپ_t)168U);
}

/**
 Squeeze five blocks
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_portable_incremental_shake128_squeeze_پہلا_five_بلاکاں(
  Eurydice_arr_7c *s,
  Eurydice_mut_borrow_ٹکڑا_u8 out0
)
{
  libcrux_sha3_generic_keccak_portable_squeeze_پہلا_five_بلاکاں_b4_60(s, out0);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.squeeze_next_block_b4
with const generics
- RATE= 168
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_generic_keccak_portable_squeeze_اگلا_بلاک_b4_60(
  Eurydice_arr_7c *self,
  Eurydice_mut_borrow_ٹکڑا_u8 باہرلا,
  ناپ_t شروع
)
{
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
  libcrux_sha3_simd_portable_squeeze_9b_60(self, باہرلا, شروع, (ناپ_t)168U);
}

/**
 Squeeze another block
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_portable_incremental_shake128_squeeze_اگلا_بلاک(
  Eurydice_arr_7c *s,
  Eurydice_mut_borrow_ٹکڑا_u8 out0
)
{
  libcrux_sha3_generic_keccak_portable_squeeze_اگلا_بلاک_b4_60(s, out0, (ناپ_t)0U);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.squeeze_next_block_b4
with const generics
- RATE= 136
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_generic_keccak_portable_squeeze_اگلا_بلاک_b4_b2(
  Eurydice_arr_7c *self,
  Eurydice_mut_borrow_ٹکڑا_u8 باہرلا,
  ناپ_t شروع
)
{
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
  libcrux_sha3_simd_portable_squeeze_9b_b2(self, باہرلا, شروع, (ناپ_t)136U);
}

/**
 Squeeze the next SHAKE-256 block
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_portable_incremental_shake256_squeeze_اگلا_بلاک(
  Eurydice_arr_7c *s,
  Eurydice_mut_borrow_ٹکڑا_u8 باہرلا
)
{
  libcrux_sha3_generic_keccak_portable_squeeze_اگلا_بلاک_b4_b2(s, باہرلا, (ناپ_t)0U);
}

/**
 Try to complete the internal partial buffer by consuming the minimum required
 number of bytes from the provided `inputs` so that `self.buf` becomes exactly
 one full block of size `RATE`.

 Behaviour:
 - If `self.buf_len` is 0 (no buffered bytes) or already equal to `RATE`
   (already a full block), or if the combined available bytes in `inputs` are
   not enough to reach `RATE`, the function does nothing and returns 0.
 - If `0 < self.buf_len < RATE` and `inputs[..]` contain at least
   `RATE - self.buf_len` bytes, the function copies exactly
   `consumed = RATE - self.buf_len` bytes from each lane `inputs[i]` into
   `self.buf[i]` starting at the current `self.buf_len` offset, sets
   `self.buf_len = RATE`, and returns `consumed`.

 Returns the `consumed` bytes from `inputs` if there's enough buffered
 content to consume, and `0` otherwise.
 If `consumed > 0` is returned, `self.buf` contains a full block to be
 loaded.
*/
/**
This function found in impl {libcrux_sha3::generic_keccak::xof::KeccakXofState<STATE, PARALLEL_LANES, RATE>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.fill_buffer_35
with types uint64_t
with const generics
- PARALLEL_LANES= 1
- RATE= 136
*/
ساكن مضمن ناپ_t
libcrux_sha3_generic_keccak_xof_fill_بفر_35_e9(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *self,
  ثابت Eurydice_arr_dc *inputs
)
{
  ناپ_t داخلہ_len = inputs->انکڑے->meta;
  ناپ_t uu____0;
  إذا (self->buf_len != (ناپ_t)0U)
  {
    إذا (داخلہ_len >= (ناپ_t)136U - self->buf_len)
    {
      ناپ_t consumed = (ناپ_t)136U - self->buf_len;
      لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)1U; i++)
      {
        ناپ_t i0 = i;
        Eurydice_ٹکڑا_copy(Eurydice_array_منزل_subslice_from_mut_5f(&self->buf.انکڑے[i0],
            self->buf_len),
          Eurydice_ٹکڑا_subslice_منزل_shared_72(inputs->انکڑے[i0], consumed),
          uint8_t);
      }
      self->buf_len = (ناپ_t)136U;
      uu____0 = consumed;
    }
    وإلا
    {
      uu____0 = (ناپ_t)0U;
    }
  }
  وإلا
  {
    uu____0 = (ناپ_t)0U;
  }
  أرجع uu____0;
}

/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.buf_to_slices.closure
with const generics
- $1size_t
- $136size_t
*/
تعريفنوع ثابت Eurydice_arr_0b *libcrux_sha3_generic_keccak_xof_buf_منزل_slices_گھیرا_94;

/**
This function found in impl {core::ops::function::FnMut<(usize), &'_ ([u8])> for libcrux_sha3::generic_keccak::xof::buf_to_slices::closure<0, PARALLEL_LANES, RATE>}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.buf_to_slices.call_mut_2a
with const generics
- PARALLEL_LANES= 1
- RATE= 136
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
libcrux_sha3_generic_keccak_xof_buf_منزل_slices_call_mut_2a_81(
  ثابت Eurydice_arr_0b **_,
  ناپ_t tupled_دلیلاں
)
{
  ناپ_t i = tupled_دلیلاں;
  أرجع
    core_array_T_N_as_ٹکڑا((ناپ_t)136U,
      &_[0U]->انکڑے[i],
      uint8_t,
      Eurydice_borrow_ٹکڑا_u8);
}

/**
This function found in impl {core::ops::function::FnOnce<(usize), &'_ ([u8])> for libcrux_sha3::generic_keccak::xof::buf_to_slices::closure<0, PARALLEL_LANES, RATE>}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.buf_to_slices.call_once_fa
with const generics
- PARALLEL_LANES= 1
- RATE= 136
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
libcrux_sha3_generic_keccak_xof_buf_منزل_slices_call_once_fa_81(
  ثابت Eurydice_arr_0b *_,
  ناپ_t _0
)
{
  أرجع libcrux_sha3_generic_keccak_xof_buf_منزل_slices_call_mut_2a_81(&_, _0);
}

/**
 Note: This function exists to work around a hax bug where `core::array::from_fn`
 is extracted with an incorrect explicit type parameter `#(usize -> t_Slice u8)`
 instead of using the typeclass-based implicit parameter `#v_F` from
 `Core_models.Array.from_fn`.
 See: https://github.com/cryspen/hax/issues/1920
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.buf_to_slices
with const generics
- PARALLEL_LANES= 1
- RATE= 136
*/
ساكن KRML_MUSTINLINE Eurydice_arr_dc
libcrux_sha3_generic_keccak_xof_buf_منزل_slices_81(ثابت Eurydice_arr_0b *buf)
{
  Eurydice_arr_dc arr_struct;
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)1U; i++)
  {
    arr_struct.انکڑے[i] = libcrux_sha3_generic_keccak_xof_buf_منزل_slices_call_mut_2a_81(&buf, i);
  }
  أرجع arr_struct;
}

/**
This function found in impl {libcrux_sha3::generic_keccak::xof::KeccakXofState<STATE, PARALLEL_LANES, RATE>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.absorb_full_35
with types uint64_t
with const generics
- PARALLEL_LANES= 1
- RATE= 136
*/
ساكن مضمن ناپ_t
libcrux_sha3_generic_keccak_xof_absorb_بھریا_35_e9(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *self,
  ثابت Eurydice_arr_dc *inputs
)
{
  ناپ_t consumed = libcrux_sha3_generic_keccak_xof_fill_بفر_35_e9(self, inputs);
  إذا (self->buf_len == (ناپ_t)136U)
  {
    Eurydice_arr_dc borrowed = libcrux_sha3_generic_keccak_xof_buf_منزل_slices_81(&self->buf);
    libcrux_sha3_simd_portable_لدو_بلاک_a1_b2(&self->inner, &borrowed, (ناپ_t)0U);
    libcrux_sha3_generic_keccak_keccakf1600_80_71(&self->inner);
    self->buf_len = (ناپ_t)0U;
  }
  ناپ_t داخلہ_منزل_consume = inputs->انکڑے->meta - consumed;
  ناپ_t عدد_بلاکاں = داخلہ_منزل_consume / (ناپ_t)136U;
  ناپ_t remainder = داخلہ_منزل_consume % (ناپ_t)136U;
  لكل (ناپ_t i = (ناپ_t)0U; i < عدد_بلاکاں; i++)
  {
    ناپ_t i0 = i;
    ناپ_t شروع = i0 * (ناپ_t)136U + consumed;
    libcrux_sha3_simd_portable_لدو_بلاک_a1_b2(&self->inner, inputs, شروع);
    libcrux_sha3_generic_keccak_keccakf1600_80_71(&self->inner);
  }
  أرجع remainder;
}

/**
 Absorb

 This function takes any number of bytes to absorb and buffers if it's not enough.
 The function assumes that all input slices in `inputs` have the same length.

 Only a multiple of `RATE` blocks are absorbed.
 For the remaining bytes [`absorb_final`] needs to be called.

 This works best with relatively small `inputs`.
*/
/**
This function found in impl {libcrux_sha3::generic_keccak::xof::KeccakXofState<STATE, PARALLEL_LANES, RATE>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.absorb_35
with types uint64_t
with const generics
- PARALLEL_LANES= 1
- RATE= 136
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_generic_keccak_xof_absorb_35_e9(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *self,
  ثابت Eurydice_arr_dc *inputs
)
{
  ناپ_t remainder = libcrux_sha3_generic_keccak_xof_absorb_بھریا_35_e9(self, inputs);
  إذا (remainder > (ناپ_t)0U)
  {
    ناپ_t داخلہ_len = inputs->انکڑے->meta;
    لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)1U; i++)
    {
      ناپ_t i0 = i;
      Eurydice_ٹکڑا_copy(Eurydice_array_منزل_subslice_mut_d42(&self->buf.انکڑے[i0],
          (
            KRML_CLITERAL(core_ops_range_Range_87){
              .شروع = self->buf_len,
              .سرا = self->buf_len + remainder
            }
          )),
        Eurydice_ٹکڑا_subslice_shared_c8(inputs->انکڑے[i0],
          (
            KRML_CLITERAL(core_ops_range_Range_87){
              .شروع = داخلہ_len - remainder,
              .سرا = داخلہ_len
            }
          )),
        uint8_t);
    }
    self->buf_len += remainder;
  }
}

/**
 Shake256 absorb
*/
/**
This function found in impl {libcrux_sha3::portable::incremental::Xof<136usize> for libcrux_sha3::portable::incremental::Shake256Xof}
*/
ساكن مضمن فراغ
libcrux_sha3_portable_incremental_absorb_42(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *self,
  Eurydice_borrow_ٹکڑا_u8 داخلہ
)
{
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_dc lvalue = { .انکڑے = { داخلہ } };
  libcrux_sha3_generic_keccak_xof_absorb_35_e9(self, &lvalue);
}

/**
 Absorb a final block.

 The `inputs` block may be empty. Everything in the `inputs` block beyond
 `RATE` bytes is ignored.
*/
/**
This function found in impl {libcrux_sha3::generic_keccak::xof::KeccakXofState<STATE, PARALLEL_LANES, RATE>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.absorb_final_35
with types uint64_t
with const generics
- PARALLEL_LANES= 1
- RATE= 136
- DELIMITER= 31
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_generic_keccak_xof_absorb_final_35_bd(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *self,
  ثابت Eurydice_arr_dc *inputs
)
{
  libcrux_sha3_generic_keccak_xof_absorb_35_e9(self, inputs);
  Eurydice_arr_dc borrowed = libcrux_sha3_generic_keccak_xof_buf_منزل_slices_81(&self->buf);
  libcrux_sha3_simd_portable_لدو_آخری_a1_22(&self->inner, &borrowed, (ناپ_t)0U, self->buf_len);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(&self->inner);
}

/**
 Shake256 absorb final
*/
/**
This function found in impl {libcrux_sha3::portable::incremental::Xof<136usize> for libcrux_sha3::portable::incremental::Shake256Xof}
*/
ساكن مضمن فراغ
libcrux_sha3_portable_incremental_absorb_final_42(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *self,
  Eurydice_borrow_ٹکڑا_u8 داخلہ
)
{
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_dc lvalue = { .انکڑے = { داخلہ } };
  libcrux_sha3_generic_keccak_xof_absorb_final_35_bd(self, &lvalue);
}

/**
 An all zero block
*/
/**
This function found in impl {libcrux_sha3::generic_keccak::xof::KeccakXofState<STATE, PARALLEL_LANES, RATE>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.zero_block_35
with types uint64_t
with const generics
- PARALLEL_LANES= 1
- RATE= 136
*/
ساكن مضمن Eurydice_arr_ff libcrux_sha3_generic_keccak_xof_zero_بلاک_35_e9(فراغ)
{
  أرجع (KRML_CLITERAL(Eurydice_arr_ff){ .انکڑے = { 0U } });
}

/**
 Generate a new keccak xof state.
*/
/**
This function found in impl {libcrux_sha3::generic_keccak::xof::KeccakXofState<STATE, PARALLEL_LANES, RATE>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.new_35
with types uint64_t
with const generics
- PARALLEL_LANES= 1
- RATE= 136
*/
ساكن مضمن libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
libcrux_sha3_generic_keccak_xof_new_35_e9(فراغ)
{
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d lit;
  lit.inner = libcrux_sha3_generic_keccak_new_80_71();
  Eurydice_arr_ff repeat_عبارت[1U];
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)1U; i++)
  {
    repeat_عبارت[i] = libcrux_sha3_generic_keccak_xof_zero_بلاک_35_e9();
  }
  حافظہ_نقل(lit.buf.انکڑے, repeat_عبارت, (ناپ_t)1U * حجم (Eurydice_arr_ff));
  lit.buf_len = (ناپ_t)0U;
  lit.sponge = false;
  أرجع lit;
}

/**
 Shake256 new state
*/
/**
This function found in impl {libcrux_sha3::portable::incremental::Xof<136usize> for libcrux_sha3::portable::incremental::Shake256Xof}
*/
ساكن مضمن libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
libcrux_sha3_portable_incremental_new_42(فراغ)
{
  أرجع libcrux_sha3_generic_keccak_xof_new_35_e9();
}

/**
 Squeeze `N` x `LEN` bytes. Only `N = 1` for now.
*/
/**
This function found in impl {libcrux_sha3::generic_keccak::xof::KeccakXofState<STATE, 1usize, RATE>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.squeeze_85
with types uint64_t
with const generics
- RATE= 136
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_generic_keccak_xof_squeeze_85_76(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *self,
  Eurydice_mut_borrow_ٹکڑا_u8 باہرلا
)
{
  ناپ_t باہرلا_len = باہرلا.meta;
  إذا (!(باہرلا_len == (ناپ_t)0U))
  {
    إذا (self->sponge)
    {
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&self->inner);
    }
    إذا (باہرلا_len > (ناپ_t)0U)
    {
      ناپ_t بلاکاں = باہرلا_len / (ناپ_t)136U;
      ناپ_t آخری = باہرلا_len - باہرلا_len % (ناپ_t)136U;
      إذا (بلاکاں == (ناپ_t)0U)
      {
        libcrux_sha3_simd_portable_squeeze_9b_b2(&self->inner, باہرلا, (ناپ_t)0U, باہرلا_len);
      }
      وإلا
      {
        libcrux_sha3_simd_portable_squeeze_9b_b2(&self->inner, باہرلا, (ناپ_t)0U, (ناپ_t)136U);
        لكل (ناپ_t i = (ناپ_t)1U; i < بلاکاں; i++)
        {
          ناپ_t i0 = i;
          libcrux_sha3_generic_keccak_keccakf1600_80_71(&self->inner);
          libcrux_sha3_simd_portable_squeeze_9b_b2(&self->inner,
            باہرلا,
            i0 * (ناپ_t)136U,
            (ناپ_t)136U);
        }
        إذا (آخری < باہرلا_len)
        {
          libcrux_sha3_generic_keccak_keccakf1600_80_71(&self->inner);
          libcrux_sha3_simd_portable_squeeze_9b_b2(&self->inner, باہرلا, آخری, باہرلا_len - آخری);
        }
      }
    }
    self->sponge = true;
  }
}

/**
 Shake256 squeeze
*/
/**
This function found in impl {libcrux_sha3::portable::incremental::Xof<136usize> for libcrux_sha3::portable::incremental::Shake256Xof}
*/
ساكن مضمن فراغ
libcrux_sha3_portable_incremental_squeeze_42(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *self,
  Eurydice_mut_borrow_ٹکڑا_u8 باہرلا
)
{
  libcrux_sha3_generic_keccak_xof_squeeze_85_76(self, باہرلا);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_block
with const generics
- RATE= 72
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_simd_portable_لدو_بلاک_c6(
  Eurydice_arr_7c *state,
  Eurydice_borrow_ٹکڑا_u8 بلاکاں,
  ناپ_t شروع
)
{
  Eurydice_arr_7c state_flat = { .انکڑے = { 0U } };
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)72U / (ناپ_t)8U; i++)
  {
    ناپ_t i0 = i;
    ناپ_t وتھ = شروع + (ناپ_t)8U * i0;
    Eurydice_array_u8x8 arr;
    حافظہ_نقل(arr.انکڑے,
      Eurydice_ٹکڑا_subslice_shared_c8(بلاکاں,
        (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = وتھ, .سرا = وتھ + (ناپ_t)8U })).ptr,
      (ناپ_t)8U * حجم (uint8_t));
    Eurydice_array_u8x8
    uu____0 =
      core_نتیجہ_unwrap_26_e0((
          KRML_CLITERAL(core_نتیجہ_نتیجہ_8e){ .ٹیگ = core_نتیجہ_Ok, .val = { .case_Ok = arr } }
        ));
    state_flat.انکڑے[i0] = core_عدد_u64_from_le_بائٹاں(uu____0);
  }
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)72U / (ناپ_t)8U; i++)
  {
    ناپ_t i0 = i;
    libcrux_sha3_traits_سیٹ_ij_71(state,
      i0 / (ناپ_t)5U,
      i0 % (ناپ_t)5U,
      libcrux_sha3_traits_get_ij_71(state, i0 / (ناپ_t)5U, i0 % (ناپ_t)5U)[0U] ^
        state_flat.انکڑے[i0]);
  }
}

/**
This function found in impl {libcrux_sha3::traits::Absorb<1usize> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.load_block_a1
with const generics
- RATE= 72
*/
ساكن مضمن فراغ
libcrux_sha3_simd_portable_لدو_بلاک_a1_c6(
  Eurydice_arr_7c *self,
  ثابت Eurydice_arr_dc *داخلہ,
  ناپ_t شروع
)
{
  libcrux_sha3_simd_portable_لدو_بلاک_c6(self, داخلہ->انکڑے[0U], شروع);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.absorb_block_80
with types uint64_t
with const generics
- N= 1
- RATE= 72
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_generic_keccak_absorb_بلاک_80_e91(
  Eurydice_arr_7c *self,
  ثابت Eurydice_arr_dc *داخلہ,
  ناپ_t شروع
)
{
  libcrux_sha3_simd_portable_لدو_بلاک_a1_c6(self, داخلہ, شروع);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_last
with const generics
- RATE= 72
- DELIMITER= 6
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_simd_portable_لدو_آخری_dc(
  Eurydice_arr_7c *state,
  Eurydice_borrow_ٹکڑا_u8 بلاکاں,
  ناپ_t شروع,
  ناپ_t len
)
{
  Eurydice_arr_ab بفر = { .انکڑے = { 0U } };
  Eurydice_ٹکڑا_copy(Eurydice_array_منزل_subslice_mut_d43(&بفر,
      (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = (ناپ_t)0U, .سرا = len })),
    Eurydice_ٹکڑا_subslice_shared_c8(بلاکاں,
      (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = شروع, .سرا = شروع + len })),
    uint8_t);
  بفر.انکڑے[len] = 6U;
  ناپ_t uu____0 = (ناپ_t)72U - (ناپ_t)1U;
  بفر.انکڑے[uu____0] = (uint32_t)بفر.انکڑے[uu____0] | 128U;
  libcrux_sha3_simd_portable_لدو_بلاک_c6(state,
    Eurydice_array_منزل_ٹکڑا_shared_e2(&بفر),
    (ناپ_t)0U);
}

/**
This function found in impl {libcrux_sha3::traits::Absorb<1usize> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.load_last_a1
with const generics
- RATE= 72
- DELIMITER= 6
*/
ساكن مضمن فراغ
libcrux_sha3_simd_portable_لدو_آخری_a1_dc(
  Eurydice_arr_7c *self,
  ثابت Eurydice_arr_dc *داخلہ,
  ناپ_t شروع,
  ناپ_t len
)
{
  libcrux_sha3_simd_portable_لدو_آخری_dc(self, داخلہ->انکڑے[0U], شروع, len);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.absorb_final_80
with types uint64_t
with const generics
- N= 1
- RATE= 72
- DELIM= 6
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_generic_keccak_absorb_final_80_bd1(
  Eurydice_arr_7c *self,
  ثابت Eurydice_arr_dc *داخلہ,
  ناپ_t شروع,
  ناپ_t len
)
{
  libcrux_sha3_simd_portable_لدو_آخری_a1_dc(self, داخلہ, شروع, len);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.store_block
with const generics
- RATE= 72
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_simd_portable_store_بلاک_c6(
  ثابت Eurydice_arr_7c *s,
  Eurydice_mut_borrow_ٹکڑا_u8 باہرلا,
  ناپ_t شروع,
  ناپ_t len
)
{
  ناپ_t octets = len / (ناپ_t)8U;
  لكل (ناپ_t i = (ناپ_t)0U; i < octets; i++)
  {
    ناپ_t i0 = i;
    Eurydice_array_u8x8
    بائٹاں =
      core_عدد_u64_منزل_le_بائٹاں(libcrux_sha3_traits_get_ij_71(s,
          i0 / (ناپ_t)5U,
          i0 % (ناپ_t)5U)[0U]);
    ناپ_t باہرلا_pos = شروع + (ناپ_t)8U * i0;
    Eurydice_ٹکڑا_copy(Eurydice_ٹکڑا_subslice_mut_c8(باہرلا,
        (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = باہرلا_pos, .سرا = باہرلا_pos + (ناپ_t)8U })),
      Eurydice_array_منزل_ٹکڑا_shared_6e(&بائٹاں),
      uint8_t);
  }
  ناپ_t بچیا = len % (ناپ_t)8U;
  إذا (بچیا > (ناپ_t)0U)
  {
    Eurydice_array_u8x8
    بائٹاں =
      core_عدد_u64_منزل_le_بائٹاں(libcrux_sha3_traits_get_ij_71(s,
          octets / (ناپ_t)5U,
          octets % (ناپ_t)5U)[0U]);
    ناپ_t باہرلا_pos = شروع + len - بچیا;
    Eurydice_mut_borrow_ٹکڑا_u8
    uu____0 =
      Eurydice_ٹکڑا_subslice_mut_c8(باہرلا,
        (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = باہرلا_pos, .سرا = باہرلا_pos + بچیا }));
    Eurydice_ٹکڑا_copy(uu____0,
      Eurydice_array_منزل_subslice_منزل_shared_21(&بائٹاں, بچیا),
      uint8_t);
  }
}

/**
This function found in impl {libcrux_sha3::traits::Squeeze<u64> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.squeeze_9b
with const generics
- RATE= 72
*/
ساكن مضمن فراغ
libcrux_sha3_simd_portable_squeeze_9b_c6(
  ثابت Eurydice_arr_7c *self,
  Eurydice_mut_borrow_ٹکڑا_u8 باہرلا,
  ناپ_t شروع,
  ناپ_t len
)
{
  libcrux_sha3_simd_portable_store_بلاک_c6(self, باہرلا, شروع, len);
}

/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.keccak1
with const generics
- RATE= 72
- DELIM= 6
*/
ساكن مضمن فراغ
libcrux_sha3_generic_keccak_portable_keccak1_dc(
  Eurydice_borrow_ٹکڑا_u8 داخلہ,
  Eurydice_mut_borrow_ٹکڑا_u8 output
)
{
  Eurydice_arr_7c s = libcrux_sha3_generic_keccak_new_80_71();
  ناپ_t داخلہ_len = داخلہ.meta;
  ناپ_t داخلہ_بلاکاں = داخلہ_len / (ناپ_t)72U;
  ناپ_t داخلہ_rem = داخلہ_len % (ناپ_t)72U;
  لكل (ناپ_t i = (ناپ_t)0U; i < داخلہ_بلاکاں; i++)
  {
    ناپ_t i0 = i;
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_dc lvalue = { .انکڑے = { داخلہ } };
    libcrux_sha3_generic_keccak_absorb_بلاک_80_e91(&s, &lvalue, i0 * (ناپ_t)72U);
  }
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_dc lvalue = { .انکڑے = { داخلہ } };
  libcrux_sha3_generic_keccak_absorb_final_80_bd1(&s, &lvalue, داخلہ_len - داخلہ_rem, داخلہ_rem);
  ناپ_t output_len = output.meta;
  ناپ_t output_بلاکاں = output_len / (ناپ_t)72U;
  ناپ_t output_rem = output_len % (ناپ_t)72U;
  إذا (output_بلاکاں == (ناپ_t)0U)
  {
    libcrux_sha3_simd_portable_squeeze_9b_c6(&s, output, (ناپ_t)0U, output_len);
  }
  وإلا
  {
    libcrux_sha3_simd_portable_squeeze_9b_c6(&s, output, (ناپ_t)0U, (ناپ_t)72U);
    لكل (ناپ_t i = (ناپ_t)1U; i < output_بلاکاں; i++)
    {
      ناپ_t i0 = i;
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&s);
      libcrux_sha3_simd_portable_squeeze_9b_c6(&s, output, i0 * (ناپ_t)72U, (ناپ_t)72U);
    }
    إذا (output_rem != (ناپ_t)0U)
    {
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&s);
      libcrux_sha3_simd_portable_squeeze_9b_c6(&s, output, output_len - output_rem, output_rem);
    }
  }
}

/**
 A portable SHA3 512 implementation.
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_portable_sha512(
  Eurydice_mut_borrow_ٹکڑا_u8 digest,
  Eurydice_borrow_ٹکڑا_u8 انکڑے
)
{
  libcrux_sha3_generic_keccak_portable_keccak1_dc(انکڑے, digest);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_last
with const generics
- RATE= 136
- DELIMITER= 6
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_simd_portable_لدو_آخری_220(
  Eurydice_arr_7c *state,
  Eurydice_borrow_ٹکڑا_u8 بلاکاں,
  ناپ_t شروع,
  ناپ_t len
)
{
  Eurydice_arr_ff بفر = { .انکڑے = { 0U } };
  Eurydice_ٹکڑا_copy(Eurydice_array_منزل_subslice_mut_d42(&بفر,
      (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = (ناپ_t)0U, .سرا = len })),
    Eurydice_ٹکڑا_subslice_shared_c8(بلاکاں,
      (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = شروع, .سرا = شروع + len })),
    uint8_t);
  بفر.انکڑے[len] = 6U;
  ناپ_t uu____0 = (ناپ_t)136U - (ناپ_t)1U;
  بفر.انکڑے[uu____0] = (uint32_t)بفر.انکڑے[uu____0] | 128U;
  libcrux_sha3_simd_portable_لدو_بلاک_b2(state,
    Eurydice_array_منزل_ٹکڑا_shared_58(&بفر),
    (ناپ_t)0U);
}

/**
This function found in impl {libcrux_sha3::traits::Absorb<1usize> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.load_last_a1
with const generics
- RATE= 136
- DELIMITER= 6
*/
ساكن مضمن فراغ
libcrux_sha3_simd_portable_لدو_آخری_a1_220(
  Eurydice_arr_7c *self,
  ثابت Eurydice_arr_dc *داخلہ,
  ناپ_t شروع,
  ناپ_t len
)
{
  libcrux_sha3_simd_portable_لدو_آخری_220(self, داخلہ->انکڑے[0U], شروع, len);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.absorb_final_80
with types uint64_t
with const generics
- N= 1
- RATE= 136
- DELIM= 6
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_generic_keccak_absorb_final_80_bd2(
  Eurydice_arr_7c *self,
  ثابت Eurydice_arr_dc *داخلہ,
  ناپ_t شروع,
  ناپ_t len
)
{
  libcrux_sha3_simd_portable_لدو_آخری_a1_220(self, داخلہ, شروع, len);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
}

/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.keccak1
with const generics
- RATE= 136
- DELIM= 6
*/
ساكن مضمن فراغ
libcrux_sha3_generic_keccak_portable_keccak1_220(
  Eurydice_borrow_ٹکڑا_u8 داخلہ,
  Eurydice_mut_borrow_ٹکڑا_u8 output
)
{
  Eurydice_arr_7c s = libcrux_sha3_generic_keccak_new_80_71();
  ناپ_t داخلہ_len = داخلہ.meta;
  ناپ_t داخلہ_بلاکاں = داخلہ_len / (ناپ_t)136U;
  ناپ_t داخلہ_rem = داخلہ_len % (ناپ_t)136U;
  لكل (ناپ_t i = (ناپ_t)0U; i < داخلہ_بلاکاں; i++)
  {
    ناپ_t i0 = i;
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_dc lvalue = { .انکڑے = { داخلہ } };
    libcrux_sha3_generic_keccak_absorb_بلاک_80_e90(&s, &lvalue, i0 * (ناپ_t)136U);
  }
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_dc lvalue = { .انکڑے = { داخلہ } };
  libcrux_sha3_generic_keccak_absorb_final_80_bd2(&s, &lvalue, داخلہ_len - داخلہ_rem, داخلہ_rem);
  ناپ_t output_len = output.meta;
  ناپ_t output_بلاکاں = output_len / (ناپ_t)136U;
  ناپ_t output_rem = output_len % (ناپ_t)136U;
  إذا (output_بلاکاں == (ناپ_t)0U)
  {
    libcrux_sha3_simd_portable_squeeze_9b_b2(&s, output, (ناپ_t)0U, output_len);
  }
  وإلا
  {
    libcrux_sha3_simd_portable_squeeze_9b_b2(&s, output, (ناپ_t)0U, (ناپ_t)136U);
    لكل (ناپ_t i = (ناپ_t)1U; i < output_بلاکاں; i++)
    {
      ناپ_t i0 = i;
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&s);
      libcrux_sha3_simd_portable_squeeze_9b_b2(&s, output, i0 * (ناپ_t)136U, (ناپ_t)136U);
    }
    إذا (output_rem != (ناپ_t)0U)
    {
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&s);
      libcrux_sha3_simd_portable_squeeze_9b_b2(&s, output, output_len - output_rem, output_rem);
    }
  }
}

/**
 A portable SHA3 256 implementation.
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_portable_sha256(
  Eurydice_mut_borrow_ٹکڑا_u8 digest,
  Eurydice_borrow_ٹکڑا_u8 انکڑے
)
{
  libcrux_sha3_generic_keccak_portable_keccak1_220(انکڑے, digest);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.squeeze_first_three_blocks_b4
with const generics
- RATE= 168
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_generic_keccak_portable_squeeze_پہلا_three_بلاکاں_b4_60(
  Eurydice_arr_7c *self,
  Eurydice_mut_borrow_ٹکڑا_u8 باہرلا
)
{
  libcrux_sha3_simd_portable_squeeze_9b_60(self, باہرلا, (ناپ_t)0U, (ناپ_t)168U);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
  libcrux_sha3_simd_portable_squeeze_9b_60(self, باہرلا, (ناپ_t)168U, (ناپ_t)168U);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
  libcrux_sha3_simd_portable_squeeze_9b_60(self, باہرلا, (ناپ_t)2U * (ناپ_t)168U, (ناپ_t)168U);
}

/**
 Squeeze three blocks
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_portable_incremental_shake128_squeeze_پہلا_three_بلاکاں(
  Eurydice_arr_7c *s,
  Eurydice_mut_borrow_ٹکڑا_u8 out0
)
{
  libcrux_sha3_generic_keccak_portable_squeeze_پہلا_three_بلاکاں_b4_60(s, out0);
}

#تعریف_کرو libcrux_sha3_Algorithm_Sha224 1
#تعریف_کرو libcrux_sha3_Algorithm_Sha256 2
#تعریف_کرو libcrux_sha3_Algorithm_Sha384 3
#تعریف_کرو libcrux_sha3_Algorithm_Sha512 4

تعريفنوع uint8_t libcrux_sha3_Algorithm;

#تعریف_کرو LIBCRUX_SHA3_SHA3_224_DIGEST_ناپ ((ناپ_t)28U)

#تعریف_کرو LIBCRUX_SHA3_SHA3_256_DIGEST_ناپ ((ناپ_t)32U)

#تعریف_کرو LIBCRUX_SHA3_SHA3_384_DIGEST_ناپ ((ناپ_t)48U)

#تعریف_کرو LIBCRUX_SHA3_SHA3_512_DIGEST_ناپ ((ناپ_t)64U)

/**
 Returns the output size of a digest.
*/
ساكن مضمن ناپ_t libcrux_sha3_digest_ناپ(libcrux_sha3_Algorithm منوال)
{
  بدل (منوال)
  {
    حالة libcrux_sha3_Algorithm_Sha224:
      {
        اكسر;
      }
    حالة libcrux_sha3_Algorithm_Sha256:
      {
        أرجع LIBCRUX_SHA3_SHA3_256_DIGEST_ناپ;
      }
    حالة libcrux_sha3_Algorithm_Sha384:
      {
        أرجع LIBCRUX_SHA3_SHA3_384_DIGEST_ناپ;
      }
    حالة libcrux_sha3_Algorithm_Sha512:
      {
        أرجع LIBCRUX_SHA3_SHA3_512_DIGEST_ناپ;
      }
    افتراضي:
      {
        KRML_HOST_EPRINTF("KaRaMeL incomplete match at %s:%d\n", __FILE__, __LINE__);
        KRML_HOST_EXIT(253U);
      }
  }
  أرجع LIBCRUX_SHA3_SHA3_224_DIGEST_ناپ;
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_block
with const generics
- RATE= 144
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_simd_portable_لدو_بلاک_9e(
  Eurydice_arr_7c *state,
  Eurydice_borrow_ٹکڑا_u8 بلاکاں,
  ناپ_t شروع
)
{
  Eurydice_arr_7c state_flat = { .انکڑے = { 0U } };
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)144U / (ناپ_t)8U; i++)
  {
    ناپ_t i0 = i;
    ناپ_t وتھ = شروع + (ناپ_t)8U * i0;
    Eurydice_array_u8x8 arr;
    حافظہ_نقل(arr.انکڑے,
      Eurydice_ٹکڑا_subslice_shared_c8(بلاکاں,
        (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = وتھ, .سرا = وتھ + (ناپ_t)8U })).ptr,
      (ناپ_t)8U * حجم (uint8_t));
    Eurydice_array_u8x8
    uu____0 =
      core_نتیجہ_unwrap_26_e0((
          KRML_CLITERAL(core_نتیجہ_نتیجہ_8e){ .ٹیگ = core_نتیجہ_Ok, .val = { .case_Ok = arr } }
        ));
    state_flat.انکڑے[i0] = core_عدد_u64_from_le_بائٹاں(uu____0);
  }
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)144U / (ناپ_t)8U; i++)
  {
    ناپ_t i0 = i;
    libcrux_sha3_traits_سیٹ_ij_71(state,
      i0 / (ناپ_t)5U,
      i0 % (ناپ_t)5U,
      libcrux_sha3_traits_get_ij_71(state, i0 / (ناپ_t)5U, i0 % (ناپ_t)5U)[0U] ^
        state_flat.انکڑے[i0]);
  }
}

/**
This function found in impl {libcrux_sha3::traits::Absorb<1usize> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.load_block_a1
with const generics
- RATE= 144
*/
ساكن مضمن فراغ
libcrux_sha3_simd_portable_لدو_بلاک_a1_9e(
  Eurydice_arr_7c *self,
  ثابت Eurydice_arr_dc *داخلہ,
  ناپ_t شروع
)
{
  libcrux_sha3_simd_portable_لدو_بلاک_9e(self, داخلہ->انکڑے[0U], شروع);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.absorb_block_80
with types uint64_t
with const generics
- N= 1
- RATE= 144
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_generic_keccak_absorb_بلاک_80_e92(
  Eurydice_arr_7c *self,
  ثابت Eurydice_arr_dc *داخلہ,
  ناپ_t شروع
)
{
  libcrux_sha3_simd_portable_لدو_بلاک_a1_9e(self, داخلہ, شروع);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_last
with const generics
- RATE= 144
- DELIMITER= 6
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_simd_portable_لدو_آخری_3a(
  Eurydice_arr_7c *state,
  Eurydice_borrow_ٹکڑا_u8 بلاکاں,
  ناپ_t شروع,
  ناپ_t len
)
{
  Eurydice_arr_f4 بفر = { .انکڑے = { 0U } };
  Eurydice_ٹکڑا_copy(Eurydice_array_منزل_subslice_mut_d44(&بفر,
      (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = (ناپ_t)0U, .سرا = len })),
    Eurydice_ٹکڑا_subslice_shared_c8(بلاکاں,
      (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = شروع, .سرا = شروع + len })),
    uint8_t);
  بفر.انکڑے[len] = 6U;
  ناپ_t uu____0 = (ناپ_t)144U - (ناپ_t)1U;
  بفر.انکڑے[uu____0] = (uint32_t)بفر.انکڑے[uu____0] | 128U;
  libcrux_sha3_simd_portable_لدو_بلاک_9e(state,
    Eurydice_array_منزل_ٹکڑا_shared_38(&بفر),
    (ناپ_t)0U);
}

/**
This function found in impl {libcrux_sha3::traits::Absorb<1usize> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.load_last_a1
with const generics
- RATE= 144
- DELIMITER= 6
*/
ساكن مضمن فراغ
libcrux_sha3_simd_portable_لدو_آخری_a1_3a(
  Eurydice_arr_7c *self,
  ثابت Eurydice_arr_dc *داخلہ,
  ناپ_t شروع,
  ناپ_t len
)
{
  libcrux_sha3_simd_portable_لدو_آخری_3a(self, داخلہ->انکڑے[0U], شروع, len);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.absorb_final_80
with types uint64_t
with const generics
- N= 1
- RATE= 144
- DELIM= 6
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_generic_keccak_absorb_final_80_bd3(
  Eurydice_arr_7c *self,
  ثابت Eurydice_arr_dc *داخلہ,
  ناپ_t شروع,
  ناپ_t len
)
{
  libcrux_sha3_simd_portable_لدو_آخری_a1_3a(self, داخلہ, شروع, len);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.store_block
with const generics
- RATE= 144
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_simd_portable_store_بلاک_9e(
  ثابت Eurydice_arr_7c *s,
  Eurydice_mut_borrow_ٹکڑا_u8 باہرلا,
  ناپ_t شروع,
  ناپ_t len
)
{
  ناپ_t octets = len / (ناپ_t)8U;
  لكل (ناپ_t i = (ناپ_t)0U; i < octets; i++)
  {
    ناپ_t i0 = i;
    Eurydice_array_u8x8
    بائٹاں =
      core_عدد_u64_منزل_le_بائٹاں(libcrux_sha3_traits_get_ij_71(s,
          i0 / (ناپ_t)5U,
          i0 % (ناپ_t)5U)[0U]);
    ناپ_t باہرلا_pos = شروع + (ناپ_t)8U * i0;
    Eurydice_ٹکڑا_copy(Eurydice_ٹکڑا_subslice_mut_c8(باہرلا,
        (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = باہرلا_pos, .سرا = باہرلا_pos + (ناپ_t)8U })),
      Eurydice_array_منزل_ٹکڑا_shared_6e(&بائٹاں),
      uint8_t);
  }
  ناپ_t بچیا = len % (ناپ_t)8U;
  إذا (بچیا > (ناپ_t)0U)
  {
    Eurydice_array_u8x8
    بائٹاں =
      core_عدد_u64_منزل_le_بائٹاں(libcrux_sha3_traits_get_ij_71(s,
          octets / (ناپ_t)5U,
          octets % (ناپ_t)5U)[0U]);
    ناپ_t باہرلا_pos = شروع + len - بچیا;
    Eurydice_mut_borrow_ٹکڑا_u8
    uu____0 =
      Eurydice_ٹکڑا_subslice_mut_c8(باہرلا,
        (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = باہرلا_pos, .سرا = باہرلا_pos + بچیا }));
    Eurydice_ٹکڑا_copy(uu____0,
      Eurydice_array_منزل_subslice_منزل_shared_21(&بائٹاں, بچیا),
      uint8_t);
  }
}

/**
This function found in impl {libcrux_sha3::traits::Squeeze<u64> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.squeeze_9b
with const generics
- RATE= 144
*/
ساكن مضمن فراغ
libcrux_sha3_simd_portable_squeeze_9b_9e(
  ثابت Eurydice_arr_7c *self,
  Eurydice_mut_borrow_ٹکڑا_u8 باہرلا,
  ناپ_t شروع,
  ناپ_t len
)
{
  libcrux_sha3_simd_portable_store_بلاک_9e(self, باہرلا, شروع, len);
}

/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.keccak1
with const generics
- RATE= 144
- DELIM= 6
*/
ساكن مضمن فراغ
libcrux_sha3_generic_keccak_portable_keccak1_3a(
  Eurydice_borrow_ٹکڑا_u8 داخلہ,
  Eurydice_mut_borrow_ٹکڑا_u8 output
)
{
  Eurydice_arr_7c s = libcrux_sha3_generic_keccak_new_80_71();
  ناپ_t داخلہ_len = داخلہ.meta;
  ناپ_t داخلہ_بلاکاں = داخلہ_len / (ناپ_t)144U;
  ناپ_t داخلہ_rem = داخلہ_len % (ناپ_t)144U;
  لكل (ناپ_t i = (ناپ_t)0U; i < داخلہ_بلاکاں; i++)
  {
    ناپ_t i0 = i;
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_dc lvalue = { .انکڑے = { داخلہ } };
    libcrux_sha3_generic_keccak_absorb_بلاک_80_e92(&s, &lvalue, i0 * (ناپ_t)144U);
  }
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_dc lvalue = { .انکڑے = { داخلہ } };
  libcrux_sha3_generic_keccak_absorb_final_80_bd3(&s, &lvalue, داخلہ_len - داخلہ_rem, داخلہ_rem);
  ناپ_t output_len = output.meta;
  ناپ_t output_بلاکاں = output_len / (ناپ_t)144U;
  ناپ_t output_rem = output_len % (ناپ_t)144U;
  إذا (output_بلاکاں == (ناپ_t)0U)
  {
    libcrux_sha3_simd_portable_squeeze_9b_9e(&s, output, (ناپ_t)0U, output_len);
  }
  وإلا
  {
    libcrux_sha3_simd_portable_squeeze_9b_9e(&s, output, (ناپ_t)0U, (ناپ_t)144U);
    لكل (ناپ_t i = (ناپ_t)1U; i < output_بلاکاں; i++)
    {
      ناپ_t i0 = i;
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&s);
      libcrux_sha3_simd_portable_squeeze_9b_9e(&s, output, i0 * (ناپ_t)144U, (ناپ_t)144U);
    }
    إذا (output_rem != (ناپ_t)0U)
    {
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&s);
      libcrux_sha3_simd_portable_squeeze_9b_9e(&s, output, output_len - output_rem, output_rem);
    }
  }
}

/**
 A portable SHA3 224 implementation.
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_portable_sha224(
  Eurydice_mut_borrow_ٹکڑا_u8 digest,
  Eurydice_borrow_ٹکڑا_u8 انکڑے
)
{
  libcrux_sha3_generic_keccak_portable_keccak1_3a(انکڑے, digest);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_block
with const generics
- RATE= 104
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_simd_portable_لدو_بلاک_53(
  Eurydice_arr_7c *state,
  Eurydice_borrow_ٹکڑا_u8 بلاکاں,
  ناپ_t شروع
)
{
  Eurydice_arr_7c state_flat = { .انکڑے = { 0U } };
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)104U / (ناپ_t)8U; i++)
  {
    ناپ_t i0 = i;
    ناپ_t وتھ = شروع + (ناپ_t)8U * i0;
    Eurydice_array_u8x8 arr;
    حافظہ_نقل(arr.انکڑے,
      Eurydice_ٹکڑا_subslice_shared_c8(بلاکاں,
        (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = وتھ, .سرا = وتھ + (ناپ_t)8U })).ptr,
      (ناپ_t)8U * حجم (uint8_t));
    Eurydice_array_u8x8
    uu____0 =
      core_نتیجہ_unwrap_26_e0((
          KRML_CLITERAL(core_نتیجہ_نتیجہ_8e){ .ٹیگ = core_نتیجہ_Ok, .val = { .case_Ok = arr } }
        ));
    state_flat.انکڑے[i0] = core_عدد_u64_from_le_بائٹاں(uu____0);
  }
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)104U / (ناپ_t)8U; i++)
  {
    ناپ_t i0 = i;
    libcrux_sha3_traits_سیٹ_ij_71(state,
      i0 / (ناپ_t)5U,
      i0 % (ناپ_t)5U,
      libcrux_sha3_traits_get_ij_71(state, i0 / (ناپ_t)5U, i0 % (ناپ_t)5U)[0U] ^
        state_flat.انکڑے[i0]);
  }
}

/**
This function found in impl {libcrux_sha3::traits::Absorb<1usize> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.load_block_a1
with const generics
- RATE= 104
*/
ساكن مضمن فراغ
libcrux_sha3_simd_portable_لدو_بلاک_a1_53(
  Eurydice_arr_7c *self,
  ثابت Eurydice_arr_dc *داخلہ,
  ناپ_t شروع
)
{
  libcrux_sha3_simd_portable_لدو_بلاک_53(self, داخلہ->انکڑے[0U], شروع);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.absorb_block_80
with types uint64_t
with const generics
- N= 1
- RATE= 104
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_generic_keccak_absorb_بلاک_80_e93(
  Eurydice_arr_7c *self,
  ثابت Eurydice_arr_dc *داخلہ,
  ناپ_t شروع
)
{
  libcrux_sha3_simd_portable_لدو_بلاک_a1_53(self, داخلہ, شروع);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_last
with const generics
- RATE= 104
- DELIMITER= 6
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_simd_portable_لدو_آخری_dc0(
  Eurydice_arr_7c *state,
  Eurydice_borrow_ٹکڑا_u8 بلاکاں,
  ناپ_t شروع,
  ناپ_t len
)
{
  Eurydice_arr_c4 بفر = { .انکڑے = { 0U } };
  Eurydice_ٹکڑا_copy(Eurydice_array_منزل_subslice_mut_d45(&بفر,
      (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = (ناپ_t)0U, .سرا = len })),
    Eurydice_ٹکڑا_subslice_shared_c8(بلاکاں,
      (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = شروع, .سرا = شروع + len })),
    uint8_t);
  بفر.انکڑے[len] = 6U;
  ناپ_t uu____0 = (ناپ_t)104U - (ناپ_t)1U;
  بفر.انکڑے[uu____0] = (uint32_t)بفر.انکڑے[uu____0] | 128U;
  libcrux_sha3_simd_portable_لدو_بلاک_53(state,
    Eurydice_array_منزل_ٹکڑا_shared_72(&بفر),
    (ناپ_t)0U);
}

/**
This function found in impl {libcrux_sha3::traits::Absorb<1usize> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.load_last_a1
with const generics
- RATE= 104
- DELIMITER= 6
*/
ساكن مضمن فراغ
libcrux_sha3_simd_portable_لدو_آخری_a1_dc0(
  Eurydice_arr_7c *self,
  ثابت Eurydice_arr_dc *داخلہ,
  ناپ_t شروع,
  ناپ_t len
)
{
  libcrux_sha3_simd_portable_لدو_آخری_dc0(self, داخلہ->انکڑے[0U], شروع, len);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<T, N>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.absorb_final_80
with types uint64_t
with const generics
- N= 1
- RATE= 104
- DELIM= 6
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_generic_keccak_absorb_final_80_bd4(
  Eurydice_arr_7c *self,
  ثابت Eurydice_arr_dc *داخلہ,
  ناپ_t شروع,
  ناپ_t len
)
{
  libcrux_sha3_simd_portable_لدو_آخری_a1_dc0(self, داخلہ, شروع, len);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.store_block
with const generics
- RATE= 104
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_simd_portable_store_بلاک_53(
  ثابت Eurydice_arr_7c *s,
  Eurydice_mut_borrow_ٹکڑا_u8 باہرلا,
  ناپ_t شروع,
  ناپ_t len
)
{
  ناپ_t octets = len / (ناپ_t)8U;
  لكل (ناپ_t i = (ناپ_t)0U; i < octets; i++)
  {
    ناپ_t i0 = i;
    Eurydice_array_u8x8
    بائٹاں =
      core_عدد_u64_منزل_le_بائٹاں(libcrux_sha3_traits_get_ij_71(s,
          i0 / (ناپ_t)5U,
          i0 % (ناپ_t)5U)[0U]);
    ناپ_t باہرلا_pos = شروع + (ناپ_t)8U * i0;
    Eurydice_ٹکڑا_copy(Eurydice_ٹکڑا_subslice_mut_c8(باہرلا,
        (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = باہرلا_pos, .سرا = باہرلا_pos + (ناپ_t)8U })),
      Eurydice_array_منزل_ٹکڑا_shared_6e(&بائٹاں),
      uint8_t);
  }
  ناپ_t بچیا = len % (ناپ_t)8U;
  إذا (بچیا > (ناپ_t)0U)
  {
    Eurydice_array_u8x8
    بائٹاں =
      core_عدد_u64_منزل_le_بائٹاں(libcrux_sha3_traits_get_ij_71(s,
          octets / (ناپ_t)5U,
          octets % (ناپ_t)5U)[0U]);
    ناپ_t باہرلا_pos = شروع + len - بچیا;
    Eurydice_mut_borrow_ٹکڑا_u8
    uu____0 =
      Eurydice_ٹکڑا_subslice_mut_c8(باہرلا,
        (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = باہرلا_pos, .سرا = باہرلا_pos + بچیا }));
    Eurydice_ٹکڑا_copy(uu____0,
      Eurydice_array_منزل_subslice_منزل_shared_21(&بائٹاں, بچیا),
      uint8_t);
  }
}

/**
This function found in impl {libcrux_sha3::traits::Squeeze<u64> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.squeeze_9b
with const generics
- RATE= 104
*/
ساكن مضمن فراغ
libcrux_sha3_simd_portable_squeeze_9b_53(
  ثابت Eurydice_arr_7c *self,
  Eurydice_mut_borrow_ٹکڑا_u8 باہرلا,
  ناپ_t شروع,
  ناپ_t len
)
{
  libcrux_sha3_simd_portable_store_بلاک_53(self, باہرلا, شروع, len);
}

/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.keccak1
with const generics
- RATE= 104
- DELIM= 6
*/
ساكن مضمن فراغ
libcrux_sha3_generic_keccak_portable_keccak1_dc0(
  Eurydice_borrow_ٹکڑا_u8 داخلہ,
  Eurydice_mut_borrow_ٹکڑا_u8 output
)
{
  Eurydice_arr_7c s = libcrux_sha3_generic_keccak_new_80_71();
  ناپ_t داخلہ_len = داخلہ.meta;
  ناپ_t داخلہ_بلاکاں = داخلہ_len / (ناپ_t)104U;
  ناپ_t داخلہ_rem = داخلہ_len % (ناپ_t)104U;
  لكل (ناپ_t i = (ناپ_t)0U; i < داخلہ_بلاکاں; i++)
  {
    ناپ_t i0 = i;
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_dc lvalue = { .انکڑے = { داخلہ } };
    libcrux_sha3_generic_keccak_absorb_بلاک_80_e93(&s, &lvalue, i0 * (ناپ_t)104U);
  }
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_dc lvalue = { .انکڑے = { داخلہ } };
  libcrux_sha3_generic_keccak_absorb_final_80_bd4(&s, &lvalue, داخلہ_len - داخلہ_rem, داخلہ_rem);
  ناپ_t output_len = output.meta;
  ناپ_t output_بلاکاں = output_len / (ناپ_t)104U;
  ناپ_t output_rem = output_len % (ناپ_t)104U;
  إذا (output_بلاکاں == (ناپ_t)0U)
  {
    libcrux_sha3_simd_portable_squeeze_9b_53(&s, output, (ناپ_t)0U, output_len);
  }
  وإلا
  {
    libcrux_sha3_simd_portable_squeeze_9b_53(&s, output, (ناپ_t)0U, (ناپ_t)104U);
    لكل (ناپ_t i = (ناپ_t)1U; i < output_بلاکاں; i++)
    {
      ناپ_t i0 = i;
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&s);
      libcrux_sha3_simd_portable_squeeze_9b_53(&s, output, i0 * (ناپ_t)104U, (ناپ_t)104U);
    }
    إذا (output_rem != (ناپ_t)0U)
    {
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&s);
      libcrux_sha3_simd_portable_squeeze_9b_53(&s, output, output_len - output_rem, output_rem);
    }
  }
}

/**
 A portable SHA3 384 implementation.
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_portable_sha384(
  Eurydice_mut_borrow_ٹکڑا_u8 digest,
  Eurydice_borrow_ٹکڑا_u8 انکڑے
)
{
  libcrux_sha3_generic_keccak_portable_keccak1_dc0(انکڑے, digest);
}

/**
 SHA3 224

 Preconditions:
 - `digest.len() == 28`
*/
ساكن مضمن فراغ
libcrux_sha3_sha224_ema(Eurydice_mut_borrow_ٹکڑا_u8 digest, Eurydice_borrow_ٹکڑا_u8 payload)
{
  libcrux_sha3_portable_sha224(digest, payload);
}

/**
 SHA3 224
*/
ساكن مضمن Eurydice_arr_a2 libcrux_sha3_sha224(Eurydice_borrow_ٹکڑا_u8 انکڑے)
{
  Eurydice_arr_a2 باہرلا = { .انکڑے = { 0U } };
  libcrux_sha3_sha224_ema(Eurydice_array_منزل_ٹکڑا_mut_5e(&باہرلا), انکڑے);
  أرجع باہرلا;
}

/**
 SHA3 256
*/
ساكن مضمن فراغ
libcrux_sha3_sha256_ema(Eurydice_mut_borrow_ٹکڑا_u8 digest, Eurydice_borrow_ٹکڑا_u8 payload)
{
  libcrux_sha3_portable_sha256(digest, payload);
}

/**
 SHA3 256
*/
ساكن مضمن Eurydice_arr_ec libcrux_sha3_sha256(Eurydice_borrow_ٹکڑا_u8 انکڑے)
{
  Eurydice_arr_ec باہرلا = { .انکڑے = { 0U } };
  libcrux_sha3_sha256_ema(Eurydice_array_منزل_ٹکڑا_mut_01(&باہرلا), انکڑے);
  أرجع باہرلا;
}

/**
 SHA3 384
*/
ساكن مضمن فراغ
libcrux_sha3_sha384_ema(Eurydice_mut_borrow_ٹکڑا_u8 digest, Eurydice_borrow_ٹکڑا_u8 payload)
{
  libcrux_sha3_portable_sha384(digest, payload);
}

/**
 SHA3 384
*/
ساكن مضمن Eurydice_arr_65 libcrux_sha3_sha384(Eurydice_borrow_ٹکڑا_u8 انکڑے)
{
  Eurydice_arr_65 باہرلا = { .انکڑے = { 0U } };
  libcrux_sha3_sha384_ema(Eurydice_array_منزل_ٹکڑا_mut_9f(&باہرلا), انکڑے);
  أرجع باہرلا;
}

/**
 SHA3 512
*/
ساكن مضمن فراغ
libcrux_sha3_sha512_ema(Eurydice_mut_borrow_ٹکڑا_u8 digest, Eurydice_borrow_ٹکڑا_u8 payload)
{
  libcrux_sha3_portable_sha512(digest, payload);
}

/**
 SHA3 512
*/
ساكن مضمن Eurydice_arr_c7 libcrux_sha3_sha512(Eurydice_borrow_ٹکڑا_u8 انکڑے)
{
  Eurydice_arr_c7 باہرلا = { .انکڑے = { 0U } };
  libcrux_sha3_sha512_ema(Eurydice_array_منزل_ٹکڑا_mut_17(&باہرلا), انکڑے);
  أرجع باہرلا;
}

/**
 SHAKE 128

 Writes `out.len()` bytes.
*/
ساكن مضمن فراغ
libcrux_sha3_shake128_ema(Eurydice_mut_borrow_ٹکڑا_u8 باہرلا, Eurydice_borrow_ٹکڑا_u8 انکڑے)
{
  libcrux_sha3_portable_shake128(باہرلا, انکڑے);
}

/**
 SHAKE 256

 Writes `out.len()` bytes.
*/
ساكن مضمن فراغ
libcrux_sha3_shake256_ema(Eurydice_mut_borrow_ٹکڑا_u8 باہرلا, Eurydice_borrow_ٹکڑا_u8 انکڑے)
{
  libcrux_sha3_portable_shake256(باہرلا, انکڑے);
}

/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.KeccakXofState
with types uint64_t
with const generics
- $1size_t
- $168size_t
*/
تعريفنوع بنية libcrux_sha3_generic_keccak_xof_KeccakXofState_55_s
{
  Eurydice_arr_7c inner;
  Eurydice_arr_88 buf;
  ناپ_t buf_len;
  bool sponge;
}
libcrux_sha3_generic_keccak_xof_KeccakXofState_55;

تعريفنوع libcrux_sha3_generic_keccak_xof_KeccakXofState_55
libcrux_sha3_portable_incremental_Shake128Xof;

/**
 Try to complete the internal partial buffer by consuming the minimum required
 number of bytes from the provided `inputs` so that `self.buf` becomes exactly
 one full block of size `RATE`.

 Behaviour:
 - If `self.buf_len` is 0 (no buffered bytes) or already equal to `RATE`
   (already a full block), or if the combined available bytes in `inputs` are
   not enough to reach `RATE`, the function does nothing and returns 0.
 - If `0 < self.buf_len < RATE` and `inputs[..]` contain at least
   `RATE - self.buf_len` bytes, the function copies exactly
   `consumed = RATE - self.buf_len` bytes from each lane `inputs[i]` into
   `self.buf[i]` starting at the current `self.buf_len` offset, sets
   `self.buf_len = RATE`, and returns `consumed`.

 Returns the `consumed` bytes from `inputs` if there's enough buffered
 content to consume, and `0` otherwise.
 If `consumed > 0` is returned, `self.buf` contains a full block to be
 loaded.
*/
/**
This function found in impl {libcrux_sha3::generic_keccak::xof::KeccakXofState<STATE, PARALLEL_LANES, RATE>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.fill_buffer_35
with types uint64_t
with const generics
- PARALLEL_LANES= 1
- RATE= 168
*/
ساكن مضمن ناپ_t
libcrux_sha3_generic_keccak_xof_fill_بفر_35_e90(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_55 *self,
  ثابت Eurydice_arr_dc *inputs
)
{
  ناپ_t داخلہ_len = inputs->انکڑے->meta;
  ناپ_t uu____0;
  إذا (self->buf_len != (ناپ_t)0U)
  {
    إذا (داخلہ_len >= (ناپ_t)168U - self->buf_len)
    {
      ناپ_t consumed = (ناپ_t)168U - self->buf_len;
      لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)1U; i++)
      {
        ناپ_t i0 = i;
        Eurydice_ٹکڑا_copy(Eurydice_array_منزل_subslice_from_mut_5f0(&self->buf.انکڑے[i0],
            self->buf_len),
          Eurydice_ٹکڑا_subslice_منزل_shared_72(inputs->انکڑے[i0], consumed),
          uint8_t);
      }
      self->buf_len = (ناپ_t)168U;
      uu____0 = consumed;
    }
    وإلا
    {
      uu____0 = (ناپ_t)0U;
    }
  }
  وإلا
  {
    uu____0 = (ناپ_t)0U;
  }
  أرجع uu____0;
}

/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.buf_to_slices.closure
with const generics
- $1size_t
- $168size_t
*/
تعريفنوع ثابت Eurydice_arr_88 *libcrux_sha3_generic_keccak_xof_buf_منزل_slices_گھیرا_48;

/**
This function found in impl {core::ops::function::FnMut<(usize), &'_ ([u8])> for libcrux_sha3::generic_keccak::xof::buf_to_slices::closure<0, PARALLEL_LANES, RATE>}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.buf_to_slices.call_mut_2a
with const generics
- PARALLEL_LANES= 1
- RATE= 168
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
libcrux_sha3_generic_keccak_xof_buf_منزل_slices_call_mut_2a_810(
  ثابت Eurydice_arr_88 **_,
  ناپ_t tupled_دلیلاں
)
{
  ناپ_t i = tupled_دلیلاں;
  أرجع
    core_array_T_N_as_ٹکڑا((ناپ_t)168U,
      &_[0U]->انکڑے[i],
      uint8_t,
      Eurydice_borrow_ٹکڑا_u8);
}

/**
This function found in impl {core::ops::function::FnOnce<(usize), &'_ ([u8])> for libcrux_sha3::generic_keccak::xof::buf_to_slices::closure<0, PARALLEL_LANES, RATE>}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.buf_to_slices.call_once_fa
with const generics
- PARALLEL_LANES= 1
- RATE= 168
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
libcrux_sha3_generic_keccak_xof_buf_منزل_slices_call_once_fa_810(
  ثابت Eurydice_arr_88 *_,
  ناپ_t _0
)
{
  أرجع libcrux_sha3_generic_keccak_xof_buf_منزل_slices_call_mut_2a_810(&_, _0);
}

/**
 Note: This function exists to work around a hax bug where `core::array::from_fn`
 is extracted with an incorrect explicit type parameter `#(usize -> t_Slice u8)`
 instead of using the typeclass-based implicit parameter `#v_F` from
 `Core_models.Array.from_fn`.
 See: https://github.com/cryspen/hax/issues/1920
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.buf_to_slices
with const generics
- PARALLEL_LANES= 1
- RATE= 168
*/
ساكن KRML_MUSTINLINE Eurydice_arr_dc
libcrux_sha3_generic_keccak_xof_buf_منزل_slices_810(ثابت Eurydice_arr_88 *buf)
{
  Eurydice_arr_dc arr_struct;
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)1U; i++)
  {
    arr_struct.انکڑے[i] = libcrux_sha3_generic_keccak_xof_buf_منزل_slices_call_mut_2a_810(&buf, i);
  }
  أرجع arr_struct;
}

/**
This function found in impl {libcrux_sha3::generic_keccak::xof::KeccakXofState<STATE, PARALLEL_LANES, RATE>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.absorb_full_35
with types uint64_t
with const generics
- PARALLEL_LANES= 1
- RATE= 168
*/
ساكن مضمن ناپ_t
libcrux_sha3_generic_keccak_xof_absorb_بھریا_35_e90(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_55 *self,
  ثابت Eurydice_arr_dc *inputs
)
{
  ناپ_t consumed = libcrux_sha3_generic_keccak_xof_fill_بفر_35_e90(self, inputs);
  إذا (self->buf_len == (ناپ_t)168U)
  {
    Eurydice_arr_dc borrowed = libcrux_sha3_generic_keccak_xof_buf_منزل_slices_810(&self->buf);
    libcrux_sha3_simd_portable_لدو_بلاک_a1_60(&self->inner, &borrowed, (ناپ_t)0U);
    libcrux_sha3_generic_keccak_keccakf1600_80_71(&self->inner);
    self->buf_len = (ناپ_t)0U;
  }
  ناپ_t داخلہ_منزل_consume = inputs->انکڑے->meta - consumed;
  ناپ_t عدد_بلاکاں = داخلہ_منزل_consume / (ناپ_t)168U;
  ناپ_t remainder = داخلہ_منزل_consume % (ناپ_t)168U;
  لكل (ناپ_t i = (ناپ_t)0U; i < عدد_بلاکاں; i++)
  {
    ناپ_t i0 = i;
    ناپ_t شروع = i0 * (ناپ_t)168U + consumed;
    libcrux_sha3_simd_portable_لدو_بلاک_a1_60(&self->inner, inputs, شروع);
    libcrux_sha3_generic_keccak_keccakf1600_80_71(&self->inner);
  }
  أرجع remainder;
}

/**
 Absorb

 This function takes any number of bytes to absorb and buffers if it's not enough.
 The function assumes that all input slices in `inputs` have the same length.

 Only a multiple of `RATE` blocks are absorbed.
 For the remaining bytes [`absorb_final`] needs to be called.

 This works best with relatively small `inputs`.
*/
/**
This function found in impl {libcrux_sha3::generic_keccak::xof::KeccakXofState<STATE, PARALLEL_LANES, RATE>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.absorb_35
with types uint64_t
with const generics
- PARALLEL_LANES= 1
- RATE= 168
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_generic_keccak_xof_absorb_35_e90(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_55 *self,
  ثابت Eurydice_arr_dc *inputs
)
{
  ناپ_t remainder = libcrux_sha3_generic_keccak_xof_absorb_بھریا_35_e90(self, inputs);
  إذا (remainder > (ناپ_t)0U)
  {
    ناپ_t داخلہ_len = inputs->انکڑے->meta;
    لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)1U; i++)
    {
      ناپ_t i0 = i;
      Eurydice_ٹکڑا_copy(Eurydice_array_منزل_subslice_mut_d41(&self->buf.انکڑے[i0],
          (
            KRML_CLITERAL(core_ops_range_Range_87){
              .شروع = self->buf_len,
              .سرا = self->buf_len + remainder
            }
          )),
        Eurydice_ٹکڑا_subslice_shared_c8(inputs->انکڑے[i0],
          (
            KRML_CLITERAL(core_ops_range_Range_87){
              .شروع = داخلہ_len - remainder,
              .سرا = داخلہ_len
            }
          )),
        uint8_t);
    }
    self->buf_len += remainder;
  }
}

/**
This function found in impl {libcrux_sha3::portable::incremental::Xof<168usize> for libcrux_sha3::portable::incremental::Shake128Xof}
*/
ساكن مضمن فراغ
libcrux_sha3_portable_incremental_absorb_26(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_55 *self,
  Eurydice_borrow_ٹکڑا_u8 داخلہ
)
{
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_dc lvalue = { .انکڑے = { داخلہ } };
  libcrux_sha3_generic_keccak_xof_absorb_35_e90(self, &lvalue);
}

/**
 Absorb a final block.

 The `inputs` block may be empty. Everything in the `inputs` block beyond
 `RATE` bytes is ignored.
*/
/**
This function found in impl {libcrux_sha3::generic_keccak::xof::KeccakXofState<STATE, PARALLEL_LANES, RATE>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.absorb_final_35
with types uint64_t
with const generics
- PARALLEL_LANES= 1
- RATE= 168
- DELIMITER= 31
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_generic_keccak_xof_absorb_final_35_bd0(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_55 *self,
  ثابت Eurydice_arr_dc *inputs
)
{
  libcrux_sha3_generic_keccak_xof_absorb_35_e90(self, inputs);
  Eurydice_arr_dc borrowed = libcrux_sha3_generic_keccak_xof_buf_منزل_slices_810(&self->buf);
  libcrux_sha3_simd_portable_لدو_آخری_a1_37(&self->inner, &borrowed, (ناپ_t)0U, self->buf_len);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(&self->inner);
}

/**
This function found in impl {libcrux_sha3::portable::incremental::Xof<168usize> for libcrux_sha3::portable::incremental::Shake128Xof}
*/
ساكن مضمن فراغ
libcrux_sha3_portable_incremental_absorb_final_26(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_55 *self,
  Eurydice_borrow_ٹکڑا_u8 داخلہ
)
{
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_dc lvalue = { .انکڑے = { داخلہ } };
  libcrux_sha3_generic_keccak_xof_absorb_final_35_bd0(self, &lvalue);
}

/**
 An all zero block
*/
/**
This function found in impl {libcrux_sha3::generic_keccak::xof::KeccakXofState<STATE, PARALLEL_LANES, RATE>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.zero_block_35
with types uint64_t
with const generics
- PARALLEL_LANES= 1
- RATE= 168
*/
ساكن مضمن Eurydice_arr_c5 libcrux_sha3_generic_keccak_xof_zero_بلاک_35_e90(فراغ)
{
  أرجع (KRML_CLITERAL(Eurydice_arr_c5){ .انکڑے = { 0U } });
}

/**
 Generate a new keccak xof state.
*/
/**
This function found in impl {libcrux_sha3::generic_keccak::xof::KeccakXofState<STATE, PARALLEL_LANES, RATE>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.new_35
with types uint64_t
with const generics
- PARALLEL_LANES= 1
- RATE= 168
*/
ساكن مضمن libcrux_sha3_generic_keccak_xof_KeccakXofState_55
libcrux_sha3_generic_keccak_xof_new_35_e90(فراغ)
{
  libcrux_sha3_generic_keccak_xof_KeccakXofState_55 lit;
  lit.inner = libcrux_sha3_generic_keccak_new_80_71();
  Eurydice_arr_c5 repeat_عبارت[1U];
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)1U; i++)
  {
    repeat_عبارت[i] = libcrux_sha3_generic_keccak_xof_zero_بلاک_35_e90();
  }
  حافظہ_نقل(lit.buf.انکڑے, repeat_عبارت, (ناپ_t)1U * حجم (Eurydice_arr_c5));
  lit.buf_len = (ناپ_t)0U;
  lit.sponge = false;
  أرجع lit;
}

/**
This function found in impl {libcrux_sha3::portable::incremental::Xof<168usize> for libcrux_sha3::portable::incremental::Shake128Xof}
*/
ساكن مضمن libcrux_sha3_generic_keccak_xof_KeccakXofState_55
libcrux_sha3_portable_incremental_new_26(فراغ)
{
  أرجع libcrux_sha3_generic_keccak_xof_new_35_e90();
}

/**
 Squeeze `N` x `LEN` bytes. Only `N = 1` for now.
*/
/**
This function found in impl {libcrux_sha3::generic_keccak::xof::KeccakXofState<STATE, 1usize, RATE>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.squeeze_85
with types uint64_t
with const generics
- RATE= 168
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_sha3_generic_keccak_xof_squeeze_85_2a(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_55 *self,
  Eurydice_mut_borrow_ٹکڑا_u8 باہرلا
)
{
  ناپ_t باہرلا_len = باہرلا.meta;
  إذا (!(باہرلا_len == (ناپ_t)0U))
  {
    إذا (self->sponge)
    {
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&self->inner);
    }
    إذا (باہرلا_len > (ناپ_t)0U)
    {
      ناپ_t بلاکاں = باہرلا_len / (ناپ_t)168U;
      ناپ_t آخری = باہرلا_len - باہرلا_len % (ناپ_t)168U;
      إذا (بلاکاں == (ناپ_t)0U)
      {
        libcrux_sha3_simd_portable_squeeze_9b_60(&self->inner, باہرلا, (ناپ_t)0U, باہرلا_len);
      }
      وإلا
      {
        libcrux_sha3_simd_portable_squeeze_9b_60(&self->inner, باہرلا, (ناپ_t)0U, (ناپ_t)168U);
        لكل (ناپ_t i = (ناپ_t)1U; i < بلاکاں; i++)
        {
          ناپ_t i0 = i;
          libcrux_sha3_generic_keccak_keccakf1600_80_71(&self->inner);
          libcrux_sha3_simd_portable_squeeze_9b_60(&self->inner,
            باہرلا,
            i0 * (ناپ_t)168U,
            (ناپ_t)168U);
        }
        إذا (آخری < باہرلا_len)
        {
          libcrux_sha3_generic_keccak_keccakf1600_80_71(&self->inner);
          libcrux_sha3_simd_portable_squeeze_9b_60(&self->inner, باہرلا, آخری, باہرلا_len - آخری);
        }
      }
    }
    self->sponge = true;
  }
}

/**
 Shake128 squeeze
*/
/**
This function found in impl {libcrux_sha3::portable::incremental::Xof<168usize> for libcrux_sha3::portable::incremental::Shake128Xof}
*/
ساكن مضمن فراغ
libcrux_sha3_portable_incremental_squeeze_26(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_55 *self,
  Eurydice_mut_borrow_ٹکڑا_u8 باہرلا
)
{
  libcrux_sha3_generic_keccak_xof_squeeze_85_2a(self, باہرلا);
}

/**
This function found in impl {core::clone::Clone for libcrux_sha3::portable::KeccakState}
*/
ساكن مضمن Eurydice_arr_7c libcrux_sha3_portable_clone_fe(ثابت Eurydice_arr_7c *self)
{
  أرجع self[0U];
}

/**
This function found in impl {core::clone::Clone for libcrux_sha3::Algorithm}
*/
ساكن مضمن libcrux_sha3_Algorithm libcrux_sha3_clone_e6(ثابت libcrux_sha3_Algorithm *self)
{
  أرجع self[0U];
}

/**
This function found in impl {core::convert::From<libcrux_sha3::Algorithm> for u32}
*/
ساكن مضمن uint32_t libcrux_sha3_from_6c(libcrux_sha3_Algorithm v)
{
  بدل (v)
  {
    حالة libcrux_sha3_Algorithm_Sha224:
      {
        اكسر;
      }
    حالة libcrux_sha3_Algorithm_Sha256:
      {
        أرجع 2U;
      }
    حالة libcrux_sha3_Algorithm_Sha384:
      {
        أرجع 3U;
      }
    حالة libcrux_sha3_Algorithm_Sha512:
      {
        أرجع 4U;
      }
    افتراضي:
      {
        KRML_HOST_EPRINTF("KaRaMeL incomplete match at %s:%d\n", __FILE__, __LINE__);
        KRML_HOST_EXIT(253U);
      }
  }
  أرجع 1U;
}

/**
A monomorphic instance of Eurydice.arr
with types libcrux_sha3_portable_KeccakState
with const generics
- $3size_t
*/
تعريفنوع بنية Eurydice_arr_1b0_s { Eurydice_arr_7c انکڑے[3U]; } Eurydice_arr_1b0;

#إذا defined(__cplusplus)
}
#جے_انت

#تعریف_کرو libcrux_sha3_portable_H_DEFINED
#جے_انت /* libcrux_sha3_portable_H */

/* from libcrux/combined_extraction/generated/libcrux_mlkem_core.h */
/*
 * SPDX-FileCopyrightText: 2025 Cryspen Sarl <info@cryspen.com>
 *
 * SPDX-License-Identifier: MIT or Apache-2.0
 *
 * This code was generated with the following revisions:
 * Charon: e656e17bff6ca5efac8ab6919b9b74cb9a8dd8ad
 * Eurydice: aaa9fa657fb6f09802edb890252040d94cd93982
 * Karamel: 8c19d41458ce5cbfea029ebc03334ba96d149039
 * F*: unset
 * Libcrux: c4e5e5e511bbc4c53f826163f57bfd10e9228911
 */


#جے_بنا_تعریف libcrux_mlkem_core_H
#تعریف_کرو libcrux_mlkem_core_H



#إذا defined(__cplusplus)
خارجي "C" {
#جے_انت


#تعریف_کرو LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_ناپ ((ناپ_t)32U)

#تعریف_کرو LIBCRUX_ML_KEM_CONSTANTS_بٹ_فی_COEFFICIENT ((ناپ_t)12U)

#تعریف_کرو LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_وچ_RING_ELEMENT ((ناپ_t)256U)

#تعریف_کرو LIBCRUX_ML_KEM_CONSTANTS_بٹ_فی_RING_ELEMENT (LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_وچ_RING_ELEMENT * (ناپ_t)12U)

#تعریف_کرو LIBCRUX_ML_KEM_CONSTANTS_بائٹاں_فی_RING_ELEMENT (LIBCRUX_ML_KEM_CONSTANTS_بٹ_فی_RING_ELEMENT / (ناپ_t)8U)

#تعریف_کرو LIBCRUX_ML_KEM_CONSTANTS_CPA_PKE_کلید_GENERATION_بیج_ناپ ((ناپ_t)32U)

#تعریف_کرو LIBCRUX_ML_KEM_CONSTANTS_G_DIGEST_ناپ ((ناپ_t)64U)

#تعریف_کرو LIBCRUX_ML_KEM_CONSTANTS_H_DIGEST_ناپ ((ناپ_t)32U)

/**
 K * BITS_PER_RING_ELEMENT / 8

 [eurydice] Note that we can't use const generics here because that breaks
            C extraction with eurydice.
*/
ساكن مضمن ناپ_t libcrux_ml_kem_constants_ranked_بائٹاں_فی_ring_element(ناپ_t rank)
{
  أرجع rank * LIBCRUX_ML_KEM_CONSTANTS_بٹ_فی_RING_ELEMENT / (ناپ_t)8U;
}

/**
This function found in impl {libcrux_secrets::int::CastOps for i16}
*/
ساكن KRML_MUSTINLINE uint8_t libcrux_secrets_int_as_u8_f5(int16_t self)
{
  أرجع
    libcrux_secrets_int_عوامی_integers_classify_27_90((uint8_t)libcrux_secrets_int_عوامی_integers_declassify_d8_39(self));
}

/**
This function found in impl {libcrux_secrets::int::CastOps for u8}
*/
ساكن KRML_MUSTINLINE int16_t libcrux_secrets_int_as_i16_59(uint8_t self)
{
  أرجع
    libcrux_secrets_int_عوامی_integers_classify_27_39((int16_t)(uint32_t)libcrux_secrets_int_عوامی_integers_declassify_d8_90(self));
}

/**
This function found in impl {libcrux_secrets::int::CastOps for i16}
*/
ساكن KRML_MUSTINLINE int32_t libcrux_secrets_int_as_i32_f5(int16_t self)
{
  أرجع
    libcrux_secrets_int_عوامی_integers_classify_27_a8((int32_t)libcrux_secrets_int_عوامی_integers_declassify_d8_39(self));
}

/**
This function found in impl {libcrux_secrets::int::CastOps for i32}
*/
ساكن KRML_MUSTINLINE int16_t libcrux_secrets_int_as_i16_36(int32_t self)
{
  أرجع
    libcrux_secrets_int_عوامی_integers_classify_27_39((int16_t)libcrux_secrets_int_عوامی_integers_declassify_d8_a8(self));
}

/**
This function found in impl {libcrux_secrets::int::CastOps for u32}
*/
ساكن KRML_MUSTINLINE int32_t libcrux_secrets_int_as_i32_b8(uint32_t self)
{
  أرجع
    libcrux_secrets_int_عوامی_integers_classify_27_a8((int32_t)libcrux_secrets_int_عوامی_integers_declassify_d8_df(self));
}

/**
This function found in impl {libcrux_secrets::int::CastOps for i16}
*/
ساكن KRML_MUSTINLINE uint16_t libcrux_secrets_int_as_u16_f5(int16_t self)
{
  أرجع
    libcrux_secrets_int_عوامی_integers_classify_27_de((uint16_t)libcrux_secrets_int_عوامی_integers_declassify_d8_39(self));
}

/**
This function found in impl {libcrux_secrets::int::CastOps for u16}
*/
ساكن KRML_MUSTINLINE int16_t libcrux_secrets_int_as_i16_ca(uint16_t self)
{
  أرجع
    libcrux_secrets_int_عوامی_integers_classify_27_39((int16_t)(uint32_t)libcrux_secrets_int_عوامی_integers_declassify_d8_de(self));
}

/**
This function found in impl {libcrux_secrets::int::CastOps for u16}
*/
ساكن KRML_MUSTINLINE uint64_t libcrux_secrets_int_as_u64_ca(uint16_t self)
{
  أرجع
    libcrux_secrets_int_عوامی_integers_classify_27_49((uint64_t)(uint32_t)libcrux_secrets_int_عوامی_integers_declassify_d8_de(self));
}

/**
This function found in impl {libcrux_secrets::int::CastOps for u64}
*/
ساكن KRML_MUSTINLINE uint32_t libcrux_secrets_int_as_u32_a3(uint64_t self)
{
  أرجع
    libcrux_secrets_int_عوامی_integers_classify_27_df((uint32_t)libcrux_secrets_int_عوامی_integers_declassify_d8_49(self));
}

/**
This function found in impl {libcrux_secrets::int::CastOps for u32}
*/
ساكن KRML_MUSTINLINE int16_t libcrux_secrets_int_as_i16_b8(uint32_t self)
{
  أرجع
    libcrux_secrets_int_عوامی_integers_classify_27_39((int16_t)libcrux_secrets_int_عوامی_integers_declassify_d8_df(self));
}

/**
This function found in impl {libcrux_secrets::int::CastOps for i16}
*/
ساكن KRML_MUSTINLINE int16_t libcrux_secrets_int_as_i16_f5(int16_t self)
{
  أرجع
    libcrux_secrets_int_عوامی_integers_classify_27_39(libcrux_secrets_int_عوامی_integers_declassify_d8_39(self));
}

/**
 Pad the `slice` with `0`s at the end.
*/
/**
A monomorphic instance of libcrux_ml_kem.utils.into_padded_array
with const generics
- LEN= 32
*/
ساكن KRML_MUSTINLINE Eurydice_arr_ec
libcrux_ml_kem_utils_into_padded_array_ce(Eurydice_borrow_ٹکڑا_u8 ٹکڑا)
{
  Eurydice_arr_ec باہرلا = { .انکڑے = { 0U } };
  Eurydice_ٹکڑا_copy(Eurydice_array_منزل_subslice_mut_d46(&باہرلا,
      (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = (ناپ_t)0U, .سرا = ٹکڑا.meta })),
    ٹکڑا,
    uint8_t);
  أرجع باہرلا;
}

/**
This function found in impl {core::default::Default for libcrux_ml_kem::types::MlKemPrivateKey<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.default_d3
with const generics
- SIZE= 2400
*/
ساكن مضمن Eurydice_arr_7d libcrux_ml_kem_types_default_d3_79(فراغ)
{
  أرجع (KRML_CLITERAL(Eurydice_arr_7d){ .انکڑے = { 0U } });
}

/**
This function found in impl {core::convert::From<[u8; SIZE]> for libcrux_ml_kem::types::MlKemPublicKey<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.from_51
with const generics
- SIZE= 1184
*/
ساكن مضمن Eurydice_arr_5f libcrux_ml_kem_types_from_51_3d(Eurydice_arr_5f قدر)
{
  أرجع قدر;
}

تعريفنوع بنية libcrux_ml_kem_mlkem768_Ml_Kem768_کلید_Pair_s
{
  Eurydice_arr_7d sk;
  Eurydice_arr_5f pk;
}
libcrux_ml_kem_mlkem768_Ml_Kem768_کلید_Pair;

/**
 Create a new [`MlKemKeyPair`] from the secret and public key.
*/
/**
This function found in impl {libcrux_ml_kem::types::MlKemKeyPair<PRIVATE_KEY_SIZE, PUBLIC_KEY_SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.from_17
with const generics
- PRIVATE_KEY_SIZE= 2400
- PUBLIC_KEY_SIZE= 1184
*/
ساكن مضمن libcrux_ml_kem_mlkem768_Ml_Kem768_کلید_Pair
libcrux_ml_kem_types_from_17_bc(Eurydice_arr_7d sk, Eurydice_arr_5f pk)
{
  أرجع (KRML_CLITERAL(libcrux_ml_kem_mlkem768_Ml_Kem768_کلید_Pair){ .sk = sk, .pk = pk });
}

/**
This function found in impl {core::convert::From<[u8; SIZE]> for libcrux_ml_kem::types::MlKemPrivateKey<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.from_b2
with const generics
- SIZE= 2400
*/
ساكن مضمن Eurydice_arr_7d libcrux_ml_kem_types_from_b2_79(Eurydice_arr_7d قدر)
{
  أرجع قدر;
}

/**
A monomorphic instance of n-tuple
with types libcrux_ml_kem_mlkem768_MlKem768Ciphertext, Eurydice_arr_ec

*/
تعريفنوع بنية tuple_f4_s
{
  Eurydice_arr_2b fst;
  Eurydice_arr_ec snd;
}
tuple_f4;

/**
This function found in impl {core::convert::From<[u8; SIZE]> for libcrux_ml_kem::types::MlKemCiphertext<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.from_19
with const generics
- SIZE= 1088
*/
ساكن مضمن Eurydice_arr_2b libcrux_ml_kem_types_from_19_52(Eurydice_arr_2b قدر)
{
  أرجع قدر;
}

/**
 A reference to the raw byte slice.
*/
/**
This function found in impl {libcrux_ml_kem::types::MlKemPublicKey<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.as_slice_e6
with const generics
- SIZE= 1184
*/
ساكن مضمن ثابت
Eurydice_arr_5f
*libcrux_ml_kem_types_as_ٹکڑا_e6_3d(ثابت Eurydice_arr_5f *self)
{
  أرجع self;
}

/**
 A reference to the raw byte slice.
*/
/**
This function found in impl {libcrux_ml_kem::types::MlKemCiphertext<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.as_slice_a9
with const generics
- SIZE= 1088
*/
ساكن مضمن ثابت
Eurydice_arr_2b
*libcrux_ml_kem_types_as_ٹکڑا_a9_52(ثابت Eurydice_arr_2b *self)
{
  أرجع self;
}

/**
A monomorphic instance of libcrux_ml_kem.utils.prf_input_inc
with const generics
- K= 3
*/
ساكن KRML_MUSTINLINE uint8_t
libcrux_ml_kem_utils_prf_داخلہ_inc_78(Eurydice_arr_fd *prf_inputs, uint8_t domain_separator)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)3U; i++)
  {
    ناپ_t i0 = i;
    prf_inputs->انکڑے[i0].انکڑے[32U] = domain_separator;
    domain_separator = (uint32_t)domain_separator + 1U;
  }
  أرجع domain_separator;
}

/**
 Pad the `slice` with `0`s at the end.
*/
/**
A monomorphic instance of libcrux_ml_kem.utils.into_padded_array
with const generics
- LEN= 33
*/
ساكن KRML_MUSTINLINE Eurydice_arr_fa0
libcrux_ml_kem_utils_into_padded_array_29(Eurydice_borrow_ٹکڑا_u8 ٹکڑا)
{
  Eurydice_arr_fa0 باہرلا = { .انکڑے = { 0U } };
  Eurydice_ٹکڑا_copy(Eurydice_array_منزل_subslice_mut_d412(&باہرلا,
      (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = (ناپ_t)0U, .سرا = ٹکڑا.meta })),
    ٹکڑا,
    uint8_t);
  أرجع باہرلا;
}

/**
 Pad the `slice` with `0`s at the end.
*/
/**
A monomorphic instance of libcrux_ml_kem.utils.into_padded_array
with const generics
- LEN= 34
*/
ساكن KRML_MUSTINLINE Eurydice_arr_31
libcrux_ml_kem_utils_into_padded_array_de(Eurydice_borrow_ٹکڑا_u8 ٹکڑا)
{
  Eurydice_arr_31 باہرلا = { .انکڑے = { 0U } };
  Eurydice_ٹکڑا_copy(Eurydice_array_منزل_subslice_mut_d40(&باہرلا,
      (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = (ناپ_t)0U, .سرا = ٹکڑا.meta })),
    ٹکڑا,
    uint8_t);
  أرجع باہرلا;
}

/**
This function found in impl {core::convert::AsRef<[u8]> for libcrux_ml_kem::types::MlKemCiphertext<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.as_ref_c1
with const generics
- SIZE= 1088
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
libcrux_ml_kem_types_as_ref_c1_52(ثابت Eurydice_arr_2b *self)
{
  أرجع Eurydice_array_منزل_ٹکڑا_shared_06(self);
}

/**
 Pad the `slice` with `0`s at the end.
*/
/**
A monomorphic instance of libcrux_ml_kem.utils.into_padded_array
with const generics
- LEN= 1120
*/
ساكن KRML_MUSTINLINE Eurydice_arr_af
libcrux_ml_kem_utils_into_padded_array_66(Eurydice_borrow_ٹکڑا_u8 ٹکڑا)
{
  Eurydice_arr_af باہرلا = { .انکڑے = { 0U } };
  Eurydice_ٹکڑا_copy(Eurydice_array_منزل_subslice_mut_d411(&باہرلا,
      (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = (ناپ_t)0U, .سرا = ٹکڑا.meta })),
    ٹکڑا,
    uint8_t);
  أرجع باہرلا;
}

/**
 Pad the `slice` with `0`s at the end.
*/
/**
A monomorphic instance of libcrux_ml_kem.utils.into_padded_array
with const generics
- LEN= 64
*/
ساكن KRML_MUSTINLINE Eurydice_arr_c7
libcrux_ml_kem_utils_into_padded_array_c9(Eurydice_borrow_ٹکڑا_u8 ٹکڑا)
{
  Eurydice_arr_c7 باہرلا = { .انکڑے = { 0U } };
  Eurydice_ٹکڑا_copy(Eurydice_array_منزل_subslice_mut_d410(&باہرلا,
      (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = (ناپ_t)0U, .سرا = ٹکڑا.meta })),
    ٹکڑا,
    uint8_t);
  أرجع باہرلا;
}

تعريفنوع بنية Eurydice_borrow_ٹکڑا_u8_x4_s
{
  Eurydice_borrow_ٹکڑا_u8 fst;
  Eurydice_borrow_ٹکڑا_u8 snd;
  Eurydice_borrow_ٹکڑا_u8 thd;
  Eurydice_borrow_ٹکڑا_u8 f3;
}
Eurydice_borrow_ٹکڑا_u8_x4;

تعريفنوع بنية Eurydice_borrow_ٹکڑا_u8_x2_s
{
  Eurydice_borrow_ٹکڑا_u8 fst;
  Eurydice_borrow_ٹکڑا_u8 snd;
}
Eurydice_borrow_ٹکڑا_u8_x2;

/**
 Unpack an incoming private key into it's different parts.

 We have this here in types to extract into a common core for C.
*/
/**
A monomorphic instance of libcrux_ml_kem.types.unpack_private_key
with const generics
- CPA_SECRET_KEY_SIZE= 1152
- PUBLIC_KEY_SIZE= 1184
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8_x4
libcrux_ml_kem_types_unpack_نجی_کلید_64(Eurydice_borrow_ٹکڑا_u8 نجی_کلید)
{
  Eurydice_borrow_ٹکڑا_u8_x2
  uu____0 =
    Eurydice_ٹکڑا_ونڈو_at(نجی_کلید,
      (ناپ_t)1152U,
      uint8_t,
      Eurydice_borrow_ٹکڑا_u8_x2);
  Eurydice_borrow_ٹکڑا_u8 ind_cpa_secret_کلید = uu____0.fst;
  Eurydice_borrow_ٹکڑا_u8 secret_key0 = uu____0.snd;
  Eurydice_borrow_ٹکڑا_u8_x2
  uu____1 =
    Eurydice_ٹکڑا_ونڈو_at(secret_key0,
      (ناپ_t)1184U,
      uint8_t,
      Eurydice_borrow_ٹکڑا_u8_x2);
  Eurydice_borrow_ٹکڑا_u8 ind_cpa_عوامی_کلید = uu____1.fst;
  Eurydice_borrow_ٹکڑا_u8 secret_کلید = uu____1.snd;
  Eurydice_borrow_ٹکڑا_u8_x2
  uu____2 =
    Eurydice_ٹکڑا_ونڈو_at(secret_کلید,
      LIBCRUX_ML_KEM_CONSTANTS_H_DIGEST_ناپ,
      uint8_t,
      Eurydice_borrow_ٹکڑا_u8_x2);
  Eurydice_borrow_ٹکڑا_u8 ind_cpa_عوامی_کلید_hash = uu____2.fst;
  Eurydice_borrow_ٹکڑا_u8 implicit_rejection_قدر = uu____2.snd;
  أرجع
    (
      KRML_CLITERAL(Eurydice_borrow_ٹکڑا_u8_x4){
        .fst = ind_cpa_secret_کلید,
        .snd = ind_cpa_عوامی_کلید,
        .thd = ind_cpa_عوامی_کلید_hash,
        .f3 = implicit_rejection_قدر
      }
    );
}

#إذا defined(__cplusplus)
}
#جے_انت

#تعریف_کرو libcrux_mlkem_core_H_DEFINED
#جے_انت /* libcrux_mlkem_core_H */

/* from libcrux/combined_extraction/generated/libcrux_mldsa_core.h */
/*
 * SPDX-FileCopyrightText: 2025 Cryspen Sarl <info@cryspen.com>
 *
 * SPDX-License-Identifier: MIT or Apache-2.0
 *
 * This code was generated with the following revisions:
 * Charon: e656e17bff6ca5efac8ab6919b9b74cb9a8dd8ad
 * Eurydice: aaa9fa657fb6f09802edb890252040d94cd93982
 * Karamel: 8c19d41458ce5cbfea029ebc03334ba96d149039
 * F*: unset
 * Libcrux: c4e5e5e511bbc4c53f826163f57bfd10e9228911
 */


#جے_بنا_تعریف libcrux_mldsa_core_H
#تعریف_کرو libcrux_mldsa_core_H



#إذا defined(__cplusplus)
خارجي "C" {
#جے_انت


#تعریف_کرو libcrux_ml_dsa_constants_Eta_Two 2
#تعریف_کرو libcrux_ml_dsa_constants_Eta_Four 4

تعريفنوع uint8_t libcrux_ml_dsa_constants_Eta;

#تعریف_کرو LIBCRUX_ML_DSA_SIMD_TRAITS_COEFFICIENTS_وچ_SIMD_UNIT ((ناپ_t)8U)

#تعریف_کرو LIBCRUX_ML_DSA_SIMD_TRAITS_SIMD_UNITS_وچ_RING_ELEMENT ((ناپ_t)32U)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_بٹ_وچ_ہیٹھلا_PART_دا_T ((ناپ_t)13U)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_میدان_MODULUS_MINUS_ONE_ثنائی_ہندسہ_لمائی ((ناپ_t)23U)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_بٹ_وچ_اتلا_PART_دا_T (LIBCRUX_ML_DSA_CONSTANTS_میدان_MODULUS_MINUS_ONE_ثنائی_ہندسہ_لمائی - LIBCRUX_ML_DSA_CONSTANTS_بٹ_وچ_ہیٹھلا_PART_دا_T)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_بائٹاں_FOR_VERIFICATION_کلید_HASH ((ناپ_t)64U)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_وچ_RING_ELEMENT ((ناپ_t)256U)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_CONTEXT_MAX_LEN ((ناپ_t)255U)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_میدان_MODULUS (8380417)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_GAMMA2_V261_888 (261888)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_GAMMA2_V95_232 (95232)

تعريفنوع int32_t libcrux_ml_dsa_constants_Gamma2;

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_کلید_GENERATION_RANDOMNESS_ناپ ((ناپ_t)32U)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_نقاب_بیج_ناپ ((ناپ_t)64U)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_سنیہا_REPRESENTATIVE_ناپ ((ناپ_t)64U)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_REJECTION_SAMPLE_BOUND_SIGN ((ناپ_t)814U)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_دا_T0_S_ناپ (LIBCRUX_ML_DSA_CONSTANTS_بٹ_وچ_ہیٹھلا_PART_دا_T * LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_وچ_RING_ELEMENT / (ناپ_t)8U)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_دا_T1_S_ناپ (LIBCRUX_ML_DSA_CONSTANTS_بٹ_وچ_اتلا_PART_دا_T * LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_وچ_RING_ELEMENT / (ناپ_t)8U)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_بیج_FOR_A_ناپ ((ناپ_t)32U)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_بیج_FOR_ERROR_VECTORS_ناپ ((ناپ_t)64U)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_بیج_FOR_SIGNING_ناپ ((ناپ_t)32U)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_SIGNING_RANDOMNESS_ناپ ((ناپ_t)32U)

ساكن مضمن int32_t
libcrux_ml_dsa_constants_beta(
  ناپ_t ones_وچ_verifier_challenge,
  libcrux_ml_dsa_constants_Eta eta
)
{
  ناپ_t eta_val;
  بدل (eta)
  {
    حالة libcrux_ml_dsa_constants_Eta_Two:
      {
        eta_val = (ناپ_t)2U;
        اكسر;
      }
    حالة libcrux_ml_dsa_constants_Eta_Four:
      {
        eta_val = (ناپ_t)4U;
        اكسر;
      }
    افتراضي:
      {
        KRML_HOST_EPRINTF("KaRaMeL incomplete match at %s:%d\n", __FILE__, __LINE__);
        KRML_HOST_EXIT(253U);
      }
  }
  أرجع (int32_t)(ones_وچ_verifier_challenge * eta_val);
}

ساكن مضمن ناپ_t
libcrux_ml_dsa_constants_commitment_ring_element_ناپ(ناپ_t بٹ_فی_commitment_coefficient)
{
  أرجع
    بٹ_فی_commitment_coefficient * LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_وچ_RING_ELEMENT /
      (ناپ_t)8U;
}

ساكن مضمن ناپ_t
libcrux_ml_dsa_constants_commitment_سمتیہ_ناپ(
  ناپ_t بٹ_فی_commitment_coefficient,
  ناپ_t صفاں_وچ_a
)
{
  أرجع
    libcrux_ml_dsa_constants_commitment_ring_element_ناپ(بٹ_فی_commitment_coefficient) *
      صفاں_وچ_a;
}

ساكن مضمن ناپ_t
libcrux_ml_dsa_constants_error_ring_element_ناپ(ناپ_t بٹ_فی_error_coefficient)
{
  أرجع
    بٹ_فی_error_coefficient * LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_وچ_RING_ELEMENT / (ناپ_t)8U;
}

ساكن مضمن ناپ_t
libcrux_ml_dsa_constants_gamma1_ring_element_ناپ(ناپ_t بٹ_فی_gamma1_coefficient)
{
  أرجع
    بٹ_فی_gamma1_coefficient * LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_وچ_RING_ELEMENT /
      (ناپ_t)8U;
}

ساكن مضمن ناپ_t
libcrux_ml_dsa_constants_signature_ناپ(
  ناپ_t صفاں_وچ_a,
  ناپ_t columns_وچ_a,
  ناپ_t max_ones_وچ_hint,
  ناپ_t commitment_hash_ناپ,
  ناپ_t بٹ_فی_gamma1_coefficient
)
{
  أرجع
    commitment_hash_ناپ +
      columns_وچ_a * libcrux_ml_dsa_constants_gamma1_ring_element_ناپ(بٹ_فی_gamma1_coefficient)
    + max_ones_وچ_hint
    + صفاں_وچ_a;
}

ساكن مضمن ناپ_t
libcrux_ml_dsa_constants_signing_کلید_ناپ(
  ناپ_t صفاں_وچ_a,
  ناپ_t columns_وچ_a,
  ناپ_t error_ring_element_ناپ
)
{
  أرجع
    LIBCRUX_ML_DSA_CONSTANTS_بیج_FOR_A_ناپ + LIBCRUX_ML_DSA_CONSTANTS_بیج_FOR_SIGNING_ناپ +
      LIBCRUX_ML_DSA_CONSTANTS_بائٹاں_FOR_VERIFICATION_کلید_HASH
    + (صفاں_وچ_a + columns_وچ_a) * error_ring_element_ناپ
    + صفاں_وچ_a * LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_دا_T0_S_ناپ;
}

ساكن مضمن ناپ_t libcrux_ml_dsa_constants_verification_کلید_ناپ(ناپ_t صفاں_وچ_a)
{
  أرجع
    LIBCRUX_ML_DSA_CONSTANTS_بیج_FOR_A_ناپ +
      LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_وچ_RING_ELEMENT * صفاں_وچ_a *
        (LIBCRUX_ML_DSA_CONSTANTS_میدان_MODULUS_MINUS_ONE_ثنائی_ہندسہ_لمائی -
          LIBCRUX_ML_DSA_CONSTANTS_بٹ_وچ_ہیٹھلا_PART_دا_T)
      / (ناپ_t)8U;
}

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_بٹ_فی_COMMITMENT_COEFFICIENT ((ناپ_t)6U)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_بٹ_فی_ERROR_COEFFICIENT ((ناپ_t)3U)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_بٹ_فی_GAMMA1_COEFFICIENT ((ناپ_t)18U)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_وچ_A ((ناپ_t)4U)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COMMITMENT_HASH_ناپ ((ناپ_t)32U)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ETA (libcrux_ml_dsa_constants_Eta_Two)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_GAMMA1_EXPONENT ((ناپ_t)17U)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_GAMMA2 ((LIBCRUX_ML_DSA_CONSTANTS_میدان_MODULUS - 1) / 88)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_MAX_ONES_وچ_HINT ((ناپ_t)80U)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ONES_وچ_VERIFIER_CHALLENGE ((ناپ_t)39U)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_صفاں_وچ_A ((ناپ_t)4U)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_بٹ_فی_COMMITMENT_COEFFICIENT ((ناپ_t)4U)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_بٹ_فی_ERROR_COEFFICIENT ((ناپ_t)4U)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_بٹ_فی_GAMMA1_COEFFICIENT ((ناپ_t)20U)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_وچ_A ((ناپ_t)5U)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COMMITMENT_HASH_ناپ ((ناپ_t)48U)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ETA (libcrux_ml_dsa_constants_Eta_Four)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA1_EXPONENT ((ناپ_t)19U)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA2 ((LIBCRUX_ML_DSA_CONSTANTS_میدان_MODULUS - 1) / 32)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_MAX_ONES_وچ_HINT ((ناپ_t)55U)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ONES_وچ_VERIFIER_CHALLENGE ((ناپ_t)49U)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_صفاں_وچ_A ((ناپ_t)6U)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_بٹ_فی_COMMITMENT_COEFFICIENT ((ناپ_t)4U)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_بٹ_فی_ERROR_COEFFICIENT ((ناپ_t)3U)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_بٹ_فی_GAMMA1_COEFFICIENT ((ناپ_t)20U)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_وچ_A ((ناپ_t)7U)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COMMITMENT_HASH_ناپ ((ناپ_t)64U)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ETA (libcrux_ml_dsa_constants_Eta_Two)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_GAMMA1_EXPONENT ((ناپ_t)19U)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_GAMMA2 ((LIBCRUX_ML_DSA_CONSTANTS_میدان_MODULUS - 1) / 32)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_MAX_ONES_وچ_HINT ((ناپ_t)75U)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ONES_وچ_VERIFIER_CHALLENGE ((ناپ_t)60U)

#تعریف_کرو LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_صفاں_وچ_A ((ناپ_t)8U)

/**
This function found in impl {core::clone::Clone for libcrux_ml_dsa::constants::Eta}
*/
ساكن مضمن libcrux_ml_dsa_constants_Eta
libcrux_ml_dsa_constants_clone_54(ثابت libcrux_ml_dsa_constants_Eta *self)
{
  أرجع self[0U];
}

ساكن KRML_MUSTINLINE ناپ_t
libcrux_ml_dsa_encoding_error_chunk_ناپ(libcrux_ml_dsa_constants_Eta eta)
{
  بدل (eta)
  {
    حالة libcrux_ml_dsa_constants_Eta_Two:
      {
        اكسر;
      }
    حالة libcrux_ml_dsa_constants_Eta_Four:
      {
        أرجع (ناپ_t)4U;
      }
    افتراضي:
      {
        KRML_HOST_EPRINTF("KaRaMeL incomplete match at %s:%d\n", __FILE__, __LINE__);
        KRML_HOST_EXIT(253U);
      }
  }
  أرجع (ناپ_t)3U;
}

#تعریف_کرو libcrux_ml_dsa_types_VerificationError_MalformedHintError 0
#تعریف_کرو libcrux_ml_dsa_types_VerificationError_SignerResponseExceedsBoundError 1
#تعریف_کرو libcrux_ml_dsa_types_Verification_Error_Commitment_Hashes_Dont_میل_Error 2
#تعریف_کرو libcrux_ml_dsa_types_VerificationError_VerificationContextTooLongError 3

تعريفنوع uint8_t libcrux_ml_dsa_types_VerificationError;

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_encoding_signature_سیٹ_hint(
  Eurydice_dst_ref_mut_20 باہرلا_hint,
  ناپ_t i,
  ناپ_t j
)
{
  باہرلا_hint.ptr[i].انکڑے[j] = 1;
}

#تعریف_کرو LIBCRUX_ML_DSA_ENCODING_T0_OUTPUT_بائٹاں_فی_SIMD_UNIT ((ناپ_t)13U)

#تعریف_کرو LIBCRUX_ML_DSA_ENCODING_T1_DESERIALIZE_کھڑکی ((ناپ_t)10U)

#تعریف_کرو LIBCRUX_ML_DSA_ENCODING_T1_SERIALIZE_OUTPUT_بائٹاں_فی_SIMD_UNIT ((ناپ_t)10U)

#تعریف_کرو LIBCRUX_ML_DSA_HASH_FUNCTIONS_SHAKE128_بلاک_ناپ ((ناپ_t)168U)

#تعریف_کرو LIBCRUX_ML_DSA_HASH_FUNCTIONS_SHAKE128_FIVE_بلاکاں_ناپ (LIBCRUX_ML_DSA_HASH_FUNCTIONS_SHAKE128_بلاک_ناپ * (ناپ_t)5U)

#تعریف_کرو LIBCRUX_ML_DSA_HASH_FUNCTIONS_SHAKE256_بلاک_ناپ ((ناپ_t)136U)

ساكن KRML_MUSTINLINE Eurydice_arr_91
libcrux_ml_dsa_sample_جوڑو_error_domain_separator(
  Eurydice_borrow_ٹکڑا_u8 ٹکڑا,
  uint16_t domain_separator
)
{
  Eurydice_arr_91 باہرلا = { .انکڑے = { 0U } };
  Eurydice_ٹکڑا_copy(Eurydice_array_منزل_subslice_mut_d4(&باہرلا,
      (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = (ناپ_t)0U, .سرا = ٹکڑا.meta })),
    ٹکڑا,
    uint8_t);
  باہرلا.انکڑے[64U] = (uint8_t)(uint32_t)domain_separator;
  باہرلا.انکڑے[65U] = (uint8_t)((uint32_t)domain_separator >> 8U & 0xFFFFU);
  أرجع باہرلا;
}

#تعریف_کرو LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_ERROR_RING_ELEMENT_ناپ (libcrux_ml_dsa_constants_error_ring_element_ناپ(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_بٹ_فی_ERROR_COEFFICIENT))

#تعریف_کرو LIBCRUX_ML_DSA_SIMD_TRAITS_میدان_MODULUS (8380417)

#تعریف_کرو LIBCRUX_ML_DSA_SIMD_TRAITS_INVERSE_دا_MODULUS_MOD_MONTGOMERY_R (58728449ULL)

ساكن مضمن uint8_t_x2
libcrux_ml_dsa_sample_sample_اتے_منزل_four_ring_elements_flat_xy(ناپ_t index, ناپ_t چوڑائی)
{
  أرجع
    (KRML_CLITERAL(uint8_t_x2){ .fst = (uint8_t)(index / چوڑائی), .snd = (uint8_t)(index % چوڑائی) });
}

ساكن KRML_MUSTINLINE uint16_t libcrux_ml_dsa_sample_generate_domain_separator(uint8_t_x2 _)
{
  uint8_t صف = _.fst;
  uint8_t کالم = _.snd;
  أرجع (uint32_t)(uint16_t)(uint32_t)کالم | (uint32_t)(uint16_t)(uint32_t)صف << 8U;
}

ساكن KRML_MUSTINLINE Eurydice_arr_31
libcrux_ml_dsa_sample_جوڑو_domain_separator(Eurydice_borrow_ٹکڑا_u8 ٹکڑا, uint8_t_x2 indices)
{
  Eurydice_arr_31 باہرلا = { .انکڑے = { 0U } };
  Eurydice_ٹکڑا_copy(Eurydice_array_منزل_subslice_mut_d40(&باہرلا,
      (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = (ناپ_t)0U, .سرا = ٹکڑا.meta })),
    ٹکڑا,
    uint8_t);
  uint16_t domain_separator = libcrux_ml_dsa_sample_generate_domain_separator(indices);
  باہرلا.انکڑے[32U] = (uint8_t)(uint32_t)domain_separator;
  باہرلا.انکڑے[33U] = (uint8_t)((uint32_t)domain_separator >> 8U & 0xFFFFU);
  أرجع باہرلا;
}

#تعریف_کرو libcrux_ml_dsa_types_SigningError_RejectionSamplingError 0
#تعریف_کرو libcrux_ml_dsa_types_SigningError_ContextTooLongError 1

تعريفنوع uint8_t libcrux_ml_dsa_types_SigningError;

تعريفنوع بنية libcrux_ml_dsa_pre_hash_DomainSeparationContext_s
{
  Eurydice_borrow_ٹکڑا_u8 context;
  core_option_Option_57 pre_hash_oid;
}
libcrux_ml_dsa_pre_hash_DomainSeparationContext;

#تعریف_کرو libcrux_ml_dsa_pre_hash_DomainSeparationError_ContextTooLongError 0

تعريفنوع uint8_t libcrux_ml_dsa_pre_hash_DomainSeparationError;

/**
A monomorphic instance of core.result.Result
with types libcrux_ml_dsa_pre_hash_DomainSeparationContext, libcrux_ml_dsa_pre_hash_DomainSeparationError

*/
تعريفنوع بنية core_نتیجہ_نتیجہ_a8_s
{
  core_نتیجہ_نتیجہ_57_ٹیگ_سوچی ٹیگ;
  اتحاد {
    libcrux_ml_dsa_pre_hash_DomainSeparationContext case_Ok;
    libcrux_ml_dsa_pre_hash_DomainSeparationError case_Err;
  }
  val;
}
core_نتیجہ_نتیجہ_a8;

/**
 `context` must be at most 255 bytes long.
*/
/**
This function found in impl {libcrux_ml_dsa::pre_hash::DomainSeparationContext<'a>}
*/
ساكن مضمن core_نتیجہ_نتیجہ_a8
libcrux_ml_dsa_pre_hash_new_88(
  Eurydice_borrow_ٹکڑا_u8 context,
  core_option_Option_57 pre_hash_oid
)
{
  إذا (!(context.meta > LIBCRUX_ML_DSA_CONSTANTS_CONTEXT_MAX_LEN))
  {
    أرجع
      (
        KRML_CLITERAL(core_نتیجہ_نتیجہ_a8){
          .ٹیگ = core_نتیجہ_Ok,
          .val = { .case_Ok = { .context = context, .pre_hash_oid = pre_hash_oid } }
        }
      );
  }
  أرجع
    (
      KRML_CLITERAL(core_نتیجہ_نتیجہ_a8){
        .ٹیگ = core_نتیجہ_Err,
        .val = { .case_Err = libcrux_ml_dsa_pre_hash_DomainSeparationError_ContextTooLongError }
      }
    );
}

/**
 Returns the pre-hash OID, if any.
*/
/**
This function found in impl {libcrux_ml_dsa::pre_hash::DomainSeparationContext<'a>}
*/
ساكن مضمن ثابت
core_option_Option_57
*libcrux_ml_dsa_pre_hash_pre_hash_oid_88(
  ثابت libcrux_ml_dsa_pre_hash_DomainSeparationContext *self
)
{
  أرجع &self->pre_hash_oid;
}

/**
 Returns the context, guaranteed to be at most 255 bytes long.
*/
/**
This function found in impl {libcrux_ml_dsa::pre_hash::DomainSeparationContext<'a>}
*/
ساكن مضمن Eurydice_borrow_ٹکڑا_u8
libcrux_ml_dsa_pre_hash_context_88(ثابت libcrux_ml_dsa_pre_hash_DomainSeparationContext *self)
{
  أرجع self->context;
}

#تعریف_کرو LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_COMMITMENT_RING_ELEMENT_ناپ (libcrux_ml_dsa_constants_commitment_ring_element_ناپ(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_بٹ_فی_COMMITMENT_COEFFICIENT))

ساكن KRML_MUSTINLINE bool
libcrux_ml_dsa_sample_inside_باہرلا_shuffle(
  Eurydice_borrow_ٹکڑا_u8 randomness,
  ناپ_t *باہرلا_اشاریہ,
  uint64_t *signs,
  Eurydice_arr_6c *نتیجہ
)
{
  bool پورا = false;
  لكل (ناپ_t i = (ناپ_t)0U; i < randomness.meta; i++)
  {
    ناپ_t _cloop_j = i;
    ثابت uint8_t *byte = &randomness.ptr[_cloop_j];
    إذا (!پورا)
    {
      ناپ_t sample_at = (ناپ_t)(uint32_t)byte[0U];
      إذا (sample_at <= باہرلا_اشاریہ[0U])
      {
        نتیجہ->انکڑے[باہرلا_اشاریہ[0U]] = نتیجہ->انکڑے[sample_at];
        باہرلا_اشاریہ[0U]++;
        نتیجہ->انکڑے[sample_at] = 1 - 2 * (int32_t)(signs[0U] & 1ULL);
        signs[0U] >>= 1U;
      }
      پورا = باہرلا_اشاریہ[0U] == (ناپ_t)256U;
    }
  }
  أرجع پورا;
}

#تعریف_کرو LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_BETA (libcrux_ml_dsa_constants_beta(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ONES_وچ_VERIFIER_CHALLENGE, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ETA))

#تعریف_کرو LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_GAMMA1_RING_ELEMENT_ناپ (libcrux_ml_dsa_constants_gamma1_ring_element_ناپ(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_بٹ_فی_GAMMA1_COEFFICIENT))

#تعریف_کرو LIBCRUX_ML_DSA_PRE_HASH_SHAKE128_OID ((KRML_CLITERAL(Eurydice_arr_c9){ .انکڑے = { 6U, 9U, 96U, 134U, 72U, 1U, 101U, 3U, 4U, 2U, 11U } }))

/**
This function found in impl {libcrux_ml_dsa::pre_hash::PreHash for libcrux_ml_dsa::pre_hash::SHAKE128_PH}
*/
ساكن مضمن Eurydice_arr_c9 libcrux_ml_dsa_pre_hash_oid_30(فراغ)
{
  أرجع LIBCRUX_ML_DSA_PRE_HASH_SHAKE128_OID;
}

#تعریف_کرو LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_VERIFICATION_کلید_ناپ (libcrux_ml_dsa_constants_verification_کلید_ناپ(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_صفاں_وچ_A))

#تعریف_کرو LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_SIGNATURE_ناپ (libcrux_ml_dsa_constants_signature_ناپ(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_صفاں_وچ_A, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_وچ_A, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_MAX_ONES_وچ_HINT, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COMMITMENT_HASH_ناپ, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_بٹ_فی_GAMMA1_COEFFICIENT))

تعريفنوع Eurydice_arr_4d libcrux_ml_dsa_simd_portable_سمتیہ_type_Coefficients;

ساكن KRML_MUSTINLINE Eurydice_arr_4d libcrux_ml_dsa_simd_portable_سمتیہ_type_zero(فراغ)
{
  أرجع (KRML_CLITERAL(Eurydice_arr_4d){ .انکڑے = { 0U } });
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ساكن مضمن Eurydice_arr_4d libcrux_ml_dsa_simd_portable_zero_65(فراغ)
{
  أرجع libcrux_ml_dsa_simd_portable_سمتیہ_type_zero();
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_سمتیہ_type_from_coefficient_array(
  Eurydice_dst_ref_shared_83 array,
  Eurydice_arr_4d *باہرلا
)
{
  Eurydice_ٹکڑا_copy(Eurydice_array_منزل_ٹکڑا_mut_fd(باہرلا),
    Eurydice_ٹکڑا_subslice_shared_47(array,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .شروع = (ناپ_t)0U,
          .سرا = LIBCRUX_ML_DSA_SIMD_TRAITS_COEFFICIENTS_وچ_SIMD_UNIT
        }
      )),
    int32_t);
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ساكن مضمن فراغ
libcrux_ml_dsa_simd_portable_from_coefficient_array_65(
  Eurydice_dst_ref_shared_83 array,
  Eurydice_arr_4d *باہرلا
)
{
  libcrux_ml_dsa_simd_portable_سمتیہ_type_from_coefficient_array(array, باہرلا);
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_سمتیہ_type_منزل_coefficient_array(
  ثابت Eurydice_arr_4d *قدر,
  Eurydice_dst_ref_mut_83 باہرلا
)
{
  Eurydice_ٹکڑا_copy(باہرلا, Eurydice_array_منزل_ٹکڑا_shared_fd(قدر), int32_t);
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ساكن مضمن فراغ
libcrux_ml_dsa_simd_portable_منزل_coefficient_array_65(
  ثابت Eurydice_arr_4d *قدر,
  Eurydice_dst_ref_mut_83 باہرلا
)
{
  libcrux_ml_dsa_simd_portable_سمتیہ_type_منزل_coefficient_array(قدر, باہرلا);
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_arithmetic_جوڑو(Eurydice_arr_4d *lhs, ثابت Eurydice_arr_4d *rhs)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)8U; i++)
  {
    ناپ_t i0 = i;
    ناپ_t uu____0 = i0;
    lhs->انکڑے[uu____0] += rhs->انکڑے[i0];
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ساكن مضمن فراغ
libcrux_ml_dsa_simd_portable_جوڑو_65(Eurydice_arr_4d *lhs, ثابت Eurydice_arr_4d *rhs)
{
  libcrux_ml_dsa_simd_portable_arithmetic_جوڑو(lhs, rhs);
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_arithmetic_گھٹاؤ(
  Eurydice_arr_4d *lhs,
  ثابت Eurydice_arr_4d *rhs
)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)8U; i++)
  {
    ناپ_t i0 = i;
    ناپ_t uu____0 = i0;
    lhs->انکڑے[uu____0] -= rhs->انکڑے[i0];
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ساكن مضمن فراغ
libcrux_ml_dsa_simd_portable_گھٹاؤ_65(Eurydice_arr_4d *lhs, ثابت Eurydice_arr_4d *rhs)
{
  libcrux_ml_dsa_simd_portable_arithmetic_گھٹاؤ(lhs, rhs);
}

ساكن KRML_MUSTINLINE bool
libcrux_ml_dsa_simd_portable_arithmetic_infinity_norm_exceeds(
  ثابت Eurydice_arr_4d *simd_unit,
  int32_t bound
)
{
  bool نتیجہ = false;
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)8U; i++)
  {
    ناپ_t i0 = i;
    int32_t coefficient = simd_unit->انکڑے[i0];
    int32_t sign = coefficient >> 31U;
    int32_t normalized = coefficient - (sign & 2 * coefficient);
    bool uu____0;
    إذا (نتیجہ)
    {
      uu____0 = true;
    }
    وإلا
    {
      uu____0 = normalized >= bound;
    }
    نتیجہ = uu____0;
  }
  أرجع نتیجہ;
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ساكن مضمن bool
libcrux_ml_dsa_simd_portable_infinity_norm_exceeds_65(
  ثابت Eurydice_arr_4d *simd_unit,
  int32_t bound
)
{
  أرجع libcrux_ml_dsa_simd_portable_arithmetic_infinity_norm_exceeds(simd_unit, bound);
}

ساكن KRML_MUSTINLINE int32_t_x2
libcrux_ml_dsa_simd_portable_arithmetic_decompose_element(int32_t gamma2, int32_t r)
{
  int32_t r0 = r + (r >> 31U & LIBCRUX_ML_DSA_SIMD_TRAITS_میدان_MODULUS);
  int32_t ceil_دا_r_by_128 = (r0 + 127) >> 7U;
  int32_t r1;
  بدل (gamma2)
  {
    حالة 95232:
      {
        int32_t نتیجہ = (ceil_دا_r_by_128 * 11275 + (int32_t)((uint32_t)1 << 23U)) >> 24U;
        int32_t نتیجہ_0 = (نتیجہ ^ (43 - نتیجہ) >> 31U) & نتیجہ;
        r1 = نتیجہ_0;
        اكسر;
      }
    حالة 261888:
      {
        int32_t نتیجہ = (ceil_دا_r_by_128 * 1025 + (int32_t)((uint32_t)1 << 21U)) >> 22U;
        int32_t نتیجہ_0 = نتیجہ & 15;
        r1 = نتیجہ_0;
        اكسر;
      }
    افتراضي:
      {
        KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __FILE__, __LINE__, "panic!");
        KRML_HOST_EXIT(255U);
      }
  }
  int32_t alpha = gamma2 * 2;
  int32_t r00 = r0 - r1 * alpha;
  r00 -=
    ((LIBCRUX_ML_DSA_SIMD_TRAITS_میدان_MODULUS - 1) / 2 - r00) >> 31U &
      LIBCRUX_ML_DSA_SIMD_TRAITS_میدان_MODULUS;
  أرجع (KRML_CLITERAL(int32_t_x2){ .fst = r00, .snd = r1 });
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_arithmetic_decompose(
  int32_t gamma2,
  ثابت Eurydice_arr_4d *simd_unit,
  Eurydice_arr_4d *کم,
  Eurydice_arr_4d *بلند
)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)8U; i++)
  {
    ناپ_t i0 = i;
    int32_t_x2
    uu____0 =
      libcrux_ml_dsa_simd_portable_arithmetic_decompose_element(gamma2,
        simd_unit->انکڑے[i0]);
    int32_t uu____1 = uu____0.snd;
    کم->انکڑے[i0] = uu____0.fst;
    بلند->انکڑے[i0] = uu____1;
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ساكن مضمن فراغ
libcrux_ml_dsa_simd_portable_decompose_65(
  int32_t gamma2,
  ثابت Eurydice_arr_4d *simd_unit,
  Eurydice_arr_4d *کم,
  Eurydice_arr_4d *بلند
)
{
  libcrux_ml_dsa_simd_portable_arithmetic_decompose(gamma2, simd_unit, کم, بلند);
}

ساكن KRML_MUSTINLINE int32_t
libcrux_ml_dsa_simd_portable_arithmetic_compute_one_hint(
  int32_t کم,
  int32_t بلند,
  int32_t gamma2
)
{
  int32_t uu____0;
  إذا (کم > gamma2)
  {
    uu____0 = 1;
  }
  وإلا إذا (کم < -gamma2)
  {
    uu____0 = 1;
  }
  وإلا إذا (کم == -gamma2)
  {
    إذا (بلند != 0)
    {
      uu____0 = 1;
    }
    وإلا
    {
      uu____0 = 0;
    }
  }
  وإلا
  {
    uu____0 = 0;
  }
  أرجع uu____0;
}

ساكن KRML_MUSTINLINE ناپ_t
libcrux_ml_dsa_simd_portable_arithmetic_compute_hint(
  ثابت Eurydice_arr_4d *کم,
  ثابت Eurydice_arr_4d *بلند,
  int32_t gamma2,
  Eurydice_arr_4d *hint
)
{
  ناپ_t one_hints_گنتی = (ناپ_t)0U;
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)8U; i++)
  {
    ناپ_t i0 = i;
    hint->انکڑے[i0] =
      libcrux_ml_dsa_simd_portable_arithmetic_compute_one_hint(کم->انکڑے[i0],
        بلند->انکڑے[i0],
        gamma2);
    one_hints_گنتی += (ناپ_t)hint->انکڑے[i0];
  }
  أرجع one_hints_گنتی;
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ساكن مضمن ناپ_t
libcrux_ml_dsa_simd_portable_compute_hint_65(
  ثابت Eurydice_arr_4d *کم,
  ثابت Eurydice_arr_4d *بلند,
  int32_t gamma2,
  Eurydice_arr_4d *hint
)
{
  أرجع libcrux_ml_dsa_simd_portable_arithmetic_compute_hint(کم, بلند, gamma2, hint);
}

ساكن KRML_MUSTINLINE int32_t
libcrux_ml_dsa_simd_portable_arithmetic_use_one_hint(int32_t gamma2, int32_t r, int32_t hint)
{
  int32_t_x2 uu____0 = libcrux_ml_dsa_simd_portable_arithmetic_decompose_element(gamma2, r);
  int32_t r0 = uu____0.fst;
  int32_t r1 = uu____0.snd;
  int32_t uu____1;
  إذا (!(hint == 0))
  {
    بدل (gamma2)
    {
      حالة 95232:
        {
          إذا (r0 > 0)
          {
            إذا (r1 == 43)
            {
              uu____1 = 0;
            }
            وإلا
            {
              uu____1 = r1 + hint;
            }
          }
          وإلا إذا (r1 == 0)
          {
            uu____1 = 43;
          }
          وإلا
          {
            uu____1 = r1 - hint;
          }
          اكسر;
        }
      حالة 261888:
        {
          إذا (r0 > 0)
          {
            uu____1 = (r1 + hint) & 15;
          }
          وإلا
          {
            uu____1 = (r1 - hint) & 15;
          }
          اكسر;
        }
      افتراضي:
        {
          KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __FILE__, __LINE__, "panic!");
          KRML_HOST_EXIT(255U);
        }
    }
    أرجع uu____1;
  }
  أرجع r1;
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_arithmetic_use_hint(
  int32_t gamma2,
  ثابت Eurydice_arr_4d *simd_unit,
  Eurydice_arr_4d *hint
)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)8U; i++)
  {
    ناپ_t i0 = i;
    int32_t
    uu____0 =
      libcrux_ml_dsa_simd_portable_arithmetic_use_one_hint(gamma2,
        simd_unit->انکڑے[i0],
        hint->انکڑے[i0]);
    hint->انکڑے[i0] = uu____0;
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ساكن مضمن فراغ
libcrux_ml_dsa_simd_portable_use_hint_65(
  int32_t gamma2,
  ثابت Eurydice_arr_4d *simd_unit,
  Eurydice_arr_4d *hint
)
{
  libcrux_ml_dsa_simd_portable_arithmetic_use_hint(gamma2, simd_unit, hint);
}

ساكن KRML_MUSTINLINE uint64_t
libcrux_ml_dsa_simd_portable_arithmetic_get_n_گھٹ_توں_گھٹ_significant_بٹ(uint8_t n, uint64_t قدر)
{
  أرجع قدر & ((1ULL << (uint32_t)n) - 1ULL);
}

#تعریف_کرو LIBCRUX_ML_DSA_SIMD_PORTABLE_ARITHMETIC_MONTGOMERY_کھسکاؤ (32U)

ساكن KRML_MUSTINLINE int32_t
libcrux_ml_dsa_simd_portable_arithmetic_montgomery_reduce_element(int64_t قدر)
{
  uint64_t
  t =
    libcrux_ml_dsa_simd_portable_arithmetic_get_n_گھٹ_توں_گھٹ_significant_بٹ(LIBCRUX_ML_DSA_SIMD_PORTABLE_ARITHMETIC_MONTGOMERY_کھسکاؤ,
      (uint64_t)قدر)
    * LIBCRUX_ML_DSA_SIMD_TRAITS_INVERSE_دا_MODULUS_MOD_MONTGOMERY_R;
  int32_t
  k =
    (int32_t)libcrux_ml_dsa_simd_portable_arithmetic_get_n_گھٹ_توں_گھٹ_significant_بٹ(LIBCRUX_ML_DSA_SIMD_PORTABLE_ARITHMETIC_MONTGOMERY_کھسکاؤ,
      t);
  int64_t k_times_modulus = (int64_t)k * (int64_t)LIBCRUX_ML_DSA_SIMD_TRAITS_میدان_MODULUS;
  int32_t
  c =
    (int32_t)(k_times_modulus >> (uint32_t)LIBCRUX_ML_DSA_SIMD_PORTABLE_ARITHMETIC_MONTGOMERY_کھسکاؤ);
  int32_t
  قدر_بلند =
    (int32_t)(قدر >> (uint32_t)LIBCRUX_ML_DSA_SIMD_PORTABLE_ARITHMETIC_MONTGOMERY_کھسکاؤ);
  أرجع قدر_بلند - c;
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply(
  Eurydice_arr_4d *lhs,
  ثابت Eurydice_arr_4d *rhs
)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)8U; i++)
  {
    ناپ_t i0 = i;
    lhs->انکڑے[i0] =
      libcrux_ml_dsa_simd_portable_arithmetic_montgomery_reduce_element((int64_t)lhs->انکڑے[i0] *
          (int64_t)rhs->انکڑے[i0]);
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ساكن مضمن فراغ
libcrux_ml_dsa_simd_portable_montgomery_multiply_65(
  Eurydice_arr_4d *lhs,
  ثابت Eurydice_arr_4d *rhs
)
{
  libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply(lhs, rhs);
}

ساكن KRML_MUSTINLINE int32_t
libcrux_ml_dsa_simd_portable_arithmetic_barrett_reduce_element(int32_t fe)
{
  int32_t quotient = (fe + (int32_t)((uint32_t)1 << 22U)) >> 23U;
  أرجع fe - quotient * LIBCRUX_ML_DSA_SIMD_TRAITS_میدان_MODULUS;
}

ساكن مضمن فراغ
libcrux_ml_dsa_simd_portable_arithmetic_barrett_reduce_simd_unit(Eurydice_arr_4d *simd_unit)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)8U; i++)
  {
    ناپ_t i0 = i;
    simd_unit->انکڑے[i0] =
      libcrux_ml_dsa_simd_portable_arithmetic_barrett_reduce_element(simd_unit->انکڑے[i0]);
  }
}

ساكن KRML_MUSTINLINE int32_t_x2
libcrux_ml_dsa_simd_portable_arithmetic_power2round_element(int32_t t)
{
  int32_t t2 = t + (t >> 31U & LIBCRUX_ML_DSA_SIMD_TRAITS_میدان_MODULUS);
  int32_t
  t1 =
    (t2 - 1 +
      (int32_t)((uint32_t)1 <<
        (uint32_t)(LIBCRUX_ML_DSA_CONSTANTS_بٹ_وچ_ہیٹھلا_PART_دا_T - (ناپ_t)1U)))
    >> (uint32_t)LIBCRUX_ML_DSA_CONSTANTS_بٹ_وچ_ہیٹھلا_PART_دا_T;
  int32_t
  t0 = t2 - (int32_t)((uint32_t)t1 << (uint32_t)LIBCRUX_ML_DSA_CONSTANTS_بٹ_وچ_ہیٹھلا_PART_دا_T);
  أرجع (KRML_CLITERAL(int32_t_x2){ .fst = t0, .snd = t1 });
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_arithmetic_power2round(Eurydice_arr_4d *t0, Eurydice_arr_4d *t1)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)8U; i++)
  {
    ناپ_t i0 = i;
    int32_t_x2 uu____0 = libcrux_ml_dsa_simd_portable_arithmetic_power2round_element(t0->انکڑے[i0]);
    int32_t uu____1 = uu____0.snd;
    t0->انکڑے[i0] = uu____0.fst;
    t1->انکڑے[i0] = uu____1;
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ساكن مضمن فراغ
libcrux_ml_dsa_simd_portable_power2round_65(Eurydice_arr_4d *t0, Eurydice_arr_4d *t1)
{
  libcrux_ml_dsa_simd_portable_arithmetic_power2round(t0, t1);
}

ساكن KRML_MUSTINLINE ناپ_t
libcrux_ml_dsa_simd_portable_sample_rejection_sample_less_than_میدان_modulus(
  Eurydice_borrow_ٹکڑا_u8 randomness,
  Eurydice_dst_ref_mut_83 باہرلا
)
{
  ناپ_t sampled = (ناپ_t)0U;
  لكل (ناپ_t i = (ناپ_t)0U; i < randomness.meta / (ناپ_t)3U; i++)
  {
    ناپ_t i0 = i;
    int32_t b0 = (int32_t)(uint32_t)randomness.ptr[i0 * (ناپ_t)3U];
    int32_t b1 = (int32_t)(uint32_t)randomness.ptr[i0 * (ناپ_t)3U + (ناپ_t)1U];
    int32_t b2 = (int32_t)(uint32_t)randomness.ptr[i0 * (ناپ_t)3U + (ناپ_t)2U];
    int32_t
    coefficient = (((int32_t)((uint32_t)b2 << 16U) | (int32_t)((uint32_t)b1 << 8U)) | b0) & 8388607;
    إذا (coefficient < LIBCRUX_ML_DSA_CONSTANTS_میدان_MODULUS)
    {
      باہرلا.ptr[sampled] = coefficient;
      sampled++;
    }
  }
  أرجع sampled;
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ساكن مضمن ناپ_t
libcrux_ml_dsa_simd_portable_rejection_sample_less_than_میدان_modulus_65(
  Eurydice_borrow_ٹکڑا_u8 randomness,
  Eurydice_dst_ref_mut_83 باہرلا
)
{
  أرجع
    libcrux_ml_dsa_simd_portable_sample_rejection_sample_less_than_میدان_modulus(randomness,
      باہرلا);
}

ساكن KRML_MUSTINLINE ناپ_t
libcrux_ml_dsa_simd_portable_sample_rejection_sample_less_than_eta_equals_2(
  Eurydice_borrow_ٹکڑا_u8 randomness,
  Eurydice_dst_ref_mut_83 باہرلا
)
{
  ناپ_t sampled = (ناپ_t)0U;
  لكل (ناپ_t i = (ناپ_t)0U; i < randomness.meta; i++)
  {
    ناپ_t i0 = i;
    uint8_t byte = randomness.ptr[i0];
    uint8_t try_0 = (uint32_t)byte & 15U;
    uint8_t try_1 = (uint32_t)byte >> 4U;
    bool try_0_comp = try_0 < 15U;
    bool try_1_comp = try_1 < 15U;
    إذا (try_0_comp)
    {
      int32_t try_00 = (int32_t)(uint32_t)try_0;
      int32_t try_0_mod_5 = try_00 - (try_00 * 26 >> 7U) * 5;
      باہرلا.ptr[sampled] = 2 - try_0_mod_5;
      sampled++;
    }
    إذا (try_1_comp)
    {
      int32_t try_10 = (int32_t)(uint32_t)try_1;
      int32_t try_1_mod_5 = try_10 - (try_10 * 26 >> 7U) * 5;
      باہرلا.ptr[sampled] = 2 - try_1_mod_5;
      sampled++;
    }
  }
  أرجع sampled;
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ساكن مضمن ناپ_t
libcrux_ml_dsa_simd_portable_rejection_sample_less_than_eta_equals_2_65(
  Eurydice_borrow_ٹکڑا_u8 randomness,
  Eurydice_dst_ref_mut_83 باہرلا
)
{
  أرجع
    libcrux_ml_dsa_simd_portable_sample_rejection_sample_less_than_eta_equals_2(randomness,
      باہرلا);
}

ساكن KRML_MUSTINLINE ناپ_t
libcrux_ml_dsa_simd_portable_sample_rejection_sample_less_than_eta_equals_4(
  Eurydice_borrow_ٹکڑا_u8 randomness,
  Eurydice_dst_ref_mut_83 باہرلا
)
{
  ناپ_t sampled = (ناپ_t)0U;
  لكل (ناپ_t i = (ناپ_t)0U; i < randomness.meta; i++)
  {
    ناپ_t i0 = i;
    uint8_t byte = randomness.ptr[i0];
    uint8_t try_0 = (uint32_t)byte & 15U;
    uint8_t try_1 = (uint32_t)byte >> 4U;
    bool try_0_comp = try_0 < 9U;
    bool try_1_comp = try_1 < 9U;
    إذا (try_0_comp)
    {
      باہرلا.ptr[sampled] = 4 - (int32_t)(uint32_t)try_0;
      sampled++;
    }
    إذا (try_1_comp)
    {
      باہرلا.ptr[sampled] = 4 - (int32_t)(uint32_t)try_1;
      sampled++;
    }
  }
  أرجع sampled;
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ساكن مضمن ناپ_t
libcrux_ml_dsa_simd_portable_rejection_sample_less_than_eta_equals_4_65(
  Eurydice_borrow_ٹکڑا_u8 randomness,
  Eurydice_dst_ref_mut_83 باہرلا
)
{
  أرجع
    libcrux_ml_dsa_simd_portable_sample_rejection_sample_less_than_eta_equals_4(randomness,
      باہرلا);
}

#تعریف_کرو LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_SERIALIZE_WHEN_GAMMA1_IS_2_POW_19_GAMMA1 ((int32_t)((uint32_t)1 << 19U))

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_encoding_gamma1_serialize_when_gamma1_is_2_pow_19(
  ثابت Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_ٹکڑا_u8 serialized
)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)8U / (ناپ_t)2U; i++)
  {
    ناپ_t i0 = i;
    Eurydice_dst_ref_shared_83
    coefficients =
      Eurydice_array_منزل_subslice_shared_44(simd_unit,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .شروع = i0 * (ناپ_t)2U,
            .سرا = i0 * (ناپ_t)2U + (ناپ_t)2U
          }
        ));
    int32_t
    coefficient0 =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_SERIALIZE_WHEN_GAMMA1_IS_2_POW_19_GAMMA1 -
        coefficients.ptr[0U];
    int32_t
    coefficient1 =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_SERIALIZE_WHEN_GAMMA1_IS_2_POW_19_GAMMA1 -
        coefficients.ptr[1U];
    serialized.ptr[(ناپ_t)5U * i0] = (uint8_t)coefficient0;
    serialized.ptr[(ناپ_t)5U * i0 + (ناپ_t)1U] = (uint8_t)(coefficient0 >> 8U);
    serialized.ptr[(ناپ_t)5U * i0 + (ناپ_t)2U] = (uint8_t)(coefficient0 >> 16U);
    ناپ_t uu____0 = (ناپ_t)5U * i0 + (ناپ_t)2U;
    serialized.ptr[uu____0] =
      (uint32_t)serialized.ptr[uu____0] | (uint32_t)(uint8_t)(int32_t)((uint32_t)coefficient1 << 4U);
    serialized.ptr[(ناپ_t)5U * i0 + (ناپ_t)3U] = (uint8_t)(coefficient1 >> 4U);
    serialized.ptr[(ناپ_t)5U * i0 + (ناپ_t)4U] = (uint8_t)(coefficient1 >> 12U);
  }
}

#تعریف_کرو LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_SERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1 ((int32_t)((uint32_t)1 << 17U))

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_encoding_gamma1_serialize_when_gamma1_is_2_pow_17(
  ثابت Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_ٹکڑا_u8 serialized
)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)8U / (ناپ_t)4U; i++)
  {
    ناپ_t i0 = i;
    Eurydice_dst_ref_shared_83
    coefficients =
      Eurydice_array_منزل_subslice_shared_44(simd_unit,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .شروع = i0 * (ناپ_t)4U,
            .سرا = i0 * (ناپ_t)4U + (ناپ_t)4U
          }
        ));
    int32_t
    coefficient0 =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_SERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1 -
        coefficients.ptr[0U];
    int32_t
    coefficient1 =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_SERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1 -
        coefficients.ptr[1U];
    int32_t
    coefficient2 =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_SERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1 -
        coefficients.ptr[2U];
    int32_t
    coefficient3 =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_SERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1 -
        coefficients.ptr[3U];
    serialized.ptr[(ناپ_t)9U * i0] = (uint8_t)coefficient0;
    serialized.ptr[(ناپ_t)9U * i0 + (ناپ_t)1U] = (uint8_t)(coefficient0 >> 8U);
    serialized.ptr[(ناپ_t)9U * i0 + (ناپ_t)2U] = (uint8_t)(coefficient0 >> 16U);
    ناپ_t uu____0 = (ناپ_t)9U * i0 + (ناپ_t)2U;
    serialized.ptr[uu____0] =
      (uint32_t)serialized.ptr[uu____0] | (uint32_t)(uint8_t)(int32_t)((uint32_t)coefficient1 << 2U);
    serialized.ptr[(ناپ_t)9U * i0 + (ناپ_t)3U] = (uint8_t)(coefficient1 >> 6U);
    serialized.ptr[(ناپ_t)9U * i0 + (ناپ_t)4U] = (uint8_t)(coefficient1 >> 14U);
    ناپ_t uu____1 = (ناپ_t)9U * i0 + (ناپ_t)4U;
    serialized.ptr[uu____1] =
      (uint32_t)serialized.ptr[uu____1] | (uint32_t)(uint8_t)(int32_t)((uint32_t)coefficient2 << 4U);
    serialized.ptr[(ناپ_t)9U * i0 + (ناپ_t)5U] = (uint8_t)(coefficient2 >> 4U);
    serialized.ptr[(ناپ_t)9U * i0 + (ناپ_t)6U] = (uint8_t)(coefficient2 >> 12U);
    ناپ_t uu____2 = (ناپ_t)9U * i0 + (ناپ_t)6U;
    serialized.ptr[uu____2] =
      (uint32_t)serialized.ptr[uu____2] | (uint32_t)(uint8_t)(int32_t)((uint32_t)coefficient3 << 6U);
    serialized.ptr[(ناپ_t)9U * i0 + (ناپ_t)7U] = (uint8_t)(coefficient3 >> 2U);
    serialized.ptr[(ناپ_t)9U * i0 + (ناپ_t)8U] = (uint8_t)(coefficient3 >> 10U);
  }
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_encoding_gamma1_serialize(
  ثابت Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_ٹکڑا_u8 serialized,
  ناپ_t gamma1_exponent
)
{
  بدل (gamma1_exponent)
  {
    حالة 17U:
      {
        اكسر;
      }
    حالة 19U:
      {
        libcrux_ml_dsa_simd_portable_encoding_gamma1_serialize_when_gamma1_is_2_pow_19(simd_unit,
          serialized);
        أرجع;
      }
    افتراضي:
      {
        KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __FILE__, __LINE__, "panic!");
        KRML_HOST_EXIT(255U);
      }
  }
  libcrux_ml_dsa_simd_portable_encoding_gamma1_serialize_when_gamma1_is_2_pow_17(simd_unit,
    serialized);
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ساكن مضمن فراغ
libcrux_ml_dsa_simd_portable_gamma1_serialize_65(
  ثابت Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_ٹکڑا_u8 serialized,
  ناپ_t gamma1_exponent
)
{
  libcrux_ml_dsa_simd_portable_encoding_gamma1_serialize(simd_unit, serialized, gamma1_exponent);
}

#تعریف_کرو LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_19_GAMMA1 ((int32_t)((uint32_t)1 << 19U))

#تعریف_کرو LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_19_GAMMA1_TIMES_2_BITMASK ((int32_t)((uint32_t)LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_19_GAMMA1 << 1U) - 1)

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_encoding_gamma1_deserialize_when_gamma1_is_2_pow_19(
  Eurydice_borrow_ٹکڑا_u8 serialized,
  Eurydice_arr_4d *simd_unit
)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < serialized.meta / (ناپ_t)5U; i++)
  {
    ناپ_t i0 = i;
    Eurydice_borrow_ٹکڑا_u8
    بائٹاں =
      Eurydice_ٹکڑا_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .شروع = i0 * (ناپ_t)5U,
            .سرا = i0 * (ناپ_t)5U + (ناپ_t)5U
          }
        ));
    int32_t coefficient0 = (int32_t)(uint32_t)بائٹاں.ptr[0U];
    coefficient0 |= (int32_t)((uint32_t)(int32_t)(uint32_t)بائٹاں.ptr[1U] << 8U);
    coefficient0 |= (int32_t)((uint32_t)(int32_t)(uint32_t)بائٹاں.ptr[2U] << 16U);
    coefficient0 &=
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_19_GAMMA1_TIMES_2_BITMASK;
    int32_t coefficient1 = (int32_t)(uint32_t)بائٹاں.ptr[2U] >> 4U;
    coefficient1 |= (int32_t)((uint32_t)(int32_t)(uint32_t)بائٹاں.ptr[3U] << 4U);
    coefficient1 |= (int32_t)((uint32_t)(int32_t)(uint32_t)بائٹاں.ptr[4U] << 12U);
    simd_unit->انکڑے[(ناپ_t)2U * i0] =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_19_GAMMA1 -
        coefficient0;
    simd_unit->انکڑے[(ناپ_t)2U * i0 + (ناپ_t)1U] =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_19_GAMMA1 -
        coefficient1;
  }
}

#تعریف_کرو LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1 ((int32_t)((uint32_t)1 << 17U))

#تعریف_کرو LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1_TIMES_2_BITMASK ((int32_t)((uint32_t)LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1 << 1U) - 1)

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_encoding_gamma1_deserialize_when_gamma1_is_2_pow_17(
  Eurydice_borrow_ٹکڑا_u8 serialized,
  Eurydice_arr_4d *simd_unit
)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < serialized.meta / (ناپ_t)9U; i++)
  {
    ناپ_t i0 = i;
    Eurydice_borrow_ٹکڑا_u8
    بائٹاں =
      Eurydice_ٹکڑا_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .شروع = i0 * (ناپ_t)9U,
            .سرا = i0 * (ناپ_t)9U + (ناپ_t)9U
          }
        ));
    int32_t coefficient0 = (int32_t)(uint32_t)بائٹاں.ptr[0U];
    coefficient0 |= (int32_t)((uint32_t)(int32_t)(uint32_t)بائٹاں.ptr[1U] << 8U);
    coefficient0 |= (int32_t)((uint32_t)(int32_t)(uint32_t)بائٹاں.ptr[2U] << 16U);
    coefficient0 &=
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1_TIMES_2_BITMASK;
    int32_t coefficient1 = (int32_t)(uint32_t)بائٹاں.ptr[2U] >> 2U;
    coefficient1 |= (int32_t)((uint32_t)(int32_t)(uint32_t)بائٹاں.ptr[3U] << 6U);
    coefficient1 |= (int32_t)((uint32_t)(int32_t)(uint32_t)بائٹاں.ptr[4U] << 14U);
    coefficient1 &=
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1_TIMES_2_BITMASK;
    int32_t coefficient2 = (int32_t)(uint32_t)بائٹاں.ptr[4U] >> 4U;
    coefficient2 |= (int32_t)((uint32_t)(int32_t)(uint32_t)بائٹاں.ptr[5U] << 4U);
    coefficient2 |= (int32_t)((uint32_t)(int32_t)(uint32_t)بائٹاں.ptr[6U] << 12U);
    coefficient2 &=
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1_TIMES_2_BITMASK;
    int32_t coefficient3 = (int32_t)(uint32_t)بائٹاں.ptr[6U] >> 6U;
    coefficient3 |= (int32_t)((uint32_t)(int32_t)(uint32_t)بائٹاں.ptr[7U] << 2U);
    coefficient3 |= (int32_t)((uint32_t)(int32_t)(uint32_t)بائٹاں.ptr[8U] << 10U);
    coefficient3 &=
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1_TIMES_2_BITMASK;
    simd_unit->انکڑے[(ناپ_t)4U * i0] =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1 -
        coefficient0;
    simd_unit->انکڑے[(ناپ_t)4U * i0 + (ناپ_t)1U] =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1 -
        coefficient1;
    simd_unit->انکڑے[(ناپ_t)4U * i0 + (ناپ_t)2U] =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1 -
        coefficient2;
    simd_unit->انکڑے[(ناپ_t)4U * i0 + (ناپ_t)3U] =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1 -
        coefficient3;
  }
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_encoding_gamma1_deserialize(
  Eurydice_borrow_ٹکڑا_u8 serialized,
  Eurydice_arr_4d *باہرلا,
  ناپ_t gamma1_exponent
)
{
  بدل (gamma1_exponent)
  {
    حالة 17U:
      {
        اكسر;
      }
    حالة 19U:
      {
        libcrux_ml_dsa_simd_portable_encoding_gamma1_deserialize_when_gamma1_is_2_pow_19(serialized,
          باہرلا);
        أرجع;
      }
    افتراضي:
      {
        KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __FILE__, __LINE__, "panic!");
        KRML_HOST_EXIT(255U);
      }
  }
  libcrux_ml_dsa_simd_portable_encoding_gamma1_deserialize_when_gamma1_is_2_pow_17(serialized,
    باہرلا);
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ساكن مضمن فراغ
libcrux_ml_dsa_simd_portable_gamma1_deserialize_65(
  Eurydice_borrow_ٹکڑا_u8 serialized,
  Eurydice_arr_4d *باہرلا,
  ناپ_t gamma1_exponent
)
{
  libcrux_ml_dsa_simd_portable_encoding_gamma1_deserialize(serialized, باہرلا, gamma1_exponent);
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_encoding_commitment_serialize_4(
  ثابت Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_ٹکڑا_u8 serialized
)
{
  uint8_t coefficient0 = (uint8_t)simd_unit->انکڑے[0U];
  uint8_t coefficient1 = (uint8_t)simd_unit->انکڑے[1U];
  uint8_t coefficient2 = (uint8_t)simd_unit->انکڑے[2U];
  uint8_t coefficient3 = (uint8_t)simd_unit->انکڑے[3U];
  uint8_t coefficient4 = (uint8_t)simd_unit->انکڑے[4U];
  uint8_t coefficient5 = (uint8_t)simd_unit->انکڑے[5U];
  uint8_t coefficient6 = (uint8_t)simd_unit->انکڑے[6U];
  uint8_t coefficient7 = (uint8_t)simd_unit->انکڑے[7U];
  uint8_t byte0 = (uint32_t)coefficient1 << 4U | (uint32_t)coefficient0;
  uint8_t byte1 = (uint32_t)coefficient3 << 4U | (uint32_t)coefficient2;
  uint8_t byte2 = (uint32_t)coefficient5 << 4U | (uint32_t)coefficient4;
  uint8_t byte3 = (uint32_t)coefficient7 << 4U | (uint32_t)coefficient6;
  serialized.ptr[0U] = byte0;
  serialized.ptr[1U] = byte1;
  serialized.ptr[2U] = byte2;
  serialized.ptr[3U] = byte3;
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_encoding_commitment_serialize_6(
  ثابت Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_ٹکڑا_u8 serialized
)
{
  uint8_t coefficient0 = (uint8_t)simd_unit->انکڑے[0U];
  uint8_t coefficient1 = (uint8_t)simd_unit->انکڑے[1U];
  uint8_t coefficient2 = (uint8_t)simd_unit->انکڑے[2U];
  uint8_t coefficient3 = (uint8_t)simd_unit->انکڑے[3U];
  uint8_t coefficient4 = (uint8_t)simd_unit->انکڑے[4U];
  uint8_t coefficient5 = (uint8_t)simd_unit->انکڑے[5U];
  uint8_t coefficient6 = (uint8_t)simd_unit->انکڑے[6U];
  uint8_t coefficient7 = (uint8_t)simd_unit->انکڑے[7U];
  uint8_t byte0 = (uint32_t)coefficient1 << 6U | (uint32_t)coefficient0;
  uint8_t byte1 = (uint32_t)coefficient2 << 4U | (uint32_t)coefficient1 >> 2U;
  uint8_t byte2 = (uint32_t)coefficient3 << 2U | (uint32_t)coefficient2 >> 4U;
  uint8_t byte3 = (uint32_t)coefficient5 << 6U | (uint32_t)coefficient4;
  uint8_t byte4 = (uint32_t)coefficient6 << 4U | (uint32_t)coefficient5 >> 2U;
  uint8_t byte5 = (uint32_t)coefficient7 << 2U | (uint32_t)coefficient6 >> 4U;
  serialized.ptr[0U] = byte0;
  serialized.ptr[1U] = byte1;
  serialized.ptr[2U] = byte2;
  serialized.ptr[3U] = byte3;
  serialized.ptr[4U] = byte4;
  serialized.ptr[5U] = byte5;
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_encoding_commitment_serialize(
  ثابت Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_ٹکڑا_u8 serialized
)
{
  بدل ((uint32_t)(uint8_t)serialized.meta)
  {
    حالة 4U:
      {
        libcrux_ml_dsa_simd_portable_encoding_commitment_serialize_4(simd_unit, serialized);
        اكسر;
      }
    حالة 6U:
      {
        libcrux_ml_dsa_simd_portable_encoding_commitment_serialize_6(simd_unit, serialized);
        اكسر;
      }
    افتراضي:
      {
        KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __FILE__, __LINE__, "panic!");
        KRML_HOST_EXIT(255U);
      }
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ساكن مضمن فراغ
libcrux_ml_dsa_simd_portable_commitment_serialize_65(
  ثابت Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_ٹکڑا_u8 serialized
)
{
  libcrux_ml_dsa_simd_portable_encoding_commitment_serialize(simd_unit, serialized);
}

#تعریف_کرو LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_4_ETA (4)

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_encoding_error_serialize_when_eta_is_4(
  ثابت Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_ٹکڑا_u8 serialized
)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)8U / (ناپ_t)2U; i++)
  {
    ناپ_t i0 = i;
    Eurydice_dst_ref_shared_83
    coefficients =
      Eurydice_array_منزل_subslice_shared_44(simd_unit,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .شروع = i0 * (ناپ_t)2U,
            .سرا = i0 * (ناپ_t)2U + (ناپ_t)2U
          }
        ));
    uint8_t
    coefficient0 =
      (uint8_t)(LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_4_ETA -
        coefficients.ptr[0U]);
    uint8_t
    coefficient1 =
      (uint8_t)(LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_4_ETA -
        coefficients.ptr[1U]);
    serialized.ptr[i0] = (uint32_t)coefficient1 << 4U | (uint32_t)coefficient0;
  }
}

#تعریف_کرو LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_2_ETA (2)

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_encoding_error_serialize_when_eta_is_2(
  ثابت Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_ٹکڑا_u8 serialized
)
{
  uint8_t
  coefficient0 =
    (uint8_t)(LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_2_ETA -
      simd_unit->انکڑے[0U]);
  uint8_t
  coefficient1 =
    (uint8_t)(LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_2_ETA -
      simd_unit->انکڑے[1U]);
  uint8_t
  coefficient2 =
    (uint8_t)(LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_2_ETA -
      simd_unit->انکڑے[2U]);
  uint8_t
  coefficient3 =
    (uint8_t)(LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_2_ETA -
      simd_unit->انکڑے[3U]);
  uint8_t
  coefficient4 =
    (uint8_t)(LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_2_ETA -
      simd_unit->انکڑے[4U]);
  uint8_t
  coefficient5 =
    (uint8_t)(LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_2_ETA -
      simd_unit->انکڑے[5U]);
  uint8_t
  coefficient6 =
    (uint8_t)(LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_2_ETA -
      simd_unit->انکڑے[6U]);
  uint8_t
  coefficient7 =
    (uint8_t)(LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_2_ETA -
      simd_unit->انکڑے[7U]);
  serialized.ptr[0U] =
    ((uint32_t)coefficient2 << 6U | (uint32_t)coefficient1 << 3U) | (uint32_t)coefficient0;
  serialized.ptr[1U] =
    (((uint32_t)coefficient5 << 7U | (uint32_t)coefficient4 << 4U) | (uint32_t)coefficient3 << 1U)
    | (uint32_t)coefficient2 >> 2U;
  serialized.ptr[2U] =
    ((uint32_t)coefficient7 << 5U | (uint32_t)coefficient6 << 2U) | (uint32_t)coefficient5 >> 1U;
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_encoding_error_serialize(
  libcrux_ml_dsa_constants_Eta eta,
  ثابت Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_ٹکڑا_u8 serialized
)
{
  بدل (eta)
  {
    حالة libcrux_ml_dsa_constants_Eta_Two:
      {
        اكسر;
      }
    حالة libcrux_ml_dsa_constants_Eta_Four:
      {
        libcrux_ml_dsa_simd_portable_encoding_error_serialize_when_eta_is_4(simd_unit, serialized);
        أرجع;
      }
    افتراضي:
      {
        KRML_HOST_EPRINTF("KaRaMeL incomplete match at %s:%d\n", __FILE__, __LINE__);
        KRML_HOST_EXIT(253U);
      }
  }
  libcrux_ml_dsa_simd_portable_encoding_error_serialize_when_eta_is_2(simd_unit, serialized);
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ساكن مضمن فراغ
libcrux_ml_dsa_simd_portable_error_serialize_65(
  libcrux_ml_dsa_constants_Eta eta,
  ثابت Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_ٹکڑا_u8 serialized
)
{
  libcrux_ml_dsa_simd_portable_encoding_error_serialize(eta, simd_unit, serialized);
}

#تعریف_کرو LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_4_ETA (4)

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_encoding_error_deserialize_when_eta_is_4(
  Eurydice_borrow_ٹکڑا_u8 serialized,
  Eurydice_arr_4d *simd_units
)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < serialized.meta; i++)
  {
    ناپ_t i0 = i;
    ثابت uint8_t *byte = &serialized.ptr[i0];
    uint8_t uu____0 = core_ops_ثنائی_ہندسہ_core_ops_ثنائی_ہندسہ_ثنائی_ہندسہ_And_u8_u8_for_0_u8_bitand(byte, 15U);
    simd_units->انکڑے[(ناپ_t)2U * i0] =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_4_ETA -
        (int32_t)(uint32_t)uu____0;
    uint8_t uu____1 = core_ops_ثنائی_ہندسہ_core_ops_ثنائی_ہندسہ_Shr_i32_u8_for_0_u8_shr(byte, 4);
    simd_units->انکڑے[(ناپ_t)2U * i0 + (ناپ_t)1U] =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_4_ETA -
        (int32_t)(uint32_t)uu____1;
  }
}

#تعریف_کرو LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_2_ETA (2)

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_encoding_error_deserialize_when_eta_is_2(
  Eurydice_borrow_ٹکڑا_u8 serialized,
  Eurydice_arr_4d *simd_unit
)
{
  int32_t byte0 = (int32_t)(uint32_t)serialized.ptr[0U];
  int32_t byte1 = (int32_t)(uint32_t)serialized.ptr[1U];
  int32_t byte2 = (int32_t)(uint32_t)serialized.ptr[2U];
  simd_unit->انکڑے[0U] =
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_2_ETA - (byte0 & 7);
  simd_unit->انکڑے[1U] =
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_2_ETA - (byte0 >> 3U & 7);
  simd_unit->انکڑے[2U] =
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_2_ETA -
      ((byte0 >> 6U | (int32_t)((uint32_t)byte1 << 2U)) & 7);
  simd_unit->انکڑے[3U] =
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_2_ETA - (byte1 >> 1U & 7);
  simd_unit->انکڑے[4U] =
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_2_ETA - (byte1 >> 4U & 7);
  simd_unit->انکڑے[5U] =
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_2_ETA -
      ((byte1 >> 7U | (int32_t)((uint32_t)byte2 << 1U)) & 7);
  simd_unit->انکڑے[6U] =
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_2_ETA - (byte2 >> 2U & 7);
  simd_unit->انکڑے[7U] =
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_2_ETA - (byte2 >> 5U & 7);
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_encoding_error_deserialize(
  libcrux_ml_dsa_constants_Eta eta,
  Eurydice_borrow_ٹکڑا_u8 serialized,
  Eurydice_arr_4d *باہرلا
)
{
  بدل (eta)
  {
    حالة libcrux_ml_dsa_constants_Eta_Two:
      {
        اكسر;
      }
    حالة libcrux_ml_dsa_constants_Eta_Four:
      {
        libcrux_ml_dsa_simd_portable_encoding_error_deserialize_when_eta_is_4(serialized, باہرلا);
        أرجع;
      }
    افتراضي:
      {
        KRML_HOST_EPRINTF("KaRaMeL incomplete match at %s:%d\n", __FILE__, __LINE__);
        KRML_HOST_EXIT(253U);
      }
  }
  libcrux_ml_dsa_simd_portable_encoding_error_deserialize_when_eta_is_2(serialized, باہرلا);
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ساكن مضمن فراغ
libcrux_ml_dsa_simd_portable_error_deserialize_65(
  libcrux_ml_dsa_constants_Eta eta,
  Eurydice_borrow_ٹکڑا_u8 serialized,
  Eurydice_arr_4d *باہرلا
)
{
  libcrux_ml_dsa_simd_portable_encoding_error_deserialize(eta, serialized, باہرلا);
}

ساكن KRML_MUSTINLINE int32_t
libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(int32_t t0)
{
  أرجع
    (int32_t)((uint32_t)1 <<
      (uint32_t)(LIBCRUX_ML_DSA_CONSTANTS_بٹ_وچ_ہیٹھلا_PART_دا_T - (ناپ_t)1U))
    - t0;
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_encoding_t0_serialize(
  ثابت Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_ٹکڑا_u8 serialized
)
{
  int32_t
  coefficient0 = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(simd_unit->انکڑے[0U]);
  int32_t
  coefficient1 = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(simd_unit->انکڑے[1U]);
  int32_t
  coefficient2 = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(simd_unit->انکڑے[2U]);
  int32_t
  coefficient3 = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(simd_unit->انکڑے[3U]);
  int32_t
  coefficient4 = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(simd_unit->انکڑے[4U]);
  int32_t
  coefficient5 = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(simd_unit->انکڑے[5U]);
  int32_t
  coefficient6 = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(simd_unit->انکڑے[6U]);
  int32_t
  coefficient7 = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(simd_unit->انکڑے[7U]);
  serialized.ptr[0U] = (uint8_t)coefficient0;
  serialized.ptr[1U] =
    (uint32_t)(uint8_t)(coefficient0 >> 8U) |
      (uint32_t)(uint8_t)(int32_t)((uint32_t)coefficient1 << 5U);
  serialized.ptr[2U] = (uint8_t)(coefficient1 >> 3U);
  serialized.ptr[3U] =
    (uint32_t)(uint8_t)(coefficient1 >> 11U) |
      (uint32_t)(uint8_t)(int32_t)((uint32_t)coefficient2 << 2U);
  serialized.ptr[4U] =
    (uint32_t)(uint8_t)(coefficient2 >> 6U) |
      (uint32_t)(uint8_t)(int32_t)((uint32_t)coefficient3 << 7U);
  serialized.ptr[5U] = (uint8_t)(coefficient3 >> 1U);
  serialized.ptr[6U] =
    (uint32_t)(uint8_t)(coefficient3 >> 9U) |
      (uint32_t)(uint8_t)(int32_t)((uint32_t)coefficient4 << 4U);
  serialized.ptr[7U] = (uint8_t)(coefficient4 >> 4U);
  serialized.ptr[8U] =
    (uint32_t)(uint8_t)(coefficient4 >> 12U) |
      (uint32_t)(uint8_t)(int32_t)((uint32_t)coefficient5 << 1U);
  serialized.ptr[9U] =
    (uint32_t)(uint8_t)(coefficient5 >> 7U) |
      (uint32_t)(uint8_t)(int32_t)((uint32_t)coefficient6 << 6U);
  serialized.ptr[10U] = (uint8_t)(coefficient6 >> 2U);
  serialized.ptr[11U] =
    (uint32_t)(uint8_t)(coefficient6 >> 10U) |
      (uint32_t)(uint8_t)(int32_t)((uint32_t)coefficient7 << 3U);
  serialized.ptr[12U] = (uint8_t)(coefficient7 >> 5U);
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ساكن مضمن فراغ
libcrux_ml_dsa_simd_portable_t0_serialize_65(
  ثابت Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_ٹکڑا_u8 باہرلا
)
{
  libcrux_ml_dsa_simd_portable_encoding_t0_serialize(simd_unit, باہرلا);
}

#تعریف_کرو LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_T0_DESERIALIZE_بٹ_وچ_ہیٹھلا_PART_دا_T_نقاب ((int32_t)((uint32_t)1 << (uint32_t)(int32_t)LIBCRUX_ML_DSA_CONSTANTS_بٹ_وچ_ہیٹھلا_PART_دا_T) - 1)

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_encoding_t0_deserialize(
  Eurydice_borrow_ٹکڑا_u8 serialized,
  Eurydice_arr_4d *simd_unit
)
{
  int32_t byte0 = (int32_t)(uint32_t)serialized.ptr[0U];
  int32_t byte1 = (int32_t)(uint32_t)serialized.ptr[1U];
  int32_t byte2 = (int32_t)(uint32_t)serialized.ptr[2U];
  int32_t byte3 = (int32_t)(uint32_t)serialized.ptr[3U];
  int32_t byte4 = (int32_t)(uint32_t)serialized.ptr[4U];
  int32_t byte5 = (int32_t)(uint32_t)serialized.ptr[5U];
  int32_t byte6 = (int32_t)(uint32_t)serialized.ptr[6U];
  int32_t byte7 = (int32_t)(uint32_t)serialized.ptr[7U];
  int32_t byte8 = (int32_t)(uint32_t)serialized.ptr[8U];
  int32_t byte9 = (int32_t)(uint32_t)serialized.ptr[9U];
  int32_t byte10 = (int32_t)(uint32_t)serialized.ptr[10U];
  int32_t byte11 = (int32_t)(uint32_t)serialized.ptr[11U];
  int32_t byte12 = (int32_t)(uint32_t)serialized.ptr[12U];
  int32_t coefficient0 = byte0;
  coefficient0 |= (int32_t)((uint32_t)byte1 << 8U);
  coefficient0 &=
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_T0_DESERIALIZE_بٹ_وچ_ہیٹھلا_PART_دا_T_نقاب;
  int32_t coefficient1 = byte1 >> 5U;
  coefficient1 |= (int32_t)((uint32_t)byte2 << 3U);
  coefficient1 |= (int32_t)((uint32_t)byte3 << 11U);
  coefficient1 &=
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_T0_DESERIALIZE_بٹ_وچ_ہیٹھلا_PART_دا_T_نقاب;
  int32_t coefficient2 = byte3 >> 2U;
  coefficient2 |= (int32_t)((uint32_t)byte4 << 6U);
  coefficient2 &=
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_T0_DESERIALIZE_بٹ_وچ_ہیٹھلا_PART_دا_T_نقاب;
  int32_t coefficient3 = byte4 >> 7U;
  coefficient3 |= (int32_t)((uint32_t)byte5 << 1U);
  coefficient3 |= (int32_t)((uint32_t)byte6 << 9U);
  coefficient3 &=
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_T0_DESERIALIZE_بٹ_وچ_ہیٹھلا_PART_دا_T_نقاب;
  int32_t coefficient4 = byte6 >> 4U;
  coefficient4 |= (int32_t)((uint32_t)byte7 << 4U);
  coefficient4 |= (int32_t)((uint32_t)byte8 << 12U);
  coefficient4 &=
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_T0_DESERIALIZE_بٹ_وچ_ہیٹھلا_PART_دا_T_نقاب;
  int32_t coefficient5 = byte8 >> 1U;
  coefficient5 |= (int32_t)((uint32_t)byte9 << 7U);
  coefficient5 &=
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_T0_DESERIALIZE_بٹ_وچ_ہیٹھلا_PART_دا_T_نقاب;
  int32_t coefficient6 = byte9 >> 6U;
  coefficient6 |= (int32_t)((uint32_t)byte10 << 2U);
  coefficient6 |= (int32_t)((uint32_t)byte11 << 10U);
  coefficient6 &=
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_T0_DESERIALIZE_بٹ_وچ_ہیٹھلا_PART_دا_T_نقاب;
  int32_t coefficient7 = byte11 >> 3U;
  coefficient7 |= (int32_t)((uint32_t)byte12 << 5U);
  coefficient7 &=
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_T0_DESERIALIZE_بٹ_وچ_ہیٹھلا_PART_دا_T_نقاب;
  simd_unit->انکڑے[0U] = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(coefficient0);
  simd_unit->انکڑے[1U] = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(coefficient1);
  simd_unit->انکڑے[2U] = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(coefficient2);
  simd_unit->انکڑے[3U] = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(coefficient3);
  simd_unit->انکڑے[4U] = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(coefficient4);
  simd_unit->انکڑے[5U] = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(coefficient5);
  simd_unit->انکڑے[6U] = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(coefficient6);
  simd_unit->انکڑے[7U] = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(coefficient7);
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ساكن مضمن فراغ
libcrux_ml_dsa_simd_portable_t0_deserialize_65(
  Eurydice_borrow_ٹکڑا_u8 serialized,
  Eurydice_arr_4d *باہرلا
)
{
  libcrux_ml_dsa_simd_portable_encoding_t0_deserialize(serialized, باہرلا);
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_encoding_t1_serialize(
  ثابت Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_ٹکڑا_u8 serialized
)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)8U / (ناپ_t)4U; i++)
  {
    ناپ_t i0 = i;
    Eurydice_dst_ref_shared_83
    coefficients =
      Eurydice_array_منزل_subslice_shared_44(simd_unit,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .شروع = i0 * (ناپ_t)4U,
            .سرا = i0 * (ناپ_t)4U + (ناپ_t)4U
          }
        ));
    serialized.ptr[(ناپ_t)5U * i0] = (uint8_t)(coefficients.ptr[0U] & 255);
    serialized.ptr[(ناپ_t)5U * i0 + (ناپ_t)1U] =
      (uint32_t)(uint8_t)(coefficients.ptr[1U] & 63) << 2U |
        (uint32_t)(uint8_t)(coefficients.ptr[0U] >> 8U & 3);
    serialized.ptr[(ناپ_t)5U * i0 + (ناپ_t)2U] =
      (uint32_t)(uint8_t)(coefficients.ptr[2U] & 15) << 4U |
        (uint32_t)(uint8_t)(coefficients.ptr[1U] >> 6U & 15);
    serialized.ptr[(ناپ_t)5U * i0 + (ناپ_t)3U] =
      (uint32_t)(uint8_t)(coefficients.ptr[3U] & 3) << 6U |
        (uint32_t)(uint8_t)(coefficients.ptr[2U] >> 4U & 63);
    serialized.ptr[(ناپ_t)5U * i0 + (ناپ_t)4U] = (uint8_t)(coefficients.ptr[3U] >> 2U & 255);
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ساكن مضمن فراغ
libcrux_ml_dsa_simd_portable_t1_serialize_65(
  ثابت Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_ٹکڑا_u8 باہرلا
)
{
  libcrux_ml_dsa_simd_portable_encoding_t1_serialize(simd_unit, باہرلا);
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_encoding_t1_deserialize(
  Eurydice_borrow_ٹکڑا_u8 serialized,
  Eurydice_arr_4d *simd_unit
)
{
  int32_t
  نقاب = (int32_t)((uint32_t)1 << (uint32_t)LIBCRUX_ML_DSA_CONSTANTS_بٹ_وچ_اتلا_PART_دا_T) - 1;
  لكل (ناپ_t i = (ناپ_t)0U; i < serialized.meta / (ناپ_t)5U; i++)
  {
    ناپ_t i0 = i;
    Eurydice_borrow_ٹکڑا_u8
    بائٹاں =
      Eurydice_ٹکڑا_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .شروع = i0 * (ناپ_t)5U,
            .سرا = i0 * (ناپ_t)5U + (ناپ_t)5U
          }
        ));
    int32_t byte0 = (int32_t)(uint32_t)بائٹاں.ptr[0U];
    int32_t byte1 = (int32_t)(uint32_t)بائٹاں.ptr[1U];
    int32_t byte2 = (int32_t)(uint32_t)بائٹاں.ptr[2U];
    int32_t byte3 = (int32_t)(uint32_t)بائٹاں.ptr[3U];
    int32_t byte4 = (int32_t)(uint32_t)بائٹاں.ptr[4U];
    simd_unit->انکڑے[(ناپ_t)4U * i0] = (byte0 | (int32_t)((uint32_t)byte1 << 8U)) & نقاب;
    simd_unit->انکڑے[(ناپ_t)4U * i0 + (ناپ_t)1U] =
      (byte1 >> 2U | (int32_t)((uint32_t)byte2 << 6U)) & نقاب;
    simd_unit->انکڑے[(ناپ_t)4U * i0 + (ناپ_t)2U] =
      (byte2 >> 4U | (int32_t)((uint32_t)byte3 << 4U)) & نقاب;
    simd_unit->انکڑے[(ناپ_t)4U * i0 + (ناپ_t)3U] =
      (byte3 >> 6U | (int32_t)((uint32_t)byte4 << 2U)) & نقاب;
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ساكن مضمن فراغ
libcrux_ml_dsa_simd_portable_t1_deserialize_65(
  Eurydice_borrow_ٹکڑا_u8 serialized,
  Eurydice_arr_4d *باہرلا
)
{
  libcrux_ml_dsa_simd_portable_encoding_t1_deserialize(serialized, باہرلا);
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(
  Eurydice_arr_4d *simd_unit,
  int32_t c
)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)8U; i++)
  {
    ناپ_t i0 = i;
    simd_unit->انکڑے[i0] =
      libcrux_ml_dsa_simd_portable_arithmetic_montgomery_reduce_element((int64_t)simd_unit->انکڑے[i0]
        * (int64_t)c);
  }
}

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- $32size_t
*/
تعريفنوع بنية Eurydice_arr_a3_s { Eurydice_arr_4d انکڑے[32U]; } Eurydice_arr_a3;

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_گیڑا(
  Eurydice_arr_a3 *re,
  ناپ_t index,
  ناپ_t قدم_by,
  int32_t zeta
)
{
  Eurydice_arr_4d tmp = re->انکڑے[index + قدم_by];
  libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&tmp, zeta);
  re->انکڑے[index + قدم_by] = re->انکڑے[index];
  libcrux_ml_dsa_simd_portable_arithmetic_گھٹاؤ(&re->انکڑے[index + قدم_by], &tmp);
  libcrux_ml_dsa_simd_portable_arithmetic_جوڑو(&re->انکڑے[index], &tmp);
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 0
- STEP_BY= 16
- ZETA= 25847
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_30(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)0U + (ناپ_t)16U; i++)
  {
    ناپ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_گیڑا(re, j, (ناپ_t)16U, 25847);
  }
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_7(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_30(re);
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 0
- STEP_BY= 8
- ZETA= -2608894
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_300(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)0U + (ناپ_t)8U; i++)
  {
    ناپ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_گیڑا(re, j, (ناپ_t)8U, -2608894);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 16
- STEP_BY= 8
- ZETA= -518909
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_42(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)16U; i < (ناپ_t)16U + (ناپ_t)8U; i++)
  {
    ناپ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_گیڑا(re, j, (ناپ_t)8U, -518909);
  }
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_6(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_300(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_42(re);
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 0
- STEP_BY= 4
- ZETA= 237124
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_301(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)0U + (ناپ_t)4U; i++)
  {
    ناپ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_گیڑا(re, j, (ناپ_t)4U, 237124);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 8
- STEP_BY= 4
- ZETA= -777960
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_82(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)8U; i < (ناپ_t)8U + (ناپ_t)4U; i++)
  {
    ناپ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_گیڑا(re, j, (ناپ_t)4U, -777960);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 16
- STEP_BY= 4
- ZETA= -876248
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_420(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)16U; i < (ناپ_t)16U + (ناپ_t)4U; i++)
  {
    ناپ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_گیڑا(re, j, (ناپ_t)4U, -876248);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 24
- STEP_BY= 4
- ZETA= 466468
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_fe(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)24U; i < (ناپ_t)24U + (ناپ_t)4U; i++)
  {
    ناپ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_گیڑا(re, j, (ناپ_t)4U, 466468);
  }
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_5(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_301(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_82(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_420(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_fe(re);
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 0
- STEP_BY= 2
- ZETA= 1826347
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_302(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)0U + (ناپ_t)2U; i++)
  {
    ناپ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_گیڑا(re, j, (ناپ_t)2U, 1826347);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 4
- STEP_BY= 2
- ZETA= 2353451
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_43(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)4U; i < (ناپ_t)4U + (ناپ_t)2U; i++)
  {
    ناپ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_گیڑا(re, j, (ناپ_t)2U, 2353451);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 8
- STEP_BY= 2
- ZETA= -359251
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_820(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)8U; i < (ناپ_t)8U + (ناپ_t)2U; i++)
  {
    ناپ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_گیڑا(re, j, (ناپ_t)2U, -359251);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 12
- STEP_BY= 2
- ZETA= -2091905
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_ea(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)12U; i < (ناپ_t)12U + (ناپ_t)2U; i++)
  {
    ناپ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_گیڑا(re, j, (ناپ_t)2U, -2091905);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 16
- STEP_BY= 2
- ZETA= 3119733
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_421(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)16U; i < (ناپ_t)16U + (ناپ_t)2U; i++)
  {
    ناپ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_گیڑا(re, j, (ناپ_t)2U, 3119733);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 20
- STEP_BY= 2
- ZETA= -2884855
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_61(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)20U; i < (ناپ_t)20U + (ناپ_t)2U; i++)
  {
    ناپ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_گیڑا(re, j, (ناپ_t)2U, -2884855);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 24
- STEP_BY= 2
- ZETA= 3111497
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_fe0(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)24U; i < (ناپ_t)24U + (ناپ_t)2U; i++)
  {
    ناپ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_گیڑا(re, j, (ناپ_t)2U, 3111497);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 28
- STEP_BY= 2
- ZETA= 2680103
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_38(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)28U; i < (ناپ_t)28U + (ناپ_t)2U; i++)
  {
    ناپ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_گیڑا(re, j, (ناپ_t)2U, 2680103);
  }
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_4(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_302(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_43(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_820(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_ea(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_421(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_61(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_fe0(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_38(re);
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 0
- STEP_BY= 1
- ZETA= 2725464
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_303(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)0U + (ناپ_t)1U; i++)
  {
    ناپ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_گیڑا(re, j, (ناپ_t)1U, 2725464);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 2
- STEP_BY= 1
- ZETA= 1024112
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_25(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)2U; i < (ناپ_t)2U + (ناپ_t)1U; i++)
  {
    ناپ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_گیڑا(re, j, (ناپ_t)1U, 1024112);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 4
- STEP_BY= 1
- ZETA= -1079900
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_430(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)4U; i < (ناپ_t)4U + (ناپ_t)1U; i++)
  {
    ناپ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_گیڑا(re, j, (ناپ_t)1U, -1079900);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 6
- STEP_BY= 1
- ZETA= 3585928
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_f4(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)6U; i < (ناپ_t)6U + (ناپ_t)1U; i++)
  {
    ناپ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_گیڑا(re, j, (ناپ_t)1U, 3585928);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 8
- STEP_BY= 1
- ZETA= -549488
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_821(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)8U; i < (ناپ_t)8U + (ناپ_t)1U; i++)
  {
    ناپ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_گیڑا(re, j, (ناپ_t)1U, -549488);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 10
- STEP_BY= 1
- ZETA= -1119584
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_1d(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)10U; i < (ناپ_t)10U + (ناپ_t)1U; i++)
  {
    ناپ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_گیڑا(re, j, (ناپ_t)1U, -1119584);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 12
- STEP_BY= 1
- ZETA= 2619752
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_ea0(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)12U; i < (ناپ_t)12U + (ناپ_t)1U; i++)
  {
    ناپ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_گیڑا(re, j, (ناپ_t)1U, 2619752);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 14
- STEP_BY= 1
- ZETA= -2108549
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_d8(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)14U; i < (ناپ_t)14U + (ناپ_t)1U; i++)
  {
    ناپ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_گیڑا(re, j, (ناپ_t)1U, -2108549);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 16
- STEP_BY= 1
- ZETA= -2118186
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_422(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)16U; i < (ناپ_t)16U + (ناپ_t)1U; i++)
  {
    ناپ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_گیڑا(re, j, (ناپ_t)1U, -2118186);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 18
- STEP_BY= 1
- ZETA= -3859737
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_60(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)18U; i < (ناپ_t)18U + (ناپ_t)1U; i++)
  {
    ناپ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_گیڑا(re, j, (ناپ_t)1U, -3859737);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 20
- STEP_BY= 1
- ZETA= -1399561
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_610(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)20U; i < (ناپ_t)20U + (ناپ_t)1U; i++)
  {
    ناپ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_گیڑا(re, j, (ناپ_t)1U, -1399561);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 22
- STEP_BY= 1
- ZETA= -3277672
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_29(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)22U; i < (ناپ_t)22U + (ناپ_t)1U; i++)
  {
    ناپ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_گیڑا(re, j, (ناپ_t)1U, -3277672);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 24
- STEP_BY= 1
- ZETA= 1757237
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_fe1(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)24U; i < (ناپ_t)24U + (ناپ_t)1U; i++)
  {
    ناپ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_گیڑا(re, j, (ناپ_t)1U, 1757237);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 26
- STEP_BY= 1
- ZETA= -19422
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_9d(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)26U; i < (ناپ_t)26U + (ناپ_t)1U; i++)
  {
    ناپ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_گیڑا(re, j, (ناپ_t)1U, -19422);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 28
- STEP_BY= 1
- ZETA= 4010497
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_380(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)28U; i < (ناپ_t)28U + (ناپ_t)1U; i++)
  {
    ناپ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_گیڑا(re, j, (ناپ_t)1U, 4010497);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 30
- STEP_BY= 1
- ZETA= 280005
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_5f(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)30U; i < (ناپ_t)30U + (ناپ_t)1U; i++)
  {
    ناپ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_گیڑا(re, j, (ناپ_t)1U, 280005);
  }
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_3(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_303(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_25(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_430(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_f4(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_821(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_1d(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_ea0(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_d8(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_422(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_60(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_610(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_29(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_fe1(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_9d(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_380(re);
  libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_5f(re);
}

ساكن KRML_MUSTINLINE int32_t
libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_fe_by_fer(int32_t fe, int32_t fer)
{
  أرجع
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_reduce_element((int64_t)fe * (int64_t)fer);
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_قدم(
  Eurydice_arr_4d *simd_unit,
  int32_t zeta,
  ناپ_t index,
  ناپ_t قدم
)
{
  int32_t
  t =
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_fe_by_fer(simd_unit->انکڑے[index +
        قدم],
      zeta);
  simd_unit->انکڑے[index + قدم] = simd_unit->انکڑے[index] - t;
  simd_unit->انکڑے[index] += t;
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_at_layer_2(
  Eurydice_arr_4d *simd_unit,
  int32_t zeta
)
{
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_قدم(simd_unit, zeta, (ناپ_t)0U, (ناپ_t)4U);
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_قدم(simd_unit, zeta, (ناپ_t)1U, (ناپ_t)4U);
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_قدم(simd_unit, zeta, (ناپ_t)2U, (ناپ_t)4U);
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_قدم(simd_unit, zeta, (ناپ_t)3U, (ناپ_t)4U);
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_گیڑا(
  Eurydice_arr_a3 *re,
  ناپ_t index,
  int32_t zeta
)
{
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_at_layer_2(&re->انکڑے[index], zeta);
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_گیڑا(re, (ناپ_t)0U, 2706023);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_گیڑا(re, (ناپ_t)1U, 95776);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_گیڑا(re, (ناپ_t)2U, 3077325);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_گیڑا(re, (ناپ_t)3U, 3530437);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_گیڑا(re, (ناپ_t)4U, -1661693);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_گیڑا(re, (ناپ_t)5U, -3592148);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_گیڑا(re, (ناپ_t)6U, -2537516);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_گیڑا(re, (ناپ_t)7U, 3915439);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_گیڑا(re, (ناپ_t)8U, -3861115);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_گیڑا(re, (ناپ_t)9U, -3043716);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_گیڑا(re, (ناپ_t)10U, 3574422);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_گیڑا(re, (ناپ_t)11U, -2867647);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_گیڑا(re, (ناپ_t)12U, 3539968);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_گیڑا(re, (ناپ_t)13U, -300467);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_گیڑا(re, (ناپ_t)14U, 2348700);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_گیڑا(re, (ناپ_t)15U, -539299);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_گیڑا(re, (ناپ_t)16U, -1699267);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_گیڑا(re, (ناپ_t)17U, -1643818);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_گیڑا(re, (ناپ_t)18U, 3505694);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_گیڑا(re, (ناپ_t)19U, -3821735);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_گیڑا(re, (ناپ_t)20U, 3507263);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_گیڑا(re, (ناپ_t)21U, -2140649);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_گیڑا(re, (ناپ_t)22U, -1600420);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_گیڑا(re, (ناپ_t)23U, 3699596);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_گیڑا(re, (ناپ_t)24U, 811944);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_گیڑا(re, (ناپ_t)25U, 531354);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_گیڑا(re, (ناپ_t)26U, 954230);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_گیڑا(re, (ناپ_t)27U, 3881043);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_گیڑا(re, (ناپ_t)28U, 3900724);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_گیڑا(re, (ناپ_t)29U, -2556880);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_گیڑا(re, (ناپ_t)30U, 2071892);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_گیڑا(re, (ناپ_t)31U, -2797779);
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_at_layer_1(
  Eurydice_arr_4d *simd_unit,
  int32_t zeta1,
  int32_t zeta2
)
{
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_قدم(simd_unit, zeta1, (ناپ_t)0U, (ناپ_t)2U);
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_قدم(simd_unit, zeta1, (ناپ_t)1U, (ناپ_t)2U);
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_قدم(simd_unit, zeta2, (ناپ_t)4U, (ناپ_t)2U);
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_قدم(simd_unit, zeta2, (ناپ_t)5U, (ناپ_t)2U);
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_گیڑا(
  Eurydice_arr_a3 *re,
  ناپ_t index,
  int32_t zeta_0,
  int32_t zeta_1
)
{
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_at_layer_1(&re->انکڑے[index], zeta_0, zeta_1);
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_گیڑا(re, (ناپ_t)0U, -3930395, -1528703);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_گیڑا(re, (ناپ_t)1U, -3677745, -3041255);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_گیڑا(re, (ناپ_t)2U, -1452451, 3475950);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_گیڑا(re, (ناپ_t)3U, 2176455, -1585221);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_گیڑا(re, (ناپ_t)4U, -1257611, 1939314);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_گیڑا(re, (ناپ_t)5U, -4083598, -1000202);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_گیڑا(re, (ناپ_t)6U, -3190144, -3157330);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_گیڑا(re, (ناپ_t)7U, -3632928, 126922);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_گیڑا(re, (ناپ_t)8U, 3412210, -983419);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_گیڑا(re, (ناپ_t)9U, 2147896, 2715295);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_گیڑا(re, (ناپ_t)10U, -2967645, -3693493);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_گیڑا(re, (ناپ_t)11U, -411027, -2477047);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_گیڑا(re, (ناپ_t)12U, -671102, -1228525);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_گیڑا(re, (ناپ_t)13U, -22981, -1308169);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_گیڑا(re, (ناپ_t)14U, -381987, 1349076);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_گیڑا(re, (ناپ_t)15U, 1852771, -1430430);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_گیڑا(re, (ناپ_t)16U, -3343383, 264944);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_گیڑا(re, (ناپ_t)17U, 508951, 3097992);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_گیڑا(re, (ناپ_t)18U, 44288, -1100098);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_گیڑا(re, (ناپ_t)19U, 904516, 3958618);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_گیڑا(re, (ناپ_t)20U, -3724342, -8578);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_گیڑا(re, (ناپ_t)21U, 1653064, -3249728);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_گیڑا(re, (ناپ_t)22U, 2389356, -210977);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_گیڑا(re, (ناپ_t)23U, 759969, -1316856);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_گیڑا(re, (ناپ_t)24U, 189548, -3553272);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_گیڑا(re, (ناپ_t)25U, 3159746, -1851402);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_گیڑا(re, (ناپ_t)26U, -2409325, -177440);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_گیڑا(re, (ناپ_t)27U, 1315589, 1341330);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_گیڑا(re, (ناپ_t)28U, 1285669, -1584928);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_گیڑا(re, (ناپ_t)29U, -812732, -1439742);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_گیڑا(re, (ناپ_t)30U, -3019102, -3881060);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_گیڑا(re, (ناپ_t)31U, -3628969, 3839961);
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_at_layer_0(
  Eurydice_arr_4d *simd_unit,
  int32_t zeta0,
  int32_t zeta1,
  int32_t zeta2,
  int32_t zeta3
)
{
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_قدم(simd_unit, zeta0, (ناپ_t)0U, (ناپ_t)1U);
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_قدم(simd_unit, zeta1, (ناپ_t)2U, (ناپ_t)1U);
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_قدم(simd_unit, zeta2, (ناپ_t)4U, (ناپ_t)1U);
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_قدم(simd_unit, zeta3, (ناپ_t)6U, (ناپ_t)1U);
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_گیڑا(
  Eurydice_arr_a3 *re,
  ناپ_t index,
  int32_t zeta_0,
  int32_t zeta_1,
  int32_t zeta_2,
  int32_t zeta_3
)
{
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_at_layer_0(&re->انکڑے[index],
    zeta_0,
    zeta_1,
    zeta_2,
    zeta_3);
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)0U,
    2091667,
    3407706,
    2316500,
    3817976);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)1U,
    -3342478,
    2244091,
    -2446433,
    -3562462);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)2U,
    266997,
    2434439,
    -1235728,
    3513181);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)3U,
    -3520352,
    -3759364,
    -1197226,
    -3193378);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)4U,
    900702,
    1859098,
    909542,
    819034);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)5U,
    495491,
    -1613174,
    -43260,
    -522500);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)6U,
    -655327,
    -3122442,
    2031748,
    3207046);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)7U,
    -3556995,
    -525098,
    -768622,
    -3595838);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)8U,
    342297,
    286988,
    -2437823,
    4108315);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)9U,
    3437287,
    -3342277,
    1735879,
    203044);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)10U,
    2842341,
    2691481,
    -2590150,
    1265009);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)11U,
    4055324,
    1247620,
    2486353,
    1595974);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)12U,
    -3767016,
    1250494,
    2635921,
    -3548272);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)13U,
    -2994039,
    1869119,
    1903435,
    -1050970);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)14U,
    -1333058,
    1237275,
    -3318210,
    -1430225);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)15U,
    -451100,
    1312455,
    3306115,
    -1962642);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)16U,
    -1279661,
    1917081,
    -2546312,
    -1374803);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)17U,
    1500165,
    777191,
    2235880,
    3406031);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)18U,
    -542412,
    -2831860,
    -1671176,
    -1846953);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)19U,
    -2584293,
    -3724270,
    594136,
    -3776993);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)20U,
    -2013608,
    2432395,
    2454455,
    -164721);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)21U,
    1957272,
    3369112,
    185531,
    -1207385);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)22U,
    -3183426,
    162844,
    1616392,
    3014001);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)23U,
    810149,
    1652634,
    -3694233,
    -1799107);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)24U,
    -3038916,
    3523897,
    3866901,
    269760);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)25U,
    2213111,
    -975884,
    1717735,
    472078);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)26U,
    -426683,
    1723600,
    -1803090,
    1910376);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)27U,
    -1667432,
    -1104333,
    -260646,
    -3833893);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)28U,
    -2939036,
    -2235985,
    -420899,
    -2286327);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)29U,
    183443,
    -976891,
    1612842,
    -3545687);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)30U,
    -554416,
    3919660,
    -48306,
    -1362209);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)31U,
    3937738,
    1400424,
    -846154,
    1976782);
}

ساكن KRML_MUSTINLINE فراغ libcrux_ml_dsa_simd_portable_ntt_ntt(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_7(re);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_6(re);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_5(re);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_4(re);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_3(re);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2(re);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1(re);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0(re);
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ساكن مضمن فراغ libcrux_ml_dsa_simd_portable_ntt_65(Eurydice_arr_a3 *simd_units)
{
  libcrux_ml_dsa_simd_portable_ntt_ntt(simd_units);
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_قدم(
  Eurydice_arr_4d *simd_unit,
  int32_t zeta,
  ناپ_t index,
  ناپ_t قدم
)
{
  int32_t a_minus_b = simd_unit->انکڑے[index + قدم] - simd_unit->انکڑے[index];
  simd_unit->انکڑے[index] += simd_unit->انکڑے[index + قدم];
  simd_unit->انکڑے[index + قدم] =
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_fe_by_fer(a_minus_b,
      zeta);
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_invntt_simd_unit_invert_ntt_at_layer_0(
  Eurydice_arr_4d *simd_unit,
  int32_t zeta0,
  int32_t zeta1,
  int32_t zeta2,
  int32_t zeta3
)
{
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_قدم(simd_unit,
    zeta0,
    (ناپ_t)0U,
    (ناپ_t)1U);
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_قدم(simd_unit,
    zeta1,
    (ناپ_t)2U,
    (ناپ_t)1U);
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_قدم(simd_unit,
    zeta2,
    (ناپ_t)4U,
    (ناپ_t)1U);
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_قدم(simd_unit,
    zeta3,
    (ناپ_t)6U,
    (ناپ_t)1U);
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_گیڑا(
  Eurydice_arr_a3 *re,
  ناپ_t index,
  int32_t zeta0,
  int32_t zeta1,
  int32_t zeta2,
  int32_t zeta3
)
{
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_invert_ntt_at_layer_0(&re->انکڑے[index],
    zeta0,
    zeta1,
    zeta2,
    zeta3);
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)0U,
    1976782,
    -846154,
    1400424,
    3937738);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)1U,
    -1362209,
    -48306,
    3919660,
    -554416);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)2U,
    -3545687,
    1612842,
    -976891,
    183443);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)3U,
    -2286327,
    -420899,
    -2235985,
    -2939036);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)4U,
    -3833893,
    -260646,
    -1104333,
    -1667432);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)5U,
    1910376,
    -1803090,
    1723600,
    -426683);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)6U,
    472078,
    1717735,
    -975884,
    2213111);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)7U,
    269760,
    3866901,
    3523897,
    -3038916);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)8U,
    -1799107,
    -3694233,
    1652634,
    810149);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)9U,
    3014001,
    1616392,
    162844,
    -3183426);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)10U,
    -1207385,
    185531,
    3369112,
    1957272);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)11U,
    -164721,
    2454455,
    2432395,
    -2013608);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)12U,
    -3776993,
    594136,
    -3724270,
    -2584293);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)13U,
    -1846953,
    -1671176,
    -2831860,
    -542412);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)14U,
    3406031,
    2235880,
    777191,
    1500165);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)15U,
    -1374803,
    -2546312,
    1917081,
    -1279661);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)16U,
    -1962642,
    3306115,
    1312455,
    -451100);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)17U,
    -1430225,
    -3318210,
    1237275,
    -1333058);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)18U,
    -1050970,
    1903435,
    1869119,
    -2994039);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)19U,
    -3548272,
    2635921,
    1250494,
    -3767016);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)20U,
    1595974,
    2486353,
    1247620,
    4055324);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)21U,
    1265009,
    -2590150,
    2691481,
    2842341);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)22U,
    203044,
    1735879,
    -3342277,
    3437287);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)23U,
    4108315,
    -2437823,
    286988,
    342297);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)24U,
    -3595838,
    -768622,
    -525098,
    -3556995);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)25U,
    3207046,
    2031748,
    -3122442,
    -655327);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)26U,
    -522500,
    -43260,
    -1613174,
    495491);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)27U,
    819034,
    909542,
    1859098,
    900702);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)28U,
    -3193378,
    -1197226,
    -3759364,
    -3520352);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)29U,
    3513181,
    -1235728,
    2434439,
    266997);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)30U,
    -3562462,
    -2446433,
    2244091,
    -3342478);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_گیڑا(re,
    (ناپ_t)31U,
    3817976,
    2316500,
    3407706,
    2091667);
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_invntt_simd_unit_invert_ntt_at_layer_1(
  Eurydice_arr_4d *simd_unit,
  int32_t zeta0,
  int32_t zeta1
)
{
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_قدم(simd_unit,
    zeta0,
    (ناپ_t)0U,
    (ناپ_t)2U);
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_قدم(simd_unit,
    zeta0,
    (ناپ_t)1U,
    (ناپ_t)2U);
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_قدم(simd_unit,
    zeta1,
    (ناپ_t)4U,
    (ناپ_t)2U);
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_قدم(simd_unit,
    zeta1,
    (ناپ_t)5U,
    (ناپ_t)2U);
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_گیڑا(
  Eurydice_arr_a3 *re,
  ناپ_t index,
  int32_t zeta_00,
  int32_t zeta_01
)
{
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_invert_ntt_at_layer_1(&re->انکڑے[index],
    zeta_00,
    zeta_01);
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_گیڑا(re,
    (ناپ_t)0U,
    3839961,
    -3628969);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_گیڑا(re,
    (ناپ_t)1U,
    -3881060,
    -3019102);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_گیڑا(re,
    (ناپ_t)2U,
    -1439742,
    -812732);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_گیڑا(re,
    (ناپ_t)3U,
    -1584928,
    1285669);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_گیڑا(re,
    (ناپ_t)4U,
    1341330,
    1315589);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_گیڑا(re,
    (ناپ_t)5U,
    -177440,
    -2409325);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_گیڑا(re,
    (ناپ_t)6U,
    -1851402,
    3159746);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_گیڑا(re,
    (ناپ_t)7U,
    -3553272,
    189548);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_گیڑا(re,
    (ناپ_t)8U,
    -1316856,
    759969);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_گیڑا(re,
    (ناپ_t)9U,
    -210977,
    2389356);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_گیڑا(re,
    (ناپ_t)10U,
    -3249728,
    1653064);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_گیڑا(re,
    (ناپ_t)11U,
    -8578,
    -3724342);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_گیڑا(re,
    (ناپ_t)12U,
    3958618,
    904516);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_گیڑا(re,
    (ناپ_t)13U,
    -1100098,
    44288);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_گیڑا(re,
    (ناپ_t)14U,
    3097992,
    508951);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_گیڑا(re,
    (ناپ_t)15U,
    264944,
    -3343383);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_گیڑا(re,
    (ناپ_t)16U,
    -1430430,
    1852771);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_گیڑا(re,
    (ناپ_t)17U,
    1349076,
    -381987);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_گیڑا(re,
    (ناپ_t)18U,
    -1308169,
    -22981);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_گیڑا(re,
    (ناپ_t)19U,
    -1228525,
    -671102);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_گیڑا(re,
    (ناپ_t)20U,
    -2477047,
    -411027);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_گیڑا(re,
    (ناپ_t)21U,
    -3693493,
    -2967645);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_گیڑا(re,
    (ناپ_t)22U,
    2715295,
    2147896);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_گیڑا(re,
    (ناپ_t)23U,
    -983419,
    3412210);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_گیڑا(re,
    (ناپ_t)24U,
    126922,
    -3632928);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_گیڑا(re,
    (ناپ_t)25U,
    -3157330,
    -3190144);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_گیڑا(re,
    (ناپ_t)26U,
    -1000202,
    -4083598);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_گیڑا(re,
    (ناپ_t)27U,
    1939314,
    -1257611);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_گیڑا(re,
    (ناپ_t)28U,
    -1585221,
    2176455);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_گیڑا(re,
    (ناپ_t)29U,
    3475950,
    -1452451);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_گیڑا(re,
    (ناپ_t)30U,
    -3041255,
    -3677745);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_گیڑا(re,
    (ناپ_t)31U,
    -1528703,
    -3930395);
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_invntt_simd_unit_invert_ntt_at_layer_2(
  Eurydice_arr_4d *simd_unit,
  int32_t zeta
)
{
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_قدم(simd_unit,
    zeta,
    (ناپ_t)0U,
    (ناپ_t)4U);
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_قدم(simd_unit,
    zeta,
    (ناپ_t)1U,
    (ناپ_t)4U);
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_قدم(simd_unit,
    zeta,
    (ناپ_t)2U,
    (ناپ_t)4U);
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_قدم(simd_unit,
    zeta,
    (ناپ_t)3U,
    (ناپ_t)4U);
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_گیڑا(
  Eurydice_arr_a3 *re,
  ناپ_t index,
  int32_t zeta1
)
{
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_invert_ntt_at_layer_2(&re->انکڑے[index], zeta1);
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_گیڑا(re, (ناپ_t)0U, -2797779);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_گیڑا(re, (ناپ_t)1U, 2071892);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_گیڑا(re, (ناپ_t)2U, -2556880);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_گیڑا(re, (ناپ_t)3U, 3900724);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_گیڑا(re, (ناپ_t)4U, 3881043);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_گیڑا(re, (ناپ_t)5U, 954230);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_گیڑا(re, (ناپ_t)6U, 531354);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_گیڑا(re, (ناپ_t)7U, 811944);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_گیڑا(re, (ناپ_t)8U, 3699596);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_گیڑا(re, (ناپ_t)9U, -1600420);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_گیڑا(re, (ناپ_t)10U, -2140649);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_گیڑا(re, (ناپ_t)11U, 3507263);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_گیڑا(re, (ناپ_t)12U, -3821735);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_گیڑا(re, (ناپ_t)13U, 3505694);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_گیڑا(re, (ناپ_t)14U, -1643818);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_گیڑا(re, (ناپ_t)15U, -1699267);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_گیڑا(re, (ناپ_t)16U, -539299);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_گیڑا(re, (ناپ_t)17U, 2348700);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_گیڑا(re, (ناپ_t)18U, -300467);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_گیڑا(re, (ناپ_t)19U, 3539968);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_گیڑا(re, (ناپ_t)20U, -2867647);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_گیڑا(re, (ناپ_t)21U, 3574422);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_گیڑا(re, (ناپ_t)22U, -3043716);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_گیڑا(re, (ناپ_t)23U, -3861115);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_گیڑا(re, (ناپ_t)24U, 3915439);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_گیڑا(re, (ناپ_t)25U, -2537516);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_گیڑا(re, (ناپ_t)26U, -3592148);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_گیڑا(re, (ناپ_t)27U, -1661693);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_گیڑا(re, (ناپ_t)28U, 3530437);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_گیڑا(re, (ناپ_t)29U, 3077325);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_گیڑا(re, (ناپ_t)30U, 95776);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_گیڑا(re, (ناپ_t)31U, 2706023);
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 0
- STEP_BY= 1
- ZETA= 280005
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_30(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)0U + (ناپ_t)1U; i++)
  {
    ناپ_t j = i;
    Eurydice_arr_4d rej = re->انکڑے[j];
    Eurydice_arr_4d rejs = re->انکڑے[j + (ناپ_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_جوڑو(&re->انکڑے[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_گھٹاؤ(&re->انکڑے[j + (ناپ_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->انکڑے[j +
        (ناپ_t)1U],
      280005);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 2
- STEP_BY= 1
- ZETA= 4010497
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_25(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)2U; i < (ناپ_t)2U + (ناپ_t)1U; i++)
  {
    ناپ_t j = i;
    Eurydice_arr_4d rej = re->انکڑے[j];
    Eurydice_arr_4d rejs = re->انکڑے[j + (ناپ_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_جوڑو(&re->انکڑے[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_گھٹاؤ(&re->انکڑے[j + (ناپ_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->انکڑے[j +
        (ناپ_t)1U],
      4010497);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 4
- STEP_BY= 1
- ZETA= -19422
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_43(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)4U; i < (ناپ_t)4U + (ناپ_t)1U; i++)
  {
    ناپ_t j = i;
    Eurydice_arr_4d rej = re->انکڑے[j];
    Eurydice_arr_4d rejs = re->انکڑے[j + (ناپ_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_جوڑو(&re->انکڑے[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_گھٹاؤ(&re->انکڑے[j + (ناپ_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->انکڑے[j +
        (ناپ_t)1U],
      -19422);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 6
- STEP_BY= 1
- ZETA= 1757237
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_f4(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)6U; i < (ناپ_t)6U + (ناپ_t)1U; i++)
  {
    ناپ_t j = i;
    Eurydice_arr_4d rej = re->انکڑے[j];
    Eurydice_arr_4d rejs = re->انکڑے[j + (ناپ_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_جوڑو(&re->انکڑے[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_گھٹاؤ(&re->انکڑے[j + (ناپ_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->انکڑے[j +
        (ناپ_t)1U],
      1757237);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 8
- STEP_BY= 1
- ZETA= -3277672
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_82(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)8U; i < (ناپ_t)8U + (ناپ_t)1U; i++)
  {
    ناپ_t j = i;
    Eurydice_arr_4d rej = re->انکڑے[j];
    Eurydice_arr_4d rejs = re->انکڑے[j + (ناپ_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_جوڑو(&re->انکڑے[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_گھٹاؤ(&re->انکڑے[j + (ناپ_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->انکڑے[j +
        (ناپ_t)1U],
      -3277672);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 10
- STEP_BY= 1
- ZETA= -1399561
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_1d(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)10U; i < (ناپ_t)10U + (ناپ_t)1U; i++)
  {
    ناپ_t j = i;
    Eurydice_arr_4d rej = re->انکڑے[j];
    Eurydice_arr_4d rejs = re->انکڑے[j + (ناپ_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_جوڑو(&re->انکڑے[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_گھٹاؤ(&re->انکڑے[j + (ناپ_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->انکڑے[j +
        (ناپ_t)1U],
      -1399561);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 12
- STEP_BY= 1
- ZETA= -3859737
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_ea(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)12U; i < (ناپ_t)12U + (ناپ_t)1U; i++)
  {
    ناپ_t j = i;
    Eurydice_arr_4d rej = re->انکڑے[j];
    Eurydice_arr_4d rejs = re->انکڑے[j + (ناپ_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_جوڑو(&re->انکڑے[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_گھٹاؤ(&re->انکڑے[j + (ناپ_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->انکڑے[j +
        (ناپ_t)1U],
      -3859737);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 14
- STEP_BY= 1
- ZETA= -2118186
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_d8(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)14U; i < (ناپ_t)14U + (ناپ_t)1U; i++)
  {
    ناپ_t j = i;
    Eurydice_arr_4d rej = re->انکڑے[j];
    Eurydice_arr_4d rejs = re->انکڑے[j + (ناپ_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_جوڑو(&re->انکڑے[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_گھٹاؤ(&re->انکڑے[j + (ناپ_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->انکڑے[j +
        (ناپ_t)1U],
      -2118186);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 16
- STEP_BY= 1
- ZETA= -2108549
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_42(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)16U; i < (ناپ_t)16U + (ناپ_t)1U; i++)
  {
    ناپ_t j = i;
    Eurydice_arr_4d rej = re->انکڑے[j];
    Eurydice_arr_4d rejs = re->انکڑے[j + (ناپ_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_جوڑو(&re->انکڑے[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_گھٹاؤ(&re->انکڑے[j + (ناپ_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->انکڑے[j +
        (ناپ_t)1U],
      -2108549);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 18
- STEP_BY= 1
- ZETA= 2619752
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_60(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)18U; i < (ناپ_t)18U + (ناپ_t)1U; i++)
  {
    ناپ_t j = i;
    Eurydice_arr_4d rej = re->انکڑے[j];
    Eurydice_arr_4d rejs = re->انکڑے[j + (ناپ_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_جوڑو(&re->انکڑے[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_گھٹاؤ(&re->انکڑے[j + (ناپ_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->انکڑے[j +
        (ناپ_t)1U],
      2619752);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 20
- STEP_BY= 1
- ZETA= -1119584
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_61(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)20U; i < (ناپ_t)20U + (ناپ_t)1U; i++)
  {
    ناپ_t j = i;
    Eurydice_arr_4d rej = re->انکڑے[j];
    Eurydice_arr_4d rejs = re->انکڑے[j + (ناپ_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_جوڑو(&re->انکڑے[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_گھٹاؤ(&re->انکڑے[j + (ناپ_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->انکڑے[j +
        (ناپ_t)1U],
      -1119584);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 22
- STEP_BY= 1
- ZETA= -549488
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_29(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)22U; i < (ناپ_t)22U + (ناپ_t)1U; i++)
  {
    ناپ_t j = i;
    Eurydice_arr_4d rej = re->انکڑے[j];
    Eurydice_arr_4d rejs = re->انکڑے[j + (ناپ_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_جوڑو(&re->انکڑے[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_گھٹاؤ(&re->انکڑے[j + (ناپ_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->انکڑے[j +
        (ناپ_t)1U],
      -549488);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 24
- STEP_BY= 1
- ZETA= 3585928
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_fe(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)24U; i < (ناپ_t)24U + (ناپ_t)1U; i++)
  {
    ناپ_t j = i;
    Eurydice_arr_4d rej = re->انکڑے[j];
    Eurydice_arr_4d rejs = re->انکڑے[j + (ناپ_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_جوڑو(&re->انکڑے[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_گھٹاؤ(&re->انکڑے[j + (ناپ_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->انکڑے[j +
        (ناپ_t)1U],
      3585928);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 26
- STEP_BY= 1
- ZETA= -1079900
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_9d(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)26U; i < (ناپ_t)26U + (ناپ_t)1U; i++)
  {
    ناپ_t j = i;
    Eurydice_arr_4d rej = re->انکڑے[j];
    Eurydice_arr_4d rejs = re->انکڑے[j + (ناپ_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_جوڑو(&re->انکڑے[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_گھٹاؤ(&re->انکڑے[j + (ناپ_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->انکڑے[j +
        (ناپ_t)1U],
      -1079900);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 28
- STEP_BY= 1
- ZETA= 1024112
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_38(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)28U; i < (ناپ_t)28U + (ناپ_t)1U; i++)
  {
    ناپ_t j = i;
    Eurydice_arr_4d rej = re->انکڑے[j];
    Eurydice_arr_4d rejs = re->انکڑے[j + (ناپ_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_جوڑو(&re->انکڑے[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_گھٹاؤ(&re->انکڑے[j + (ناپ_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->انکڑے[j +
        (ناپ_t)1U],
      1024112);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 30
- STEP_BY= 1
- ZETA= 2725464
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_5f(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)30U; i < (ناپ_t)30U + (ناپ_t)1U; i++)
  {
    ناپ_t j = i;
    Eurydice_arr_4d rej = re->انکڑے[j];
    Eurydice_arr_4d rejs = re->انکڑے[j + (ناپ_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_جوڑو(&re->انکڑے[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_گھٹاؤ(&re->انکڑے[j + (ناپ_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->انکڑے[j +
        (ناپ_t)1U],
      2725464);
  }
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_3(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_30(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_25(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_43(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_f4(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_82(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_1d(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_ea(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_d8(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_42(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_60(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_61(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_29(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_fe(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_9d(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_38(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_5f(re);
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 0
- STEP_BY= 2
- ZETA= 2680103
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_300(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)0U + (ناپ_t)2U; i++)
  {
    ناپ_t j = i;
    Eurydice_arr_4d rej = re->انکڑے[j];
    Eurydice_arr_4d rejs = re->انکڑے[j + (ناپ_t)2U];
    libcrux_ml_dsa_simd_portable_arithmetic_جوڑو(&re->انکڑے[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_گھٹاؤ(&re->انکڑے[j + (ناپ_t)2U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->انکڑے[j +
        (ناپ_t)2U],
      2680103);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 4
- STEP_BY= 2
- ZETA= 3111497
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_430(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)4U; i < (ناپ_t)4U + (ناپ_t)2U; i++)
  {
    ناپ_t j = i;
    Eurydice_arr_4d rej = re->انکڑے[j];
    Eurydice_arr_4d rejs = re->انکڑے[j + (ناپ_t)2U];
    libcrux_ml_dsa_simd_portable_arithmetic_جوڑو(&re->انکڑے[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_گھٹاؤ(&re->انکڑے[j + (ناپ_t)2U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->انکڑے[j +
        (ناپ_t)2U],
      3111497);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 8
- STEP_BY= 2
- ZETA= -2884855
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_820(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)8U; i < (ناپ_t)8U + (ناپ_t)2U; i++)
  {
    ناپ_t j = i;
    Eurydice_arr_4d rej = re->انکڑے[j];
    Eurydice_arr_4d rejs = re->انکڑے[j + (ناپ_t)2U];
    libcrux_ml_dsa_simd_portable_arithmetic_جوڑو(&re->انکڑے[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_گھٹاؤ(&re->انکڑے[j + (ناپ_t)2U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->انکڑے[j +
        (ناپ_t)2U],
      -2884855);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 12
- STEP_BY= 2
- ZETA= 3119733
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_ea0(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)12U; i < (ناپ_t)12U + (ناپ_t)2U; i++)
  {
    ناپ_t j = i;
    Eurydice_arr_4d rej = re->انکڑے[j];
    Eurydice_arr_4d rejs = re->انکڑے[j + (ناپ_t)2U];
    libcrux_ml_dsa_simd_portable_arithmetic_جوڑو(&re->انکڑے[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_گھٹاؤ(&re->انکڑے[j + (ناپ_t)2U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->انکڑے[j +
        (ناپ_t)2U],
      3119733);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 16
- STEP_BY= 2
- ZETA= -2091905
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_420(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)16U; i < (ناپ_t)16U + (ناپ_t)2U; i++)
  {
    ناپ_t j = i;
    Eurydice_arr_4d rej = re->انکڑے[j];
    Eurydice_arr_4d rejs = re->انکڑے[j + (ناپ_t)2U];
    libcrux_ml_dsa_simd_portable_arithmetic_جوڑو(&re->انکڑے[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_گھٹاؤ(&re->انکڑے[j + (ناپ_t)2U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->انکڑے[j +
        (ناپ_t)2U],
      -2091905);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 20
- STEP_BY= 2
- ZETA= -359251
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_610(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)20U; i < (ناپ_t)20U + (ناپ_t)2U; i++)
  {
    ناپ_t j = i;
    Eurydice_arr_4d rej = re->انکڑے[j];
    Eurydice_arr_4d rejs = re->انکڑے[j + (ناپ_t)2U];
    libcrux_ml_dsa_simd_portable_arithmetic_جوڑو(&re->انکڑے[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_گھٹاؤ(&re->انکڑے[j + (ناپ_t)2U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->انکڑے[j +
        (ناپ_t)2U],
      -359251);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 24
- STEP_BY= 2
- ZETA= 2353451
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_fe0(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)24U; i < (ناپ_t)24U + (ناپ_t)2U; i++)
  {
    ناپ_t j = i;
    Eurydice_arr_4d rej = re->انکڑے[j];
    Eurydice_arr_4d rejs = re->انکڑے[j + (ناپ_t)2U];
    libcrux_ml_dsa_simd_portable_arithmetic_جوڑو(&re->انکڑے[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_گھٹاؤ(&re->انکڑے[j + (ناپ_t)2U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->انکڑے[j +
        (ناپ_t)2U],
      2353451);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 28
- STEP_BY= 2
- ZETA= 1826347
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_380(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)28U; i < (ناپ_t)28U + (ناپ_t)2U; i++)
  {
    ناپ_t j = i;
    Eurydice_arr_4d rej = re->انکڑے[j];
    Eurydice_arr_4d rejs = re->انکڑے[j + (ناپ_t)2U];
    libcrux_ml_dsa_simd_portable_arithmetic_جوڑو(&re->انکڑے[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_گھٹاؤ(&re->انکڑے[j + (ناپ_t)2U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->انکڑے[j +
        (ناپ_t)2U],
      1826347);
  }
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_4(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_300(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_430(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_820(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_ea0(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_420(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_610(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_fe0(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_380(re);
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 0
- STEP_BY= 4
- ZETA= 466468
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_301(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)0U + (ناپ_t)4U; i++)
  {
    ناپ_t j = i;
    Eurydice_arr_4d rej = re->انکڑے[j];
    Eurydice_arr_4d rejs = re->انکڑے[j + (ناپ_t)4U];
    libcrux_ml_dsa_simd_portable_arithmetic_جوڑو(&re->انکڑے[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_گھٹاؤ(&re->انکڑے[j + (ناپ_t)4U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->انکڑے[j +
        (ناپ_t)4U],
      466468);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 8
- STEP_BY= 4
- ZETA= -876248
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_821(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)8U; i < (ناپ_t)8U + (ناپ_t)4U; i++)
  {
    ناپ_t j = i;
    Eurydice_arr_4d rej = re->انکڑے[j];
    Eurydice_arr_4d rejs = re->انکڑے[j + (ناپ_t)4U];
    libcrux_ml_dsa_simd_portable_arithmetic_جوڑو(&re->انکڑے[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_گھٹاؤ(&re->انکڑے[j + (ناپ_t)4U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->انکڑے[j +
        (ناپ_t)4U],
      -876248);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 16
- STEP_BY= 4
- ZETA= -777960
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_421(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)16U; i < (ناپ_t)16U + (ناپ_t)4U; i++)
  {
    ناپ_t j = i;
    Eurydice_arr_4d rej = re->انکڑے[j];
    Eurydice_arr_4d rejs = re->انکڑے[j + (ناپ_t)4U];
    libcrux_ml_dsa_simd_portable_arithmetic_جوڑو(&re->انکڑے[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_گھٹاؤ(&re->انکڑے[j + (ناپ_t)4U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->انکڑے[j +
        (ناپ_t)4U],
      -777960);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 24
- STEP_BY= 4
- ZETA= 237124
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_fe1(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)24U; i < (ناپ_t)24U + (ناپ_t)4U; i++)
  {
    ناپ_t j = i;
    Eurydice_arr_4d rej = re->انکڑے[j];
    Eurydice_arr_4d rejs = re->انکڑے[j + (ناپ_t)4U];
    libcrux_ml_dsa_simd_portable_arithmetic_جوڑو(&re->انکڑے[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_گھٹاؤ(&re->انکڑے[j + (ناپ_t)4U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->انکڑے[j +
        (ناپ_t)4U],
      237124);
  }
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_5(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_301(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_821(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_421(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_fe1(re);
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 0
- STEP_BY= 8
- ZETA= -518909
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_302(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)0U + (ناپ_t)8U; i++)
  {
    ناپ_t j = i;
    Eurydice_arr_4d rej = re->انکڑے[j];
    Eurydice_arr_4d rejs = re->انکڑے[j + (ناپ_t)8U];
    libcrux_ml_dsa_simd_portable_arithmetic_جوڑو(&re->انکڑے[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_گھٹاؤ(&re->انکڑے[j + (ناپ_t)8U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->انکڑے[j +
        (ناپ_t)8U],
      -518909);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 16
- STEP_BY= 8
- ZETA= -2608894
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_422(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)16U; i < (ناپ_t)16U + (ناپ_t)8U; i++)
  {
    ناپ_t j = i;
    Eurydice_arr_4d rej = re->انکڑے[j];
    Eurydice_arr_4d rejs = re->انکڑے[j + (ناپ_t)8U];
    libcrux_ml_dsa_simd_portable_arithmetic_جوڑو(&re->انکڑے[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_گھٹاؤ(&re->انکڑے[j + (ناپ_t)8U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->انکڑے[j +
        (ناپ_t)8U],
      -2608894);
  }
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_6(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_302(re);
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_422(re);
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 0
- STEP_BY= 16
- ZETA= 25847
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_303(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)0U + (ناپ_t)16U; i++)
  {
    ناپ_t j = i;
    Eurydice_arr_4d rej = re->انکڑے[j];
    Eurydice_arr_4d rejs = re->انکڑے[j + (ناپ_t)16U];
    libcrux_ml_dsa_simd_portable_arithmetic_جوڑو(&re->انکڑے[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_گھٹاؤ(&re->انکڑے[j + (ناپ_t)16U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->انکڑے[j +
        (ناپ_t)16U],
      25847);
  }
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_7(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_303(re);
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_montgomery(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0(re);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1(re);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2(re);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_3(re);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_4(re);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_5(re);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_6(re);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_7(re);
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)32U; i++)
  {
    ناپ_t i0 = i;
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->انکڑے[i0], 41978);
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ساكن مضمن فراغ
libcrux_ml_dsa_simd_portable_invert_ntt_montgomery_65(Eurydice_arr_a3 *simd_units)
{
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_montgomery(simd_units);
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ساكن مضمن فراغ
libcrux_ml_dsa_simd_portable_barrett_reduce_simd_unit_65(Eurydice_arr_4d *simd_unit)
{
  libcrux_ml_dsa_simd_portable_arithmetic_barrett_reduce_simd_unit(simd_unit);
}

#تعریف_کرو LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_ERROR_RING_ELEMENT_ناپ (libcrux_ml_dsa_constants_error_ring_element_ناپ(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_بٹ_فی_ERROR_COEFFICIENT))

#تعریف_کرو LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_COMMITMENT_RING_ELEMENT_ناپ (libcrux_ml_dsa_constants_commitment_ring_element_ناپ(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_بٹ_فی_COMMITMENT_COEFFICIENT))

#تعریف_کرو LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_BETA (libcrux_ml_dsa_constants_beta(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ONES_وچ_VERIFIER_CHALLENGE, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ETA))

#تعریف_کرو LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_GAMMA1_RING_ELEMENT_ناپ (libcrux_ml_dsa_constants_gamma1_ring_element_ناپ(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_بٹ_فی_GAMMA1_COEFFICIENT))

#تعریف_کرو LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_VERIFICATION_کلید_ناپ (libcrux_ml_dsa_constants_verification_کلید_ناپ(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_صفاں_وچ_A))

#تعریف_کرو LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_SIGNATURE_ناپ (libcrux_ml_dsa_constants_signature_ناپ(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_صفاں_وچ_A, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_وچ_A, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_MAX_ONES_وچ_HINT, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COMMITMENT_HASH_ناپ, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_بٹ_فی_GAMMA1_COEFFICIENT))

#تعریف_کرو LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_ERROR_RING_ELEMENT_ناپ (libcrux_ml_dsa_constants_error_ring_element_ناپ(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_بٹ_فی_ERROR_COEFFICIENT))

#تعریف_کرو LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_COMMITMENT_RING_ELEMENT_ناپ (libcrux_ml_dsa_constants_commitment_ring_element_ناپ(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_بٹ_فی_COMMITMENT_COEFFICIENT))

#تعریف_کرو LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_BETA (libcrux_ml_dsa_constants_beta(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ONES_وچ_VERIFIER_CHALLENGE, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ETA))

#تعریف_کرو LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_GAMMA1_RING_ELEMENT_ناپ (libcrux_ml_dsa_constants_gamma1_ring_element_ناپ(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_بٹ_فی_GAMMA1_COEFFICIENT))

#تعریف_کرو LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_VERIFICATION_کلید_ناپ (libcrux_ml_dsa_constants_verification_کلید_ناپ(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_صفاں_وچ_A))

#تعریف_کرو LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_SIGNATURE_ناپ (libcrux_ml_dsa_constants_signature_ناپ(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_صفاں_وچ_A, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_وچ_A, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_MAX_ONES_وچ_HINT, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COMMITMENT_HASH_ناپ, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_بٹ_فی_GAMMA1_COEFFICIENT))

#تعریف_کرو LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_COMMITMENT_سمتیہ_ناپ (libcrux_ml_dsa_constants_commitment_سمتیہ_ناپ(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_بٹ_فی_COMMITMENT_COEFFICIENT, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_صفاں_وچ_A))

/**
A monomorphic instance of libcrux_ml_dsa.types.MLDSASigningKey
with const generics
- $2560size_t
*/
تعريفنوع Eurydice_arr_10 libcrux_ml_dsa_types_MLDSASigning_کلید_11;

تعريفنوع Eurydice_arr_10 libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_MLDSA44_Signing_کلید;

/**
A monomorphic instance of libcrux_ml_dsa.types.MLDSAVerificationKey
with const generics
- $1312size_t
*/
تعريفنوع Eurydice_arr_02 libcrux_ml_dsa_types_MLDSAVerification_کلید_1d;

تعريفنوع Eurydice_arr_02 libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_MLDSA44_Verification_کلید;

#تعریف_کرو LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_صف_کالم (LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_صفاں_وچ_A + LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_وچ_A)

#تعریف_کرو LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_صف_X_کالم (LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_صفاں_وچ_A * LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_وچ_A)

#تعریف_کرو LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_SIGNING_کلید_ناپ (libcrux_ml_dsa_constants_signing_کلید_ناپ(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_صفاں_وچ_A, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_وچ_A, LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_ERROR_RING_ELEMENT_ناپ))

#تعریف_کرو LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_COMMITMENT_سمتیہ_ناپ (libcrux_ml_dsa_constants_commitment_سمتیہ_ناپ(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_بٹ_فی_COMMITMENT_COEFFICIENT, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_صفاں_وچ_A))

/**
A monomorphic instance of libcrux_ml_dsa.types.MLDSASigningKey
with const generics
- $4032size_t
*/
تعريفنوع Eurydice_arr_24 libcrux_ml_dsa_types_MLDSASigning_کلید_8e;

تعريفنوع Eurydice_arr_24 libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_MLDSA65_Signing_کلید;

/**
A monomorphic instance of libcrux_ml_dsa.types.MLDSAVerificationKey
with const generics
- $1952size_t
*/
تعريفنوع Eurydice_arr_29 libcrux_ml_dsa_types_MLDSAVerification_کلید_c8;

تعريفنوع Eurydice_arr_29 libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_MLDSA65_Verification_کلید;

#تعریف_کرو LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_صف_کالم (LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_صفاں_وچ_A + LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_وچ_A)

#تعریف_کرو LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_صف_X_کالم (LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_صفاں_وچ_A * LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_وچ_A)

#تعریف_کرو LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_SIGNING_کلید_ناپ (libcrux_ml_dsa_constants_signing_کلید_ناپ(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_صفاں_وچ_A, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_وچ_A, LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_ERROR_RING_ELEMENT_ناپ))

#تعریف_کرو LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_COMMITMENT_سمتیہ_ناپ (libcrux_ml_dsa_constants_commitment_سمتیہ_ناپ(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_بٹ_فی_COMMITMENT_COEFFICIENT, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_صفاں_وچ_A))

/**
A monomorphic instance of libcrux_ml_dsa.types.MLDSASigningKey
with const generics
- $4896size_t
*/
تعريفنوع Eurydice_arr_e2 libcrux_ml_dsa_types_MLDSASigning_کلید_b8;

تعريفنوع Eurydice_arr_e2 libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_MLDSA87_Signing_کلید;

/**
A monomorphic instance of libcrux_ml_dsa.types.MLDSAVerificationKey
with const generics
- $2592size_t
*/
تعريفنوع Eurydice_arr_43 libcrux_ml_dsa_types_MLDSAVerification_کلید_e9;

تعريفنوع Eurydice_arr_43 libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_MLDSA87_Verification_کلید;

#تعریف_کرو LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_صف_کالم (LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_صفاں_وچ_A + LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_وچ_A)

#تعریف_کرو LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_صف_X_کالم (LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_صفاں_وچ_A * LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_وچ_A)

#تعریف_کرو LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_SIGNING_کلید_ناپ (libcrux_ml_dsa_constants_signing_کلید_ناپ(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_صفاں_وچ_A, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_وچ_A, LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_ERROR_RING_ELEMENT_ناپ))

#تعریف_کرو LIBCRUX_ML_DSA_PRE_HASH_PRE_HASH_OID_LEN ((ناپ_t)11U)

تعريفنوع Eurydice_arr_c9 libcrux_ml_dsa_pre_hash_PreHashOID;

تعريفنوع core_نتیجہ_نتیجہ_a8 libcrux_ml_dsa_pre_hash_Pre_Hash_نتیجہ;

/**
This function found in impl {core::convert::From<libcrux_ml_dsa::pre_hash::DomainSeparationError> for libcrux_ml_dsa::types::SigningError}
*/
ساكن مضمن libcrux_ml_dsa_types_SigningError
libcrux_ml_dsa_pre_hash_from_96(libcrux_ml_dsa_pre_hash_DomainSeparationError e)
{
  أرجع libcrux_ml_dsa_types_SigningError_ContextTooLongError;
}

/**
This function found in impl {core::convert::From<libcrux_ml_dsa::pre_hash::DomainSeparationError> for libcrux_ml_dsa::types::VerificationError}
*/
ساكن مضمن libcrux_ml_dsa_types_VerificationError
libcrux_ml_dsa_pre_hash_from_bf(libcrux_ml_dsa_pre_hash_DomainSeparationError e)
{
  أرجع libcrux_ml_dsa_types_VerificationError_VerificationContextTooLongError;
}

#تعریف_کرو LIBCRUX_ML_DSA_SIMD_PORTABLE_INVNTT_INVERT_NTT_AT_LAYER_3_قدم ((ناپ_t)8U)

#تعریف_کرو LIBCRUX_ML_DSA_SIMD_PORTABLE_INVNTT_INVERT_NTT_AT_LAYER_3_قدم_BY ((ناپ_t)1U)

#تعریف_کرو LIBCRUX_ML_DSA_SIMD_PORTABLE_INVNTT_INVERT_NTT_AT_LAYER_4_قدم ((ناپ_t)16U)

#تعریف_کرو LIBCRUX_ML_DSA_SIMD_PORTABLE_INVNTT_INVERT_NTT_AT_LAYER_4_قدم_BY ((ناپ_t)2U)

#تعریف_کرو LIBCRUX_ML_DSA_SIMD_PORTABLE_INVNTT_INVERT_NTT_AT_LAYER_5_قدم ((ناپ_t)32U)

#تعریف_کرو LIBCRUX_ML_DSA_SIMD_PORTABLE_INVNTT_INVERT_NTT_AT_LAYER_5_قدم_BY ((ناپ_t)4U)

#تعریف_کرو LIBCRUX_ML_DSA_SIMD_PORTABLE_INVNTT_INVERT_NTT_AT_LAYER_6_قدم ((ناپ_t)64U)

#تعریف_کرو LIBCRUX_ML_DSA_SIMD_PORTABLE_INVNTT_INVERT_NTT_AT_LAYER_6_قدم_BY ((ناپ_t)8U)

#تعریف_کرو LIBCRUX_ML_DSA_SIMD_PORTABLE_INVNTT_INVERT_NTT_AT_LAYER_7_قدم ((ناپ_t)128U)

#تعریف_کرو LIBCRUX_ML_DSA_SIMD_PORTABLE_INVNTT_INVERT_NTT_AT_LAYER_7_قدم_BY ((ناپ_t)16U)

#تعریف_کرو LIBCRUX_ML_DSA_SIMD_PORTABLE_NTT_NTT_AT_LAYER_3_قدم ((ناپ_t)8U)

#تعریف_کرو LIBCRUX_ML_DSA_SIMD_PORTABLE_NTT_NTT_AT_LAYER_3_قدم_BY ((ناپ_t)1U)

#تعریف_کرو LIBCRUX_ML_DSA_SIMD_PORTABLE_NTT_NTT_AT_LAYER_4_قدم ((ناپ_t)16U)

#تعریف_کرو LIBCRUX_ML_DSA_SIMD_PORTABLE_NTT_NTT_AT_LAYER_4_قدم_BY ((ناپ_t)2U)

#تعریف_کرو LIBCRUX_ML_DSA_SIMD_PORTABLE_NTT_NTT_AT_LAYER_5_قدم ((ناپ_t)32U)

#تعریف_کرو LIBCRUX_ML_DSA_SIMD_PORTABLE_NTT_NTT_AT_LAYER_5_قدم_BY ((ناپ_t)4U)

#تعریف_کرو LIBCRUX_ML_DSA_SIMD_PORTABLE_NTT_NTT_AT_LAYER_6_قدم ((ناپ_t)64U)

#تعریف_کرو LIBCRUX_ML_DSA_SIMD_PORTABLE_NTT_NTT_AT_LAYER_6_قدم_BY ((ناپ_t)8U)

#تعریف_کرو LIBCRUX_ML_DSA_SIMD_PORTABLE_NTT_NTT_AT_LAYER_7_قدم ((ناپ_t)128U)

#تعریف_کرو LIBCRUX_ML_DSA_SIMD_PORTABLE_NTT_NTT_AT_LAYER_7_قدم_BY ((ناپ_t)16U)

تعريفنوع int32_t libcrux_ml_dsa_simd_portable_سمتیہ_type_میدان_Element;

/**
This function found in impl {core::clone::Clone for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ساكن مضمن Eurydice_arr_4d
libcrux_ml_dsa_simd_portable_سمتیہ_type_clone_a5(ثابت Eurydice_arr_4d *self)
{
  أرجع self[0U];
}

تعريفنوع int32_t libcrux_ml_dsa_simd_traits_میدان_Element_Times_Montgomery_R;

تعريفنوع Eurydice_arr_93 libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_MLDSA87Signature;

/**
 A reference to the raw byte array.
*/
/**
This function found in impl {libcrux_ml_dsa::types::MLDSASignature<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_dsa.types.as_ref_c5
with const generics
- SIZE= 4627
*/
ساكن مضمن ثابت
Eurydice_arr_93
*libcrux_ml_dsa_types_as_ref_c5_f1(ثابت Eurydice_arr_93 *self)
{
  أرجع self;
}

/**
 A reference to the raw byte array.
*/
/**
This function found in impl {libcrux_ml_dsa::types::MLDSAVerificationKey<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_dsa.types.as_ref_7f
with const generics
- SIZE= 2592
*/
ساكن مضمن ثابت
Eurydice_arr_43
*libcrux_ml_dsa_types_as_ref_7f_c6(ثابت Eurydice_arr_43 *self)
{
  أرجع self;
}

/**
 A reference to the raw byte array.
*/
/**
This function found in impl {libcrux_ml_dsa::types::MLDSASigningKey<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_dsa.types.as_ref_9b
with const generics
- SIZE= 4896
*/
ساكن مضمن ثابت
Eurydice_arr_e2
*libcrux_ml_dsa_types_as_ref_9b_72(ثابت Eurydice_arr_e2 *self)
{
  أرجع self;
}

/**
 Build
*/
/**
This function found in impl {libcrux_ml_dsa::types::MLDSAVerificationKey<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_dsa.types.new_7f
with const generics
- SIZE= 2592
*/
ساكن مضمن Eurydice_arr_43 libcrux_ml_dsa_types_new_7f_c6(Eurydice_arr_43 قدر)
{
  أرجع قدر;
}

/**
 Build
*/
/**
This function found in impl {libcrux_ml_dsa::types::MLDSASigningKey<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_dsa.types.new_9b
with const generics
- SIZE= 4896
*/
ساكن مضمن Eurydice_arr_e2 libcrux_ml_dsa_types_new_9b_72(Eurydice_arr_e2 قدر)
{
  أرجع قدر;
}

تعريفنوع Eurydice_arr_85 libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_MLDSA44Signature;

/**
 A reference to the raw byte array.
*/
/**
This function found in impl {libcrux_ml_dsa::types::MLDSASignature<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_dsa.types.as_ref_c5
with const generics
- SIZE= 2420
*/
ساكن مضمن ثابت
Eurydice_arr_85
*libcrux_ml_dsa_types_as_ref_c5_37(ثابت Eurydice_arr_85 *self)
{
  أرجع self;
}

/**
 A reference to the raw byte array.
*/
/**
This function found in impl {libcrux_ml_dsa::types::MLDSAVerificationKey<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_dsa.types.as_ref_7f
with const generics
- SIZE= 1312
*/
ساكن مضمن ثابت
Eurydice_arr_02
*libcrux_ml_dsa_types_as_ref_7f_7d(ثابت Eurydice_arr_02 *self)
{
  أرجع self;
}

/**
 A reference to the raw byte array.
*/
/**
This function found in impl {libcrux_ml_dsa::types::MLDSASigningKey<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_dsa.types.as_ref_9b
with const generics
- SIZE= 2560
*/
ساكن مضمن ثابت
Eurydice_arr_10
*libcrux_ml_dsa_types_as_ref_9b_ab(ثابت Eurydice_arr_10 *self)
{
  أرجع self;
}

/**
 Build
*/
/**
This function found in impl {libcrux_ml_dsa::types::MLDSAVerificationKey<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_dsa.types.new_7f
with const generics
- SIZE= 1312
*/
ساكن مضمن Eurydice_arr_02 libcrux_ml_dsa_types_new_7f_7d(Eurydice_arr_02 قدر)
{
  أرجع قدر;
}

/**
 Build
*/
/**
This function found in impl {libcrux_ml_dsa::types::MLDSASigningKey<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_dsa.types.new_9b
with const generics
- SIZE= 2560
*/
ساكن مضمن Eurydice_arr_10 libcrux_ml_dsa_types_new_9b_ab(Eurydice_arr_10 قدر)
{
  أرجع قدر;
}

تعريفنوع Eurydice_arr_0c libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_MLDSA65Signature;

/**
 A reference to the raw byte array.
*/
/**
This function found in impl {libcrux_ml_dsa::types::MLDSASignature<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_dsa.types.as_ref_c5
with const generics
- SIZE= 3309
*/
ساكن مضمن ثابت
Eurydice_arr_0c
*libcrux_ml_dsa_types_as_ref_c5_5c(ثابت Eurydice_arr_0c *self)
{
  أرجع self;
}

/**
 A reference to the raw byte array.
*/
/**
This function found in impl {libcrux_ml_dsa::types::MLDSAVerificationKey<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_dsa.types.as_ref_7f
with const generics
- SIZE= 1952
*/
ساكن مضمن ثابت
Eurydice_arr_29
*libcrux_ml_dsa_types_as_ref_7f_a2(ثابت Eurydice_arr_29 *self)
{
  أرجع self;
}

/**
 A reference to the raw byte array.
*/
/**
This function found in impl {libcrux_ml_dsa::types::MLDSASigningKey<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_dsa.types.as_ref_9b
with const generics
- SIZE= 4032
*/
ساكن مضمن ثابت
Eurydice_arr_24
*libcrux_ml_dsa_types_as_ref_9b_e5(ثابت Eurydice_arr_24 *self)
{
  أرجع self;
}

/**
 Build
*/
/**
This function found in impl {libcrux_ml_dsa::types::MLDSAVerificationKey<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_dsa.types.new_7f
with const generics
- SIZE= 1952
*/
ساكن مضمن Eurydice_arr_29 libcrux_ml_dsa_types_new_7f_a2(Eurydice_arr_29 قدر)
{
  أرجع قدر;
}

/**
 Build
*/
/**
This function found in impl {libcrux_ml_dsa::types::MLDSASigningKey<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_dsa.types.new_9b
with const generics
- SIZE= 4032
*/
ساكن مضمن Eurydice_arr_24 libcrux_ml_dsa_types_new_9b_e5(Eurydice_arr_24 قدر)
{
  أرجع قدر;
}

/**
A monomorphic instance of core.result.Result
with types libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_MLDSA87Signature, libcrux_ml_dsa_types_SigningError

*/
تعريفنوع بنية core_نتیجہ_نتیجہ_8b_s
{
  core_نتیجہ_نتیجہ_57_ٹیگ_سوچی ٹیگ;
  اتحاد {
    Eurydice_arr_93 case_Ok;
    libcrux_ml_dsa_types_SigningError case_Err;
  }
  val;
}
core_نتیجہ_نتیجہ_8b;

/**
A monomorphic instance of libcrux_ml_dsa.polynomial.PolynomialRingElement
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients

*/
تعريفنوع Eurydice_arr_a3 libcrux_ml_dsa_polynomial_PolynomialRingElement_e8;

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8
with const generics
- $7size_t
*/
تعريفنوع بنية Eurydice_arr_bb_s { Eurydice_arr_a3 انکڑے[7U]; } Eurydice_arr_bb;

/**
A monomorphic instance of core.option.Option
with types Eurydice_arr_bb

*/
تعريفنوع بنية core_option_Option_2d_s
{
  core_option_Option_45_ٹیگ_سوچی ٹیگ;
  Eurydice_arr_bb f0;
}
core_option_Option_2d;

/**
A monomorphic instance of Eurydice.dst_ref_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8, size_t

*/
تعريفنوع بنية Eurydice_dst_ref_shared_44_s
{
  ثابت Eurydice_arr_a3 *ptr;
  ناپ_t meta;
}
Eurydice_dst_ref_shared_44;

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8
with const generics
- $56size_t
*/
تعريفنوع بنية Eurydice_arr_0f_s { Eurydice_arr_a3 انکڑے[56U]; } Eurydice_arr_0f;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 56
*/
ساكن مضمن Eurydice_dst_ref_shared_44
Eurydice_array_منزل_ٹکڑا_shared_208(ثابت Eurydice_arr_0f *a)
{
  Eurydice_dst_ref_shared_44 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)56U;
  أرجع lit;
}

/**
 Init with zero
*/
/**
This function found in impl {libcrux_ml_dsa::types::MLDSASignature<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_dsa.types.zero_c5
with const generics
- SIZE= 4627
*/
ساكن مضمن Eurydice_arr_93 libcrux_ml_dsa_types_zero_c5_f1(فراغ)
{
  أرجع (KRML_CLITERAL(Eurydice_arr_93){ .انکڑے = { 0U } });
}

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8
with const generics
- $8size_t
*/
تعريفنوع بنية Eurydice_arr_8f_s { Eurydice_arr_a3 انکڑے[8U]; } Eurydice_arr_8f;

/**
 Declassify secret memory.

 No-op if `valgrind_ct_test` cfg is not enabled.
*/
/**
A monomorphic instance of libcrux_secrets.mem_requests.ct_declassify
with types Eurydice_arr libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients[[$8size_t]]

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_secrets_mem_بینتیاں_ct_declassify_6a(ثابت Eurydice_arr_8f *val)
{

}

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8
with const generics
- $15size_t
*/
تعريفنوع بنية Eurydice_arr_92_s { Eurydice_arr_a3 انکڑے[15U]; } Eurydice_arr_92;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 15
*/
ساكن مضمن Eurydice_dst_ref_shared_44
Eurydice_array_منزل_ٹکڑا_shared_207(ثابت Eurydice_arr_92 *a)
{
  Eurydice_dst_ref_shared_44 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)15U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 7
*/
ساكن مضمن Eurydice_dst_ref_shared_44
Eurydice_array_منزل_ٹکڑا_shared_206(ثابت Eurydice_arr_bb *a)
{
  Eurydice_dst_ref_shared_44 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)7U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients, core_ops_range_Range size_t, Eurydice_derefed_slice libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 15
*/
ساكن مضمن Eurydice_dst_ref_shared_44
Eurydice_array_منزل_subslice_shared_251(ثابت Eurydice_arr_92 *a, core_ops_range_Range_87 r)
{
  أرجع
    (
      KRML_CLITERAL(Eurydice_dst_ref_shared_44){ .ptr = a->انکڑے + r.شروع, .meta = r.سرا - r.شروع }
    );
}

/**
A monomorphic instance of Eurydice.dst_ref_mut
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8, size_t

*/
تعريفنوع بنية Eurydice_dst_ref_mut_44_s
{
  Eurydice_arr_a3 *ptr;
  ناپ_t meta;
}
Eurydice_dst_ref_mut_44;

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 7
*/
ساكن مضمن Eurydice_dst_ref_mut_44 Eurydice_array_منزل_ٹکڑا_mut_208(Eurydice_arr_bb *a)
{
  Eurydice_dst_ref_mut_44 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)7U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 56
*/
ساكن مضمن Eurydice_dst_ref_mut_44 Eurydice_array_منزل_ٹکڑا_mut_207(Eurydice_arr_0f *a)
{
  Eurydice_dst_ref_mut_44 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)56U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 15
*/
ساكن مضمن Eurydice_dst_ref_mut_44 Eurydice_array_منزل_ٹکڑا_mut_206(Eurydice_arr_92 *a)
{
  Eurydice_dst_ref_mut_44 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)15U;
  أرجع lit;
}

/**
A monomorphic instance of core.result.Result
with types libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_MLDSA65Signature, libcrux_ml_dsa_types_SigningError

*/
تعريفنوع بنية core_نتیجہ_نتیجہ_8c_s
{
  core_نتیجہ_نتیجہ_57_ٹیگ_سوچی ٹیگ;
  اتحاد {
    Eurydice_arr_0c case_Ok;
    libcrux_ml_dsa_types_SigningError case_Err;
  }
  val;
}
core_نتیجہ_نتیجہ_8c;

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8
with const generics
- $5size_t
*/
تعريفنوع بنية Eurydice_arr_5d_s { Eurydice_arr_a3 انکڑے[5U]; } Eurydice_arr_5d;

/**
A monomorphic instance of core.option.Option
with types Eurydice_arr_5d

*/
تعريفنوع بنية core_option_Option_1e_s
{
  core_option_Option_45_ٹیگ_سوچی ٹیگ;
  Eurydice_arr_5d f0;
}
core_option_Option_1e;

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8
with const generics
- $30size_t
*/
تعريفنوع بنية Eurydice_arr_5a_s { Eurydice_arr_a3 انکڑے[30U]; } Eurydice_arr_5a;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 30
*/
ساكن مضمن Eurydice_dst_ref_shared_44
Eurydice_array_منزل_ٹکڑا_shared_205(ثابت Eurydice_arr_5a *a)
{
  Eurydice_dst_ref_shared_44 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)30U;
  أرجع lit;
}

/**
 Init with zero
*/
/**
This function found in impl {libcrux_ml_dsa::types::MLDSASignature<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_dsa.types.zero_c5
with const generics
- SIZE= 3309
*/
ساكن مضمن Eurydice_arr_0c libcrux_ml_dsa_types_zero_c5_5c(فراغ)
{
  أرجع (KRML_CLITERAL(Eurydice_arr_0c){ .انکڑے = { 0U } });
}

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8
with const generics
- $6size_t
*/
تعريفنوع بنية Eurydice_arr_dc1_s { Eurydice_arr_a3 انکڑے[6U]; } Eurydice_arr_dc1;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 6
*/
ساكن مضمن Eurydice_dst_ref_shared_44
Eurydice_array_منزل_ٹکڑا_shared_204(ثابت Eurydice_arr_dc1 *a)
{
  Eurydice_dst_ref_shared_44 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)6U;
  أرجع lit;
}

/**
 Declassify secret memory.

 No-op if `valgrind_ct_test` cfg is not enabled.
*/
/**
A monomorphic instance of libcrux_secrets.mem_requests.ct_declassify
with types Eurydice_arr libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients[[$6size_t]]

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_secrets_mem_بینتیاں_ct_declassify_b2(ثابت Eurydice_arr_dc1 *val)
{

}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 6
*/
ساكن مضمن Eurydice_dst_ref_mut_44 Eurydice_array_منزل_ٹکڑا_mut_205(Eurydice_arr_dc1 *a)
{
  Eurydice_dst_ref_mut_44 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)6U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8
with const generics
- $11size_t
*/
تعريفنوع بنية Eurydice_arr_47_s { Eurydice_arr_a3 انکڑے[11U]; } Eurydice_arr_47;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 11
*/
ساكن مضمن Eurydice_dst_ref_shared_44
Eurydice_array_منزل_ٹکڑا_shared_203(ثابت Eurydice_arr_47 *a)
{
  Eurydice_dst_ref_shared_44 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)11U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 5
*/
ساكن مضمن Eurydice_dst_ref_shared_44
Eurydice_array_منزل_ٹکڑا_shared_202(ثابت Eurydice_arr_5d *a)
{
  Eurydice_dst_ref_shared_44 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)5U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients, core_ops_range_Range size_t, Eurydice_derefed_slice libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 11
*/
ساكن مضمن Eurydice_dst_ref_shared_44
Eurydice_array_منزل_subslice_shared_250(ثابت Eurydice_arr_47 *a, core_ops_range_Range_87 r)
{
  أرجع
    (
      KRML_CLITERAL(Eurydice_dst_ref_shared_44){ .ptr = a->انکڑے + r.شروع, .meta = r.سرا - r.شروع }
    );
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 5
*/
ساكن مضمن Eurydice_dst_ref_mut_44 Eurydice_array_منزل_ٹکڑا_mut_204(Eurydice_arr_5d *a)
{
  Eurydice_dst_ref_mut_44 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)5U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 30
*/
ساكن مضمن Eurydice_dst_ref_mut_44 Eurydice_array_منزل_ٹکڑا_mut_203(Eurydice_arr_5a *a)
{
  Eurydice_dst_ref_mut_44 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)30U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 11
*/
ساكن مضمن Eurydice_dst_ref_mut_44 Eurydice_array_منزل_ٹکڑا_mut_202(Eurydice_arr_47 *a)
{
  Eurydice_dst_ref_mut_44 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)11U;
  أرجع lit;
}

/**
This function found in impl {libcrux_ml_dsa::polynomial::PolynomialRingElement<SIMDUnit>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_dsa.polynomial.zero_ff
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ساكن مضمن Eurydice_arr_a3 libcrux_ml_dsa_polynomial_zero_ff_37(فراغ)
{
  Eurydice_arr_a3 lit;
  Eurydice_arr_4d repeat_عبارت[32U];
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)32U; i++)
  {
    repeat_عبارت[i] = libcrux_ml_dsa_simd_portable_zero_65();
  }
  حافظہ_نقل(lit.انکڑے, repeat_عبارت, (ناپ_t)32U * حجم (Eurydice_arr_4d));
  أرجع lit;
}

/**
This function found in impl {libcrux_ml_dsa::polynomial::PolynomialRingElement<SIMDUnit>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_dsa.polynomial.from_i32_array_ff
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ساكن مضمن فراغ
libcrux_ml_dsa_polynomial_from_i32_array_ff_37(
  Eurydice_dst_ref_shared_83 array,
  Eurydice_arr_a3 *نتیجہ
)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < LIBCRUX_ML_DSA_SIMD_TRAITS_SIMD_UNITS_وچ_RING_ELEMENT; i++)
  {
    ناپ_t i0 = i;
    libcrux_ml_dsa_simd_portable_from_coefficient_array_65(Eurydice_ٹکڑا_subslice_shared_47(array,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .شروع = i0 * LIBCRUX_ML_DSA_SIMD_TRAITS_COEFFICIENTS_وچ_SIMD_UNIT,
            .سرا = (i0 + (ناپ_t)1U) * LIBCRUX_ML_DSA_SIMD_TRAITS_COEFFICIENTS_وچ_SIMD_UNIT
          }
        )),
      &نتیجہ->انکڑے[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.arithmetic.use_hint
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_arithmetic_use_hint_37(
  int32_t gamma2,
  Eurydice_dst_ref_shared_20 hint,
  Eurydice_dst_ref_mut_44 re_سمتیہ
)
{
  لكل (ناپ_t i0 = (ناپ_t)0U; i0 < re_سمتیہ.meta; i0++)
  {
    ناپ_t i1 = i0;
    Eurydice_arr_a3 tmp = libcrux_ml_dsa_polynomial_zero_ff_37();
    libcrux_ml_dsa_polynomial_from_i32_array_ff_37(Eurydice_array_منزل_ٹکڑا_shared_af(&hint.ptr[i1]),
      &tmp);
    لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)32U; i++)
    {
      ناپ_t j = i;
      libcrux_ml_dsa_simd_portable_use_hint_65(gamma2, &re_سمتیہ.ptr[i1].انکڑے[j], &tmp.انکڑے[j]);
    }
    re_سمتیہ.ptr[i1] = tmp;
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.ntt.ntt_multiply_montgomery
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_ntt_ntt_multiply_montgomery_37(Eurydice_arr_a3 *lhs, ثابت Eurydice_arr_a3 *rhs)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)32U; i++)
  {
    ناپ_t i0 = i;
    libcrux_ml_dsa_simd_portable_montgomery_multiply_65(&lhs->انکڑے[i0], &rhs->انکڑے[i0]);
  }
}

/**
This function found in impl {libcrux_ml_dsa::polynomial::PolynomialRingElement<SIMDUnit>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_dsa.polynomial.add_ff
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_polynomial_جوڑو_ff_37(Eurydice_arr_a3 *self, ثابت Eurydice_arr_a3 *rhs)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)32U; i++)
  {
    ناپ_t i0 = i;
    libcrux_ml_dsa_simd_portable_جوڑو_65(&self->انکڑے[i0], &rhs->انکڑے[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.arithmetic.shift_left_then_reduce
with const generics
- SHIFT_BY= 13
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_simd_portable_arithmetic_کھسکاؤ_بایاں_then_reduce_84(Eurydice_arr_4d *simd_unit)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)8U; i++)
  {
    ناپ_t i0 = i;
    simd_unit->انکڑے[i0] = (int32_t)((uint32_t)simd_unit->انکڑے[i0] << (uint32_t)13);
  }
  libcrux_ml_dsa_simd_portable_arithmetic_barrett_reduce_simd_unit(simd_unit);
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.shift_left_then_reduce_65
with const generics
- SHIFT_BY= 13
*/
ساكن مضمن فراغ
libcrux_ml_dsa_simd_portable_کھسکاؤ_بایاں_then_reduce_65_84(Eurydice_arr_4d *simd_unit)
{
  libcrux_ml_dsa_simd_portable_arithmetic_کھسکاؤ_بایاں_then_reduce_84(simd_unit);
}

/**
A monomorphic instance of libcrux_ml_dsa.arithmetic.shift_left_then_reduce
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- SHIFT_BY= 13
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_arithmetic_کھسکاؤ_بایاں_then_reduce_68(Eurydice_arr_a3 *re)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)32U; i++)
  {
    ناپ_t i0 = i;
    libcrux_ml_dsa_simd_portable_کھسکاؤ_بایاں_then_reduce_65_84(&re->انکڑے[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.ntt.ntt
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ساكن KRML_MUSTINLINE فراغ libcrux_ml_dsa_ntt_ntt_37(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_ntt_65(re);
}

/**
This function found in impl {libcrux_ml_dsa::polynomial::PolynomialRingElement<SIMDUnit>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_dsa.polynomial.subtract_ff
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_polynomial_گھٹاؤ_ff_37(Eurydice_arr_a3 *self, ثابت Eurydice_arr_a3 *rhs)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)32U; i++)
  {
    ناپ_t i0 = i;
    libcrux_ml_dsa_simd_portable_گھٹاؤ_65(&self->انکڑے[i0], &rhs->انکڑے[i0]);
  }
}

/**
This function found in impl {libcrux_ml_dsa::polynomial::PolynomialRingElement<SIMDUnit>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_dsa.polynomial.barrett_reduce_ff
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_polynomial_barrett_reduce_ff_37(Eurydice_arr_a3 *self)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)32U; i++)
  {
    ناپ_t i0 = i;
    libcrux_ml_dsa_simd_portable_barrett_reduce_simd_unit_65(&self->انکڑے[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.ntt.invert_ntt_montgomery
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ساكن KRML_MUSTINLINE فراغ libcrux_ml_dsa_ntt_invert_ntt_montgomery_37(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_invert_ntt_montgomery_65(re);
}

/**
 Compute InvertNTT(Â ◦ ẑ - ĉ ◦ NTT(t₁2ᵈ))
*/
/**
A monomorphic instance of libcrux_ml_dsa.matrix.compute_w_approx
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_میٹرکس_compute_w_approx_37(
  ناپ_t صفاں_وچ_a,
  ناپ_t columns_وچ_a,
  Eurydice_dst_ref_shared_44 میٹرکس,
  Eurydice_dst_ref_shared_44 signer_response,
  ثابت Eurydice_arr_a3 *verifier_challenge_as_ntt,
  Eurydice_dst_ref_mut_44 t1
)
{
  لكل (ناپ_t i0 = (ناپ_t)0U; i0 < صفاں_وچ_a; i0++)
  {
    ناپ_t i1 = i0;
    Eurydice_arr_a3 inner_نتیجہ = libcrux_ml_dsa_polynomial_zero_ff_37();
    لكل (ناپ_t i = (ناپ_t)0U; i < columns_وچ_a; i++)
    {
      ناپ_t j = i;
      Eurydice_arr_a3 ضرب_حاصل = میٹرکس.ptr[i1 * columns_وچ_a + j];
      libcrux_ml_dsa_ntt_ntt_multiply_montgomery_37(&ضرب_حاصل, &signer_response.ptr[j]);
      libcrux_ml_dsa_polynomial_جوڑو_ff_37(&inner_نتیجہ, &ضرب_حاصل);
    }
    libcrux_ml_dsa_arithmetic_کھسکاؤ_بایاں_then_reduce_68(&t1.ptr[i1]);
    libcrux_ml_dsa_ntt_ntt_37(&t1.ptr[i1]);
    libcrux_ml_dsa_ntt_ntt_multiply_montgomery_37(&t1.ptr[i1], verifier_challenge_as_ntt);
    libcrux_ml_dsa_polynomial_گھٹاؤ_ff_37(&inner_نتیجہ, &t1.ptr[i1]);
    t1.ptr[i1] = inner_نتیجہ;
    libcrux_ml_dsa_polynomial_barrett_reduce_ff_37(&t1.ptr[i1]);
    libcrux_ml_dsa_ntt_invert_ntt_montgomery_37(&t1.ptr[i1]);
  }
}

/**
A monomorphic instance of core.result.Result
with types (), libcrux_ml_dsa_types_VerificationError

*/
تعريفنوع بنية core_نتیجہ_نتیجہ_41_s
{
  core_نتیجہ_نتیجہ_57_ٹیگ_سوچی ٹیگ;
  libcrux_ml_dsa_types_VerificationError f0;
}
core_نتیجہ_نتیجہ_41;

/**
A monomorphic instance of libcrux_ml_dsa.encoding.gamma1.deserialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_encoding_gamma1_deserialize_37(
  ناپ_t gamma1_exponent,
  Eurydice_borrow_ٹکڑا_u8 serialized,
  Eurydice_arr_a3 *نتیجہ
)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)32U; i++)
  {
    ناپ_t i0 = i;
    libcrux_ml_dsa_simd_portable_gamma1_deserialize_65(Eurydice_ٹکڑا_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .شروع = i0 * (gamma1_exponent + (ناپ_t)1U),
            .سرا = (i0 + (ناپ_t)1U) * (gamma1_exponent + (ناپ_t)1U)
          }
        )),
      &نتیجہ->انکڑے[i0],
      gamma1_exponent);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.signature.deserialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ساكن KRML_MUSTINLINE core_نتیجہ_نتیجہ_41
libcrux_ml_dsa_encoding_signature_deserialize_37(
  ناپ_t columns_وچ_a,
  ناپ_t صفاں_وچ_a,
  ناپ_t commitment_hash_ناپ,
  ناپ_t gamma1_exponent,
  ناپ_t gamma1_ring_element_ناپ,
  ناپ_t max_ones_وچ_hint,
  ناپ_t signature_ناپ,
  Eurydice_borrow_ٹکڑا_u8 serialized,
  Eurydice_mut_borrow_ٹکڑا_u8 باہرلا_commitment_hash,
  Eurydice_dst_ref_mut_44 باہرلا_signer_response,
  Eurydice_dst_ref_mut_20 باہرلا_hint
)
{
  Eurydice_borrow_ٹکڑا_u8_x2
  uu____0 =
    Eurydice_ٹکڑا_ونڈو_at(serialized,
      commitment_hash_ناپ,
      uint8_t,
      Eurydice_borrow_ٹکڑا_u8_x2);
  Eurydice_borrow_ٹکڑا_u8 commitment_hash = uu____0.fst;
  Eurydice_borrow_ٹکڑا_u8 rest_دا_serialized = uu____0.snd;
  Eurydice_ٹکڑا_copy(Eurydice_ٹکڑا_subslice_mut_c8(باہرلا_commitment_hash,
      (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = (ناپ_t)0U, .سرا = commitment_hash_ناپ })),
    commitment_hash,
    uint8_t);
  Eurydice_borrow_ٹکڑا_u8_x2
  uu____1 =
    Eurydice_ٹکڑا_ونڈو_at(rest_دا_serialized,
      gamma1_ring_element_ناپ * columns_وچ_a,
      uint8_t,
      Eurydice_borrow_ٹکڑا_u8_x2);
  Eurydice_borrow_ٹکڑا_u8 signer_response_serialized = uu____1.fst;
  Eurydice_borrow_ٹکڑا_u8 hint_serialized = uu____1.snd;
  لكل (ناپ_t i = (ناپ_t)0U; i < columns_وچ_a; i++)
  {
    ناپ_t i0 = i;
    libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
      Eurydice_ٹکڑا_subslice_shared_c8(signer_response_serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .شروع = i0 * gamma1_ring_element_ناپ,
            .سرا = (i0 + (ناپ_t)1U) * gamma1_ring_element_ناپ
          }
        )),
      &باہرلا_signer_response.ptr[i0]);
  }
  ناپ_t پچھلا_true_hints_تکیا = (ناپ_t)0U;
  bool malformed_hint = false;
  لكل (ناپ_t i0 = (ناپ_t)0U; i0 < صفاں_وچ_a; i0++)
  {
    ناپ_t i1 = i0;
    ناپ_t current_true_hints_تکیا = (ناپ_t)(uint32_t)hint_serialized.ptr[max_ones_وچ_hint + i1];
    إذا (current_true_hints_تکیا < پچھلا_true_hints_تکیا)
    {
      malformed_hint = true;
      اكسر;
    }
    إذا (current_true_hints_تکیا > max_ones_وچ_hint)
    {
      malformed_hint = true;
      اكسر;
    }
    لكل (ناپ_t i = پچھلا_true_hints_تکیا; i < current_true_hints_تکیا; i++)
    {
      ناپ_t j = i;
      إذا (j > پچھلا_true_hints_تکیا)
      {
        إذا (hint_serialized.ptr[j] <= hint_serialized.ptr[j - (ناپ_t)1U])
        {
          malformed_hint = true;
          اكسر;
        }
      }
      libcrux_ml_dsa_encoding_signature_سیٹ_hint(باہرلا_hint,
        i1,
        (ناپ_t)(uint32_t)hint_serialized.ptr[j]);
    }
    إذا (malformed_hint)
    {
      اكسر;
    }
    پچھلا_true_hints_تکیا = current_true_hints_تکیا;
  }
  لكل (ناپ_t i = پچھلا_true_hints_تکیا; i < max_ones_وچ_hint; i++)
  {
    ناپ_t j = i;
    إذا (hint_serialized.ptr[j] != 0U)
    {
      malformed_hint = true;
      اكسر;
    }
  }
  core_نتیجہ_نتیجہ_41 uu____2;
  إذا (malformed_hint)
  {
    uu____2 =
      (
        KRML_CLITERAL(core_نتیجہ_نتیجہ_41){
          .ٹیگ = core_نتیجہ_Err,
          .f0 = libcrux_ml_dsa_types_VerificationError_MalformedHintError
        }
      );
  }
  وإلا
  {
    uu____2 = (KRML_CLITERAL(core_نتیجہ_نتیجہ_41){ .ٹیگ = core_نتیجہ_Ok });
  }
  أرجع uu____2;
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.t1.deserialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ساكن مضمن فراغ
libcrux_ml_dsa_encoding_t1_deserialize_37(
  Eurydice_borrow_ٹکڑا_u8 serialized,
  Eurydice_arr_a3 *نتیجہ
)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)32U; i++)
  {
    ناپ_t i0 = i;
    libcrux_ml_dsa_simd_portable_t1_deserialize_65(Eurydice_ٹکڑا_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .شروع = i0 * LIBCRUX_ML_DSA_ENCODING_T1_DESERIALIZE_کھڑکی,
            .سرا = (i0 + (ناپ_t)1U) * LIBCRUX_ML_DSA_ENCODING_T1_DESERIALIZE_کھڑکی
          }
        )),
      &نتیجہ->انکڑے[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.verification_key.deserialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_encoding_verification_کلید_deserialize_37(
  ناپ_t صفاں_وچ_a,
  ناپ_t verification_کلید_ناپ,
  Eurydice_borrow_ٹکڑا_u8 serialized,
  Eurydice_dst_ref_mut_44 t1
)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < صفاں_وچ_a; i++)
  {
    ناپ_t i0 = i;
    libcrux_ml_dsa_encoding_t1_deserialize_37(Eurydice_ٹکڑا_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .شروع = i0 * LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_دا_T1_S_ناپ,
            .سرا = (i0 + (ناپ_t)1U) * LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_دا_T1_S_ناپ
          }
        )),
      &t1.ptr[i0]);
  }
}

/**
A monomorphic instance of core.result.Result
with types libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_MLDSA44Signature, libcrux_ml_dsa_types_SigningError

*/
تعريفنوع بنية core_نتیجہ_نتیجہ_48_s
{
  core_نتیجہ_نتیجہ_57_ٹیگ_سوچی ٹیگ;
  اتحاد {
    Eurydice_arr_85 case_Ok;
    libcrux_ml_dsa_types_SigningError case_Err;
  }
  val;
}
core_نتیجہ_نتیجہ_48;

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8
with const generics
- $4size_t
*/
تعريفنوع بنية Eurydice_arr_9d_s { Eurydice_arr_a3 انکڑے[4U]; } Eurydice_arr_9d;

/**
A monomorphic instance of core.option.Option
with types Eurydice_arr_9d

*/
تعريفنوع بنية core_option_Option_d9_s
{
  core_option_Option_45_ٹیگ_سوچی ٹیگ;
  Eurydice_arr_9d f0;
}
core_option_Option_d9;

/**
A monomorphic instance of core.result.Result
with types (), libcrux_ml_dsa_types_SigningError

*/
تعريفنوع بنية core_نتیجہ_نتیجہ_53_s
{
  core_نتیجہ_نتیجہ_57_ٹیگ_سوچی ٹیگ;
  libcrux_ml_dsa_types_SigningError f0;
}
core_نتیجہ_نتیجہ_53;

/**
A monomorphic instance of libcrux_ml_dsa.encoding.gamma1.serialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_encoding_gamma1_serialize_37(
  ثابت Eurydice_arr_a3 *re,
  Eurydice_mut_borrow_ٹکڑا_u8 serialized,
  ناپ_t gamma1_exponent
)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)32U; i++)
  {
    ناپ_t i0 = i;
    ثابت Eurydice_arr_4d *simd_unit = &re->انکڑے[i0];
    libcrux_ml_dsa_simd_portable_gamma1_serialize_65(simd_unit,
      Eurydice_ٹکڑا_subslice_mut_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .شروع = i0 * (gamma1_exponent + (ناپ_t)1U),
            .سرا = (i0 + (ناپ_t)1U) * (gamma1_exponent + (ناپ_t)1U)
          }
        )),
      gamma1_exponent);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.signature.serialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_encoding_signature_serialize_37(
  Eurydice_borrow_ٹکڑا_u8 commitment_hash,
  Eurydice_dst_ref_shared_44 signer_response,
  Eurydice_dst_ref_shared_20 hint,
  ناپ_t commitment_hash_ناپ,
  ناپ_t columns_وچ_a,
  ناپ_t صفاں_وچ_a,
  ناپ_t gamma1_exponent,
  ناپ_t gamma1_ring_element_ناپ,
  ناپ_t max_ones_وچ_hint,
  Eurydice_mut_borrow_ٹکڑا_u8 signature
)
{
  ناپ_t وتھ = (ناپ_t)0U;
  Eurydice_ٹکڑا_copy(Eurydice_ٹکڑا_subslice_mut_c8(signature,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .شروع = وتھ,
          .سرا = وتھ + commitment_hash_ناپ
        }
      )),
    commitment_hash,
    uint8_t);
  وتھ += commitment_hash_ناپ;
  لكل (ناپ_t i = (ناپ_t)0U; i < columns_وچ_a; i++)
  {
    ناپ_t i0 = i;
    libcrux_ml_dsa_encoding_gamma1_serialize_37(&signer_response.ptr[i0],
      Eurydice_ٹکڑا_subslice_mut_c8(signature,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .شروع = وتھ,
            .سرا = وتھ + gamma1_ring_element_ناپ
          }
        )),
      gamma1_exponent);
    وتھ += gamma1_ring_element_ناپ;
  }
  ناپ_t true_hints_تکیا = (ناپ_t)0U;
  لكل (ناپ_t i0 = (ناپ_t)0U; i0 < صفاں_وچ_a; i0++)
  {
    ناپ_t i1 = i0;
    لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)256U; i++)
    {
      ناپ_t j = i;
      إذا (hint.ptr[i1].انکڑے[j] == 1)
      {
        signature.ptr[وتھ + true_hints_تکیا] = (uint8_t)j;
        true_hints_تکیا++;
      }
    }
    signature.ptr[وتھ + max_ones_وچ_hint + i1] = (uint8_t)true_hints_تکیا;
  }
}

/**
This function found in impl {libcrux_ml_dsa::polynomial::PolynomialRingElement<SIMDUnit>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_dsa.polynomial.to_i32_array_ff
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ساكن مضمن Eurydice_arr_6c
libcrux_ml_dsa_polynomial_منزل_i32_array_ff_37(ثابت Eurydice_arr_a3 *self)
{
  Eurydice_arr_6c نتیجہ = { .انکڑے = { 0U } };
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)32U; i++)
  {
    ناپ_t i0 = i;
    libcrux_ml_dsa_simd_portable_منزل_coefficient_array_65(&self->انکڑے[i0],
      Eurydice_array_منزل_subslice_mut_44(&نتیجہ,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .شروع = i0 * LIBCRUX_ML_DSA_SIMD_TRAITS_COEFFICIENTS_وچ_SIMD_UNIT,
            .سرا = (i0 + (ناپ_t)1U) * LIBCRUX_ML_DSA_SIMD_TRAITS_COEFFICIENTS_وچ_SIMD_UNIT
          }
        )));
  }
  أرجع نتیجہ;
}

/**
A monomorphic instance of libcrux_ml_dsa.arithmetic.make_hint
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ساكن KRML_MUSTINLINE ناپ_t
libcrux_ml_dsa_arithmetic_make_hint_37(
  Eurydice_dst_ref_shared_44 کم,
  Eurydice_dst_ref_shared_44 بلند,
  int32_t gamma2,
  Eurydice_dst_ref_mut_20 hint
)
{
  ناپ_t true_hints = (ناپ_t)0U;
  Eurydice_arr_a3 hint_simd = libcrux_ml_dsa_polynomial_zero_ff_37();
  لكل (ناپ_t i0 = (ناپ_t)0U; i0 < کم.meta; i0++)
  {
    ناپ_t i1 = i0;
    لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)32U; i++)
    {
      ناپ_t j = i;
      ناپ_t
      one_hints_گنتی =
        libcrux_ml_dsa_simd_portable_compute_hint_65(&کم.ptr[i1].انکڑے[j],
          &بلند.ptr[i1].انکڑے[j],
          gamma2,
          &hint_simd.انکڑے[j]);
      true_hints += one_hints_گنتی;
    }
    Eurydice_arr_6c uu____0 = libcrux_ml_dsa_polynomial_منزل_i32_array_ff_37(&hint_simd);
    hint.ptr[i1] = uu____0;
  }
  أرجع true_hints;
}

/**
 CAUTION: This function must only be called with inputs for
 which it is safe to leak the index of a violating coefficient.

 For all norm checks during ML-DSA signature generation it is
 safe to leak the index of a violating coefficient.
*/
/**
This function found in impl {libcrux_ml_dsa::polynomial::PolynomialRingElement<SIMDUnit>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_dsa.polynomial.infinity_norm_exceeds_ff
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ساكن KRML_MUSTINLINE bool
libcrux_ml_dsa_polynomial_infinity_norm_exceeds_ff_37(
  ثابت Eurydice_arr_a3 *self,
  int32_t bound
)
{
  bool نتیجہ = false;
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)32U; i++)
  {
    ناپ_t i0 = i;
    bool
    coeff_exceeds = libcrux_ml_dsa_simd_portable_infinity_norm_exceeds_65(&self->انکڑے[i0], bound);
    bool uu____0;
    إذا (نتیجہ)
    {
      uu____0 = true;
    }
    وإلا
    {
      uu____0 = coeff_exceeds;
    }
    نتیجہ = uu____0;
  }
  أرجع نتیجہ;
}

/**
 CAUTION: This function must only be called with inputs for
 which it is safe to leak the index of a violating coefficient.

 For all norm checks during ML-DSA signature generation it is
 safe to leak the index of a violating coefficient.
*/
/**
A monomorphic instance of libcrux_ml_dsa.arithmetic.vector_infinity_norm_exceeds
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ساكن KRML_MUSTINLINE bool
libcrux_ml_dsa_arithmetic_سمتیہ_infinity_norm_exceeds_37(
  Eurydice_dst_ref_shared_44 سمتیہ,
  int32_t bound
)
{
  bool نتیجہ = false;
  لكل (ناپ_t i = (ناپ_t)0U; i < سمتیہ.meta; i++)
  {
    ناپ_t i0 = i;
    bool uu____0;
    إذا (نتیجہ)
    {
      uu____0 = true;
    }
    وإلا
    {
      uu____0 = libcrux_ml_dsa_polynomial_infinity_norm_exceeds_ff_37(&سمتیہ.ptr[i0], bound);
    }
    نتیجہ = uu____0;
  }
  أرجع نتیجہ;
}

/**
A monomorphic instance of libcrux_ml_dsa.matrix.subtract_vectors
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_میٹرکس_گھٹاؤ_vectors_37(
  ناپ_t dimension,
  Eurydice_dst_ref_mut_44 lhs,
  Eurydice_dst_ref_shared_44 rhs
)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < dimension; i++)
  {
    ناپ_t i0 = i;
    libcrux_ml_dsa_polynomial_گھٹاؤ_ff_37(&lhs.ptr[i0], &rhs.ptr[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.matrix.add_vectors
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_میٹرکس_جوڑو_vectors_37(
  ناپ_t dimension,
  Eurydice_dst_ref_mut_44 lhs,
  Eurydice_dst_ref_shared_44 rhs
)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < dimension; i++)
  {
    ناپ_t i0 = i;
    libcrux_ml_dsa_polynomial_جوڑو_ff_37(&lhs.ptr[i0], &rhs.ptr[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.matrix.vector_times_ring_element
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_میٹرکس_سمتیہ_times_ring_element_37(
  Eurydice_dst_ref_mut_44 سمتیہ,
  ثابت Eurydice_arr_a3 *ring_element
)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < سمتیہ.meta; i++)
  {
    ناپ_t i0 = i;
    libcrux_ml_dsa_ntt_ntt_multiply_montgomery_37(&سمتیہ.ptr[i0], ring_element);
    libcrux_ml_dsa_ntt_invert_ntt_montgomery_37(&سمتیہ.ptr[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.commitment.serialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_encoding_commitment_serialize_37(
  ثابت Eurydice_arr_a3 *re,
  Eurydice_mut_borrow_ٹکڑا_u8 serialized
)
{
  ناپ_t output_بائٹاں_فی_simd_unit = serialized.meta / ((ناپ_t)8U * (ناپ_t)4U);
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)32U; i++)
  {
    ناپ_t i0 = i;
    ثابت Eurydice_arr_4d *simd_unit = &re->انکڑے[i0];
    libcrux_ml_dsa_simd_portable_commitment_serialize_65(simd_unit,
      Eurydice_ٹکڑا_subslice_mut_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .شروع = i0 * output_بائٹاں_فی_simd_unit,
            .سرا = (i0 + (ناپ_t)1U) * output_بائٹاں_فی_simd_unit
          }
        )));
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.commitment.serialize_vector
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_encoding_commitment_serialize_سمتیہ_37(
  ناپ_t ring_element_ناپ,
  Eurydice_dst_ref_shared_44 سمتیہ,
  Eurydice_mut_borrow_ٹکڑا_u8 serialized
)
{
  ناپ_t وتھ = (ناپ_t)0U;
  لكل (ناپ_t i = (ناپ_t)0U; i < سمتیہ.meta; i++)
  {
    ناپ_t _cloop_j = i;
    ثابت Eurydice_arr_a3 *ring_element = &سمتیہ.ptr[_cloop_j];
    libcrux_ml_dsa_encoding_commitment_serialize_37(ring_element,
      Eurydice_ٹکڑا_subslice_mut_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .شروع = وتھ,
            .سرا = وتھ + ring_element_ناپ
          }
        )));
    وتھ += ring_element_ناپ;
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.arithmetic.decompose_vector
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_arithmetic_decompose_سمتیہ_37(
  ناپ_t dimension,
  int32_t gamma2,
  Eurydice_dst_ref_shared_44 t,
  Eurydice_dst_ref_mut_44 کم,
  Eurydice_dst_ref_mut_44 بلند
)
{
  لكل (ناپ_t i0 = (ناپ_t)0U; i0 < dimension; i0++)
  {
    ناپ_t i1 = i0;
    لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)32U; i++)
    {
      ناپ_t j = i;
      libcrux_ml_dsa_simd_portable_decompose_65(gamma2,
        &t.ptr[i1].انکڑے[j],
        &کم.ptr[i1].انکڑے[j],
        &بلند.ptr[i1].انکڑے[j]);
    }
  }
}

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8
with const generics
- $16size_t
*/
تعريفنوع بنية Eurydice_arr_2f_s { Eurydice_arr_a3 انکڑے[16U]; } Eurydice_arr_2f;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 16
*/
ساكن مضمن Eurydice_dst_ref_shared_44
Eurydice_array_منزل_ٹکڑا_shared_201(ثابت Eurydice_arr_2f *a)
{
  Eurydice_dst_ref_shared_44 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)16U;
  أرجع lit;
}

/**
 Compute InvertNTT(Â ◦ ŷ)
*/
/**
A monomorphic instance of libcrux_ml_dsa.matrix.compute_matrix_x_mask
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_میٹرکس_compute_میٹرکس_x_نقاب_37(
  ناپ_t صفاں_وچ_a,
  ناپ_t columns_وچ_a,
  Eurydice_dst_ref_shared_44 میٹرکس,
  Eurydice_dst_ref_shared_44 نقاب,
  Eurydice_dst_ref_mut_44 نتیجہ
)
{
  لكل (ناپ_t i0 = (ناپ_t)0U; i0 < صفاں_وچ_a; i0++)
  {
    ناپ_t i1 = i0;
    لكل (ناپ_t i = (ناپ_t)0U; i < columns_وچ_a; i++)
    {
      ناپ_t j = i;
      Eurydice_arr_a3 ضرب_حاصل = نقاب.ptr[j];
      libcrux_ml_dsa_ntt_ntt_multiply_montgomery_37(&ضرب_حاصل, &میٹرکس.ptr[i1 * columns_وچ_a + j]);
      libcrux_ml_dsa_polynomial_جوڑو_ff_37(&نتیجہ.ptr[i1], &ضرب_حاصل);
    }
    libcrux_ml_dsa_polynomial_barrett_reduce_ff_37(&نتیجہ.ptr[i1]);
    libcrux_ml_dsa_ntt_invert_ntt_montgomery_37(&نتیجہ.ptr[i1]);
  }
}

/**
A monomorphic instance of core.option.Option
with types libcrux_ml_dsa_pre_hash_DomainSeparationContext

*/
تعريفنوع بنية core_option_Option_84_s
{
  core_option_Option_45_ٹیگ_سوچی ٹیگ;
  libcrux_ml_dsa_pre_hash_DomainSeparationContext f0;
}
core_option_Option_84;

/**
A monomorphic instance of libcrux_ml_dsa.encoding.t0.deserialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_encoding_t0_deserialize_37(
  Eurydice_borrow_ٹکڑا_u8 serialized,
  Eurydice_arr_a3 *نتیجہ
)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)32U; i++)
  {
    ناپ_t i0 = i;
    libcrux_ml_dsa_simd_portable_t0_deserialize_65(Eurydice_ٹکڑا_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .شروع = i0 * LIBCRUX_ML_DSA_ENCODING_T0_OUTPUT_بائٹاں_فی_SIMD_UNIT,
            .سرا = (i0 + (ناپ_t)1U) * LIBCRUX_ML_DSA_ENCODING_T0_OUTPUT_بائٹاں_فی_SIMD_UNIT
          }
        )),
      &نتیجہ->انکڑے[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.t0.deserialize_to_vector_then_ntt
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_encoding_t0_deserialize_منزل_سمتیہ_then_ntt_37(
  Eurydice_borrow_ٹکڑا_u8 serialized,
  Eurydice_dst_ref_mut_44 ring_elements
)
{
  لكل
  (ناپ_t
    i = (ناپ_t)0U;
    i < serialized.meta / LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_دا_T0_S_ناپ;
    i++)
  {
    ناپ_t i0 = i;
    Eurydice_borrow_ٹکڑا_u8
    بائٹاں =
      Eurydice_ٹکڑا_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .شروع = i0 * LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_دا_T0_S_ناپ,
            .سرا = i0 * LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_دا_T0_S_ناپ +
              LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_دا_T0_S_ناپ
          }
        ));
    libcrux_ml_dsa_encoding_t0_deserialize_37(بائٹاں, &ring_elements.ptr[i0]);
    libcrux_ml_dsa_ntt_ntt_37(&ring_elements.ptr[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.error.deserialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_encoding_error_deserialize_37(
  libcrux_ml_dsa_constants_Eta eta,
  Eurydice_borrow_ٹکڑا_u8 serialized,
  Eurydice_arr_a3 *نتیجہ
)
{
  ناپ_t chunk_ناپ = libcrux_ml_dsa_encoding_error_chunk_ناپ(eta);
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)32U; i++)
  {
    ناپ_t i0 = i;
    libcrux_ml_dsa_simd_portable_error_deserialize_65(eta,
      Eurydice_ٹکڑا_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .شروع = i0 * chunk_ناپ,
            .سرا = (i0 + (ناپ_t)1U) * chunk_ناپ
          }
        )),
      &نتیجہ->انکڑے[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.error.deserialize_to_vector_then_ntt
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_encoding_error_deserialize_منزل_سمتیہ_then_ntt_37(
  libcrux_ml_dsa_constants_Eta eta,
  ناپ_t ring_element_ناپ,
  Eurydice_borrow_ٹکڑا_u8 serialized,
  Eurydice_dst_ref_mut_44 ring_elements
)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < serialized.meta / ring_element_ناپ; i++)
  {
    ناپ_t i0 = i;
    Eurydice_borrow_ٹکڑا_u8
    بائٹاں =
      Eurydice_ٹکڑا_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .شروع = i0 * ring_element_ناپ,
            .سرا = i0 * ring_element_ناپ + ring_element_ناپ
          }
        ));
    libcrux_ml_dsa_encoding_error_deserialize_37(eta, بائٹاں, &ring_elements.ptr[i0]);
    libcrux_ml_dsa_ntt_ntt_37(&ring_elements.ptr[i0]);
  }
}

/**
 Init with zero
*/
/**
This function found in impl {libcrux_ml_dsa::types::MLDSASignature<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_dsa.types.zero_c5
with const generics
- SIZE= 2420
*/
ساكن مضمن Eurydice_arr_85 libcrux_ml_dsa_types_zero_c5_37(فراغ)
{
  أرجع (KRML_CLITERAL(Eurydice_arr_85){ .انکڑے = { 0U } });
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.t0.serialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_encoding_t0_serialize_37(
  ثابت Eurydice_arr_a3 *re,
  Eurydice_mut_borrow_ٹکڑا_u8 serialized
)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)32U; i++)
  {
    ناپ_t i0 = i;
    ثابت Eurydice_arr_4d *simd_unit = &re->انکڑے[i0];
    libcrux_ml_dsa_simd_portable_t0_serialize_65(simd_unit,
      Eurydice_ٹکڑا_subslice_mut_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .شروع = i0 * LIBCRUX_ML_DSA_ENCODING_T0_OUTPUT_بائٹاں_فی_SIMD_UNIT,
            .سرا = (i0 + (ناپ_t)1U) * LIBCRUX_ML_DSA_ENCODING_T0_OUTPUT_بائٹاں_فی_SIMD_UNIT
          }
        )));
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.error.serialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_encoding_error_serialize_37(
  libcrux_ml_dsa_constants_Eta eta,
  ثابت Eurydice_arr_a3 *re,
  Eurydice_mut_borrow_ٹکڑا_u8 serialized
)
{
  ناپ_t output_بائٹاں_فی_simd_unit = libcrux_ml_dsa_encoding_error_chunk_ناپ(eta);
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)32U; i++)
  {
    ناپ_t i0 = i;
    ثابت Eurydice_arr_4d *simd_unit = &re->انکڑے[i0];
    libcrux_ml_dsa_simd_portable_error_serialize_65(eta,
      simd_unit,
      Eurydice_ٹکڑا_subslice_mut_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .شروع = i0 * output_بائٹاں_فی_simd_unit,
            .سرا = (i0 + (ناپ_t)1U) * output_بائٹاں_فی_simd_unit
          }
        )));
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.t1.serialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_encoding_t1_serialize_37(
  ثابت Eurydice_arr_a3 *re,
  Eurydice_mut_borrow_ٹکڑا_u8 serialized
)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)32U; i++)
  {
    ناپ_t i0 = i;
    ثابت Eurydice_arr_4d *simd_unit = &re->انکڑے[i0];
    libcrux_ml_dsa_simd_portable_t1_serialize_65(simd_unit,
      Eurydice_ٹکڑا_subslice_mut_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .شروع = i0 * LIBCRUX_ML_DSA_ENCODING_T1_SERIALIZE_OUTPUT_بائٹاں_فی_SIMD_UNIT,
            .سرا = (i0 + (ناپ_t)1U) *
              LIBCRUX_ML_DSA_ENCODING_T1_SERIALIZE_OUTPUT_بائٹاں_فی_SIMD_UNIT
          }
        )));
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.verification_key.generate_serialized
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_encoding_verification_کلید_generate_serialized_37(
  Eurydice_borrow_ٹکڑا_u8 بیج,
  Eurydice_dst_ref_shared_44 t1,
  Eurydice_mut_borrow_ٹکڑا_u8 verification_کلید_serialized
)
{
  Eurydice_ٹکڑا_copy(Eurydice_ٹکڑا_subslice_mut_c8(verification_کلید_serialized,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .شروع = (ناپ_t)0U,
          .سرا = LIBCRUX_ML_DSA_CONSTANTS_بیج_FOR_A_ناپ
        }
      )),
    بیج,
    uint8_t);
  لكل (ناپ_t i = (ناپ_t)0U; i < t1.meta; i++)
  {
    ناپ_t i0 = i;
    ثابت Eurydice_arr_a3 *ring_element = &t1.ptr[i0];
    ناپ_t
    وتھ =
      LIBCRUX_ML_DSA_CONSTANTS_بیج_FOR_A_ناپ +
        i0 * LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_دا_T1_S_ناپ;
    libcrux_ml_dsa_encoding_t1_serialize_37(ring_element,
      Eurydice_ٹکڑا_subslice_mut_c8(verification_کلید_serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .شروع = وتھ,
            .سرا = وتھ + LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_دا_T1_S_ناپ
          }
        )));
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.arithmetic.power2round_vector
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_arithmetic_power2round_سمتیہ_37(
  Eurydice_dst_ref_mut_44 t,
  Eurydice_dst_ref_mut_44 t1
)
{
  لكل (ناپ_t i0 = (ناپ_t)0U; i0 < t.meta; i0++)
  {
    ناپ_t i1 = i0;
    لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)32U; i++)
    {
      ناپ_t j = i;
      libcrux_ml_dsa_simd_portable_power2round_65(&t.ptr[i1].انکڑے[j], &t1.ptr[i1].انکڑے[j]);
    }
  }
}

/**
 Declassify secret memory.

 No-op if `valgrind_ct_test` cfg is not enabled.
*/
/**
A monomorphic instance of libcrux_secrets.mem_requests.ct_declassify
with types Eurydice_arr libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients[[$4size_t]]

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_secrets_mem_بینتیاں_ct_declassify_f5(ثابت Eurydice_arr_9d *val)
{

}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 8
*/
ساكن مضمن Eurydice_dst_ref_shared_44
Eurydice_array_منزل_ٹکڑا_shared_200(ثابت Eurydice_arr_8f *a)
{
  Eurydice_dst_ref_shared_44 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)8U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 4
*/
ساكن مضمن Eurydice_dst_ref_shared_44
Eurydice_array_منزل_ٹکڑا_shared_20(ثابت Eurydice_arr_9d *a)
{
  Eurydice_dst_ref_shared_44 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)4U;
  أرجع lit;
}

/**
 Compute InvertNTT(Â ◦ ŝ₁) + s₂
*/
/**
A monomorphic instance of libcrux_ml_dsa.matrix.compute_as1_plus_s2
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_میٹرکس_compute_as1_plus_s2_37(
  ناپ_t صفاں_وچ_a,
  ناپ_t columns_وچ_a,
  Eurydice_dst_ref_mut_44 a_as_ntt,
  Eurydice_dst_ref_shared_44 s1_ntt,
  Eurydice_dst_ref_shared_44 s1_s2,
  Eurydice_dst_ref_mut_44 نتیجہ
)
{
  لكل (ناپ_t i0 = (ناپ_t)0U; i0 < صفاں_وچ_a; i0++)
  {
    ناپ_t i1 = i0;
    لكل (ناپ_t i = (ناپ_t)0U; i < columns_وچ_a; i++)
    {
      ناپ_t j = i;
      libcrux_ml_dsa_ntt_ntt_multiply_montgomery_37(&a_as_ntt.ptr[i1 * columns_وچ_a + j],
        &s1_ntt.ptr[j]);
      libcrux_ml_dsa_polynomial_جوڑو_ff_37(&نتیجہ.ptr[i1], &a_as_ntt.ptr[i1 * columns_وچ_a + j]);
    }
  }
  لكل (ناپ_t i = (ناپ_t)0U; i < نتیجہ.meta; i++)
  {
    ناپ_t i0 = i;
    libcrux_ml_dsa_polynomial_barrett_reduce_ff_37(&نتیجہ.ptr[i0]);
    libcrux_ml_dsa_ntt_invert_ntt_montgomery_37(&نتیجہ.ptr[i0]);
    libcrux_ml_dsa_polynomial_جوڑو_ff_37(&نتیجہ.ptr[i0], &s1_s2.ptr[columns_وچ_a + i0]);
  }
}

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients, core_ops_range_Range size_t, Eurydice_derefed_slice libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 8
*/
ساكن مضمن Eurydice_dst_ref_shared_44
Eurydice_array_منزل_subslice_shared_25(ثابت Eurydice_arr_8f *a, core_ops_range_Range_87 r)
{
  أرجع
    (
      KRML_CLITERAL(Eurydice_dst_ref_shared_44){ .ptr = a->انکڑے + r.شروع, .meta = r.سرا - r.شروع }
    );
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 4
*/
ساكن مضمن Eurydice_dst_ref_mut_44 Eurydice_array_منزل_ٹکڑا_mut_201(Eurydice_arr_9d *a)
{
  Eurydice_dst_ref_mut_44 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)4U;
  أرجع lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 16
*/
ساكن مضمن Eurydice_dst_ref_mut_44 Eurydice_array_منزل_ٹکڑا_mut_200(Eurydice_arr_2f *a)
{
  Eurydice_dst_ref_mut_44 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)16U;
  أرجع lit;
}

/**
A monomorphic instance of libcrux_ml_dsa.sample.rejection_sample_less_than_field_modulus
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ساكن KRML_MUSTINLINE bool
libcrux_ml_dsa_sample_rejection_sample_less_than_میدان_modulus_37(
  Eurydice_borrow_ٹکڑا_u8 randomness,
  ناپ_t *sampled_coefficients,
  Eurydice_arr_d0 *باہرلا
)
{
  bool پورا = false;
  لكل (ناپ_t i = (ناپ_t)0U; i < randomness.meta / (ناپ_t)24U; i++)
  {
    ناپ_t _cloop_i = i;
    Eurydice_borrow_ٹکڑا_u8
    random_بائٹاں =
      Eurydice_ٹکڑا_subslice_shared_c8(randomness,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .شروع = _cloop_i * (ناپ_t)24U,
            .سرا = _cloop_i * (ناپ_t)24U + (ناپ_t)24U
          }
        ));
    إذا (!پورا)
    {
      ناپ_t
      sampled =
        libcrux_ml_dsa_simd_portable_rejection_sample_less_than_میدان_modulus_65(random_بائٹاں,
          Eurydice_array_منزل_subslice_from_mut_11(باہرلا, sampled_coefficients[0U]));
      sampled_coefficients[0U] += sampled;
      إذا (sampled_coefficients[0U] >= LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_وچ_RING_ELEMENT)
      {
        پورا = true;
      }
    }
  }
  أرجع پورا;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 8
*/
ساكن مضمن Eurydice_dst_ref_mut_44 Eurydice_array_منزل_ٹکڑا_mut_20(Eurydice_arr_8f *a)
{
  Eurydice_dst_ref_mut_44 lit;
  lit.ptr = a->انکڑے;
  lit.meta = (ناپ_t)8U;
  أرجع lit;
}

/**
A monomorphic instance of libcrux_ml_dsa.sample.rejection_sample_less_than_eta_equals_4
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ساكن KRML_MUSTINLINE bool
libcrux_ml_dsa_sample_rejection_sample_less_than_eta_equals_4_37(
  Eurydice_borrow_ٹکڑا_u8 randomness,
  ناپ_t *sampled_coefficients,
  Eurydice_arr_d0 *باہرلا
)
{
  bool پورا = false;
  لكل (ناپ_t i = (ناپ_t)0U; i < randomness.meta / (ناپ_t)4U; i++)
  {
    ناپ_t _cloop_i = i;
    Eurydice_borrow_ٹکڑا_u8
    random_بائٹاں =
      Eurydice_ٹکڑا_subslice_shared_c8(randomness,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .شروع = _cloop_i * (ناپ_t)4U,
            .سرا = _cloop_i * (ناپ_t)4U + (ناپ_t)4U
          }
        ));
    إذا (!پورا)
    {
      ناپ_t
      sampled =
        libcrux_ml_dsa_simd_portable_rejection_sample_less_than_eta_equals_4_65(random_بائٹاں,
          Eurydice_array_منزل_subslice_from_mut_11(باہرلا, sampled_coefficients[0U]));
      sampled_coefficients[0U] += sampled;
      إذا (sampled_coefficients[0U] >= LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_وچ_RING_ELEMENT)
      {
        پورا = true;
      }
    }
  }
  أرجع پورا;
}

/**
A monomorphic instance of libcrux_ml_dsa.sample.rejection_sample_less_than_eta_equals_2
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ساكن KRML_MUSTINLINE bool
libcrux_ml_dsa_sample_rejection_sample_less_than_eta_equals_2_37(
  Eurydice_borrow_ٹکڑا_u8 randomness,
  ناپ_t *sampled_coefficients,
  Eurydice_arr_d0 *باہرلا
)
{
  bool پورا = false;
  لكل (ناپ_t i = (ناپ_t)0U; i < randomness.meta / (ناپ_t)4U; i++)
  {
    ناپ_t _cloop_i = i;
    Eurydice_borrow_ٹکڑا_u8
    random_بائٹاں =
      Eurydice_ٹکڑا_subslice_shared_c8(randomness,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .شروع = _cloop_i * (ناپ_t)4U,
            .سرا = _cloop_i * (ناپ_t)4U + (ناپ_t)4U
          }
        ));
    إذا (!پورا)
    {
      ناپ_t
      sampled =
        libcrux_ml_dsa_simd_portable_rejection_sample_less_than_eta_equals_2_65(random_بائٹاں,
          Eurydice_array_منزل_subslice_from_mut_11(باہرلا, sampled_coefficients[0U]));
      sampled_coefficients[0U] += sampled;
      إذا (sampled_coefficients[0U] >= LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_وچ_RING_ELEMENT)
      {
        پورا = true;
      }
    }
  }
  أرجع پورا;
}

/**
A monomorphic instance of libcrux_ml_dsa.sample.rejection_sample_less_than_eta
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ساكن KRML_MUSTINLINE bool
libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(
  libcrux_ml_dsa_constants_Eta eta,
  Eurydice_borrow_ٹکڑا_u8 randomness,
  ناپ_t *sampled,
  Eurydice_arr_d0 *باہرلا
)
{
  بدل (eta)
  {
    حالة libcrux_ml_dsa_constants_Eta_Two:
      {
        اكسر;
      }
    حالة libcrux_ml_dsa_constants_Eta_Four:
      {
        أرجع
          libcrux_ml_dsa_sample_rejection_sample_less_than_eta_equals_4_37(randomness,
            sampled,
            باہرلا);
      }
    افتراضي:
      {
        KRML_HOST_EPRINTF("KaRaMeL incomplete match at %s:%d\n", __FILE__, __LINE__);
        KRML_HOST_EXIT(253U);
      }
  }
  أرجع
    libcrux_ml_dsa_sample_rejection_sample_less_than_eta_equals_2_37(randomness,
      sampled,
      باہرلا);
}

تعريفنوع بنية libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_MLDSA87_کلید_Pair_s
{
  Eurydice_arr_e2 signing_کلید;
  Eurydice_arr_43 verification_کلید;
}
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_MLDSA87_کلید_Pair;

تعريفنوع بنية libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_MLDSA65_کلید_Pair_s
{
  Eurydice_arr_24 signing_کلید;
  Eurydice_arr_29 verification_کلید;
}
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_MLDSA65_کلید_Pair;

تعريفنوع بنية libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_MLDSA44_کلید_Pair_s
{
  Eurydice_arr_10 signing_کلید;
  Eurydice_arr_02 verification_کلید;
}
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_MLDSA44_کلید_Pair;

#إذا defined(__cplusplus)
}
#جے_انت

#تعریف_کرو libcrux_mldsa_core_H_DEFINED
#جے_انت /* libcrux_mldsa_core_H */

/* from libcrux/combined_extraction/generated/libcrux_ct_ops.h */
/*
 * SPDX-FileCopyrightText: 2025 Cryspen Sarl <info@cryspen.com>
 *
 * SPDX-License-Identifier: MIT or Apache-2.0
 *
 * This code was generated with the following revisions:
 * Charon: e656e17bff6ca5efac8ab6919b9b74cb9a8dd8ad
 * Eurydice: aaa9fa657fb6f09802edb890252040d94cd93982
 * Karamel: 8c19d41458ce5cbfea029ebc03334ba96d149039
 * F*: unset
 * Libcrux: c4e5e5e511bbc4c53f826163f57bfd10e9228911
 */


#جے_بنا_تعریف libcrux_ct_ops_H
#تعریف_کرو libcrux_ct_ops_H



#إذا defined(__cplusplus)
خارجي "C" {
#جے_انت


/**
 Return 1 if `value` is not zero and 0 otherwise.
*/
ساكن KRML_NOINLINE uint8_t libcrux_ml_kem_constant_ویلا_ops_inz(uint8_t قدر)
{
  uint16_t value0 = (uint16_t)(uint32_t)قدر;
  uint8_t نتیجہ = (uint8_t)((uint32_t)core_عدد_u16_wrapping_جوڑو(~value0, 1U) >> 8U & 0xFFFFU);
  أرجع (uint32_t)نتیجہ & 1U;
}

ساكن KRML_NOINLINE uint8_t libcrux_ml_kem_constant_ویلا_ops_is_non_zero(uint8_t قدر)
{
  أرجع libcrux_ml_kem_constant_ویلا_ops_inz(قدر);
}

/**
 Return 1 if the bytes of `lhs` and `rhs` do not exactly
 match and 0 otherwise.
*/
ساكن KRML_NOINLINE uint8_t
libcrux_ml_kem_constant_ویلا_ops_compare(
  Eurydice_borrow_ٹکڑا_u8 lhs,
  Eurydice_borrow_ٹکڑا_u8 rhs
)
{
  uint8_t r = 0U;
  لكل (ناپ_t i = (ناپ_t)0U; i < lhs.meta; i++)
  {
    ناپ_t i0 = i;
    uint8_t nr = (uint32_t)r | ((uint32_t)lhs.ptr[i0] ^ (uint32_t)rhs.ptr[i0]);
    r = nr;
  }
  أرجع libcrux_ml_kem_constant_ویلا_ops_is_non_zero(r);
}

ساكن KRML_NOINLINE uint8_t
libcrux_ml_kem_constant_ویلا_ops_compare_ciphertexts_وچ_constant_ویلا(
  Eurydice_borrow_ٹکڑا_u8 lhs,
  Eurydice_borrow_ٹکڑا_u8 rhs
)
{
  أرجع libcrux_ml_kem_constant_ویلا_ops_compare(lhs, rhs);
}

/**
 If `selector` is not zero, return the bytes in `rhs`; return the bytes in
 `lhs` otherwise.
*/
ساكن KRML_NOINLINE Eurydice_arr_ec
libcrux_ml_kem_constant_ویلا_ops_select_ct(
  Eurydice_borrow_ٹکڑا_u8 lhs,
  Eurydice_borrow_ٹکڑا_u8 rhs,
  uint8_t selector
)
{
  uint8_t
  نقاب = core_عدد_u8_wrapping_sub(libcrux_ml_kem_constant_ویلا_ops_is_non_zero(selector), 1U);
  Eurydice_arr_ec باہرلا = { .انکڑے = { 0U } };
  لكل (ناپ_t i = (ناپ_t)0U; i < LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_ناپ; i++)
  {
    ناپ_t i0 = i;
    uint8_t
    outi =
      ((uint32_t)lhs.ptr[i0] & (uint32_t)نقاب) | ((uint32_t)rhs.ptr[i0] & (~(uint32_t)نقاب & 0xFFU));
    باہرلا.انکڑے[i0] = outi;
  }
  أرجع باہرلا;
}

ساكن KRML_NOINLINE Eurydice_arr_ec
libcrux_ml_kem_constant_ویلا_ops_select_shared_secret_وچ_constant_ویلا(
  Eurydice_borrow_ٹکڑا_u8 lhs,
  Eurydice_borrow_ٹکڑا_u8 rhs,
  uint8_t selector
)
{
  أرجع libcrux_ml_kem_constant_ویلا_ops_select_ct(lhs, rhs, selector);
}

ساكن KRML_NOINLINE Eurydice_arr_ec
libcrux_ml_kem_constant_ویلا_ops_compare_ciphertexts_select_shared_secret_وچ_constant_ویلا(
  Eurydice_borrow_ٹکڑا_u8 lhs_c,
  Eurydice_borrow_ٹکڑا_u8 rhs_c,
  Eurydice_borrow_ٹکڑا_u8 lhs_s,
  Eurydice_borrow_ٹکڑا_u8 rhs_s
)
{
  uint8_t
  selector = libcrux_ml_kem_constant_ویلا_ops_compare_ciphertexts_وچ_constant_ویلا(lhs_c, rhs_c);
  أرجع
    libcrux_ml_kem_constant_ویلا_ops_select_shared_secret_وچ_constant_ویلا(lhs_s,
      rhs_s,
      selector);
}

#إذا defined(__cplusplus)
}
#جے_انت

#تعریف_کرو libcrux_ct_ops_H_DEFINED
#جے_انت /* libcrux_ct_ops_H */

/* from libcrux/combined_extraction/generated/libcrux_mldsa_portable.h */
/*
 * SPDX-FileCopyrightText: 2025 Cryspen Sarl <info@cryspen.com>
 *
 * SPDX-License-Identifier: MIT or Apache-2.0
 *
 * This code was generated with the following revisions:
 * Charon: e656e17bff6ca5efac8ab6919b9b74cb9a8dd8ad
 * Eurydice: aaa9fa657fb6f09802edb890252040d94cd93982
 * Karamel: 8c19d41458ce5cbfea029ebc03334ba96d149039
 * F*: unset
 * Libcrux: c4e5e5e511bbc4c53f826163f57bfd10e9228911
 */


#جے_بنا_تعریف libcrux_mldsa_portable_H
#تعریف_کرو libcrux_mldsa_portable_H



#إذا defined(__cplusplus)
خارجي "C" {
#جے_انت


تعريفنوع بنية libcrux_ml_dsa_hash_functions_portable_Shake128X4_s
{
  Eurydice_arr_7c state0;
  Eurydice_arr_7c state1;
  Eurydice_arr_7c state2;
  Eurydice_arr_7c state3;
}
libcrux_ml_dsa_hash_functions_portable_Shake128X4;

تعريفنوع libcrux_sha3_portable_KeccakState libcrux_ml_dsa_hash_functions_portable_Shake256;

تعريفنوع بنية libcrux_ml_dsa_hash_functions_portable_Shake256X4_s
{
  Eurydice_arr_7c state0;
  Eurydice_arr_7c state1;
  Eurydice_arr_7c state2;
  Eurydice_arr_7c state3;
}
libcrux_ml_dsa_hash_functions_portable_Shake256X4;

تعريفنوع libcrux_sha3_portable_incremental_Shake256Xof
libcrux_ml_dsa_hash_functions_portable_Shake256Xof;

ساكن KRML_MUSTINLINE libcrux_ml_dsa_hash_functions_portable_Shake128X4
libcrux_ml_dsa_hash_functions_portable_init_absorb(
  Eurydice_borrow_ٹکڑا_u8 input0,
  Eurydice_borrow_ٹکڑا_u8 input1,
  Eurydice_borrow_ٹکڑا_u8 input2,
  Eurydice_borrow_ٹکڑا_u8 input3
)
{
  Eurydice_arr_7c state0 = libcrux_sha3_portable_incremental_shake128_init();
  libcrux_sha3_portable_incremental_shake128_absorb_final(&state0, input0);
  Eurydice_arr_7c state1 = libcrux_sha3_portable_incremental_shake128_init();
  libcrux_sha3_portable_incremental_shake128_absorb_final(&state1, input1);
  Eurydice_arr_7c state2 = libcrux_sha3_portable_incremental_shake128_init();
  libcrux_sha3_portable_incremental_shake128_absorb_final(&state2, input2);
  Eurydice_arr_7c state3 = libcrux_sha3_portable_incremental_shake128_init();
  libcrux_sha3_portable_incremental_shake128_absorb_final(&state3, input3);
  أرجع
    (
      KRML_CLITERAL(libcrux_ml_dsa_hash_functions_portable_Shake128X4){
        .state0 = state0,
        .state1 = state1,
        .state2 = state2,
        .state3 = state3
      }
    );
}

ساكن KRML_MUSTINLINE Eurydice_arr_7c
libcrux_ml_dsa_hash_functions_portable_init_absorb_final_shake256(
  Eurydice_borrow_ٹکڑا_u8 داخلہ
)
{
  Eurydice_arr_7c state = libcrux_sha3_portable_incremental_shake256_init();
  libcrux_sha3_portable_incremental_shake256_absorb_final(&state, داخلہ);
  أرجع state;
}

ساكن KRML_MUSTINLINE libcrux_ml_dsa_hash_functions_portable_Shake256X4
libcrux_ml_dsa_hash_functions_portable_init_absorb_x4(
  Eurydice_borrow_ٹکڑا_u8 input0,
  Eurydice_borrow_ٹکڑا_u8 input1,
  Eurydice_borrow_ٹکڑا_u8 input2,
  Eurydice_borrow_ٹکڑا_u8 input3
)
{
  Eurydice_arr_7c state0 = libcrux_sha3_portable_incremental_shake256_init();
  libcrux_sha3_portable_incremental_shake256_absorb_final(&state0, input0);
  Eurydice_arr_7c state1 = libcrux_sha3_portable_incremental_shake256_init();
  libcrux_sha3_portable_incremental_shake256_absorb_final(&state1, input1);
  Eurydice_arr_7c state2 = libcrux_sha3_portable_incremental_shake256_init();
  libcrux_sha3_portable_incremental_shake256_absorb_final(&state2, input2);
  Eurydice_arr_7c state3 = libcrux_sha3_portable_incremental_shake256_init();
  libcrux_sha3_portable_incremental_shake256_absorb_final(&state3, input3);
  أرجع
    (
      KRML_CLITERAL(libcrux_ml_dsa_hash_functions_portable_Shake256X4){
        .state0 = state0,
        .state1 = state1,
        .state2 = state2,
        .state3 = state3
      }
    );
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_hash_functions_portable_shake128(
  Eurydice_borrow_ٹکڑا_u8 داخلہ,
  Eurydice_mut_borrow_ٹکڑا_u8 باہرلا
)
{
  libcrux_sha3_portable_shake128(باہرلا, داخلہ);
}

ساكن KRML_MUSTINLINE Eurydice_arr_ff
libcrux_ml_dsa_hash_functions_portable_squeeze_پہلا_بلاک_shake256(Eurydice_arr_7c *state)
{
  Eurydice_arr_ff باہرلا = { .انکڑے = { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_پہلا_بلاک(state,
    Eurydice_array_منزل_ٹکڑا_mut_58(&باہرلا));
  أرجع باہرلا;
}

ساكن KRML_MUSTINLINE Eurydice_arr_ff_x4
libcrux_ml_dsa_hash_functions_portable_squeeze_پہلا_بلاک_x4(
  libcrux_ml_dsa_hash_functions_portable_Shake256X4 *state
)
{
  Eurydice_arr_ff out0 = { .انکڑے = { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_پہلا_بلاک(&state->state0,
    Eurydice_array_منزل_ٹکڑا_mut_58(&out0));
  Eurydice_arr_ff out1 = { .انکڑے = { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_پہلا_بلاک(&state->state1,
    Eurydice_array_منزل_ٹکڑا_mut_58(&out1));
  Eurydice_arr_ff out2 = { .انکڑے = { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_پہلا_بلاک(&state->state2,
    Eurydice_array_منزل_ٹکڑا_mut_58(&out2));
  Eurydice_arr_ff out3 = { .انکڑے = { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_پہلا_بلاک(&state->state3,
    Eurydice_array_منزل_ٹکڑا_mut_58(&out3));
  أرجع
    (KRML_CLITERAL(Eurydice_arr_ff_x4){ .fst = out0, .snd = out1, .thd = out2, .f3 = out3 });
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_hash_functions_portable_squeeze_پہلا_five_بلاکاں(
  libcrux_ml_dsa_hash_functions_portable_Shake128X4 *state,
  Eurydice_arr_d10 *out0,
  Eurydice_arr_d10 *out1,
  Eurydice_arr_d10 *out2,
  Eurydice_arr_d10 *out3
)
{
  libcrux_sha3_portable_incremental_shake128_squeeze_پہلا_five_بلاکاں(&state->state0,
    Eurydice_array_منزل_ٹکڑا_mut_4c(out0));
  libcrux_sha3_portable_incremental_shake128_squeeze_پہلا_five_بلاکاں(&state->state1,
    Eurydice_array_منزل_ٹکڑا_mut_4c(out1));
  libcrux_sha3_portable_incremental_shake128_squeeze_پہلا_five_بلاکاں(&state->state2,
    Eurydice_array_منزل_ٹکڑا_mut_4c(out2));
  libcrux_sha3_portable_incremental_shake128_squeeze_پہلا_five_بلاکاں(&state->state3,
    Eurydice_array_منزل_ٹکڑا_mut_4c(out3));
}

ساكن KRML_MUSTINLINE Eurydice_arr_c5_x4
libcrux_ml_dsa_hash_functions_portable_squeeze_اگلا_بلاک(
  libcrux_ml_dsa_hash_functions_portable_Shake128X4 *state
)
{
  Eurydice_arr_c5 out0 = { .انکڑے = { 0U } };
  libcrux_sha3_portable_incremental_shake128_squeeze_اگلا_بلاک(&state->state0,
    Eurydice_array_منزل_ٹکڑا_mut_2c(&out0));
  Eurydice_arr_c5 out1 = { .انکڑے = { 0U } };
  libcrux_sha3_portable_incremental_shake128_squeeze_اگلا_بلاک(&state->state1,
    Eurydice_array_منزل_ٹکڑا_mut_2c(&out1));
  Eurydice_arr_c5 out2 = { .انکڑے = { 0U } };
  libcrux_sha3_portable_incremental_shake128_squeeze_اگلا_بلاک(&state->state2,
    Eurydice_array_منزل_ٹکڑا_mut_2c(&out2));
  Eurydice_arr_c5 out3 = { .انکڑے = { 0U } };
  libcrux_sha3_portable_incremental_shake128_squeeze_اگلا_بلاک(&state->state3,
    Eurydice_array_منزل_ٹکڑا_mut_2c(&out3));
  أرجع
    (KRML_CLITERAL(Eurydice_arr_c5_x4){ .fst = out0, .snd = out1, .thd = out2, .f3 = out3 });
}

ساكن KRML_MUSTINLINE Eurydice_arr_ff
libcrux_ml_dsa_hash_functions_portable_squeeze_اگلا_بلاک_shake256(Eurydice_arr_7c *state)
{
  Eurydice_arr_ff باہرلا = { .انکڑے = { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_اگلا_بلاک(state,
    Eurydice_array_منزل_ٹکڑا_mut_58(&باہرلا));
  أرجع باہرلا;
}

ساكن KRML_MUSTINLINE Eurydice_arr_ff_x4
libcrux_ml_dsa_hash_functions_portable_squeeze_اگلا_بلاک_x4(
  libcrux_ml_dsa_hash_functions_portable_Shake256X4 *state
)
{
  Eurydice_arr_ff out0 = { .انکڑے = { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_اگلا_بلاک(&state->state0,
    Eurydice_array_منزل_ٹکڑا_mut_58(&out0));
  Eurydice_arr_ff out1 = { .انکڑے = { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_اگلا_بلاک(&state->state1,
    Eurydice_array_منزل_ٹکڑا_mut_58(&out1));
  Eurydice_arr_ff out2 = { .انکڑے = { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_اگلا_بلاک(&state->state2,
    Eurydice_array_منزل_ٹکڑا_mut_58(&out2));
  Eurydice_arr_ff out3 = { .انکڑے = { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_اگلا_بلاک(&state->state3,
    Eurydice_array_منزل_ٹکڑا_mut_58(&out3));
  أرجع
    (KRML_CLITERAL(Eurydice_arr_ff_x4){ .fst = out0, .snd = out1, .thd = out2, .f3 = out3 });
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake128::Xof for libcrux_ml_dsa::hash_functions::portable::Shake128}
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_hash_functions_portable_shake128_7b(
  Eurydice_borrow_ٹکڑا_u8 داخلہ,
  Eurydice_mut_borrow_ٹکڑا_u8 باہرلا
)
{
  libcrux_ml_dsa_hash_functions_portable_shake128(داخلہ, باہرلا);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake128::XofX4 for libcrux_ml_dsa::hash_functions::portable::Shake128X4}
*/
ساكن KRML_MUSTINLINE libcrux_ml_dsa_hash_functions_portable_Shake128X4
libcrux_ml_dsa_hash_functions_portable_init_absorb_11(
  Eurydice_borrow_ٹکڑا_u8 input0,
  Eurydice_borrow_ٹکڑا_u8 input1,
  Eurydice_borrow_ٹکڑا_u8 input2,
  Eurydice_borrow_ٹکڑا_u8 input3
)
{
  أرجع libcrux_ml_dsa_hash_functions_portable_init_absorb(input0, input1, input2, input3);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake128::XofX4 for libcrux_ml_dsa::hash_functions::portable::Shake128X4}
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_hash_functions_portable_squeeze_پہلا_five_بلاکاں_11(
  libcrux_ml_dsa_hash_functions_portable_Shake128X4 *self,
  Eurydice_arr_d10 *out0,
  Eurydice_arr_d10 *out1,
  Eurydice_arr_d10 *out2,
  Eurydice_arr_d10 *out3
)
{
  libcrux_ml_dsa_hash_functions_portable_squeeze_پہلا_five_بلاکاں(self, out0, out1, out2, out3);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake128::XofX4 for libcrux_ml_dsa::hash_functions::portable::Shake128X4}
*/
ساكن KRML_MUSTINLINE Eurydice_arr_c5_x4
libcrux_ml_dsa_hash_functions_portable_squeeze_اگلا_بلاک_11(
  libcrux_ml_dsa_hash_functions_portable_Shake128X4 *self
)
{
  أرجع libcrux_ml_dsa_hash_functions_portable_squeeze_اگلا_بلاک(self);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::DsaXof for libcrux_ml_dsa::hash_functions::portable::Shake256}
*/
ساكن KRML_MUSTINLINE Eurydice_arr_7c
libcrux_ml_dsa_hash_functions_portable_init_absorb_final_61(Eurydice_borrow_ٹکڑا_u8 داخلہ)
{
  أرجع libcrux_ml_dsa_hash_functions_portable_init_absorb_final_shake256(داخلہ);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::DsaXof for libcrux_ml_dsa::hash_functions::portable::Shake256}
*/
ساكن KRML_MUSTINLINE Eurydice_arr_ff
libcrux_ml_dsa_hash_functions_portable_squeeze_پہلا_بلاک_61(Eurydice_arr_7c *self)
{
  أرجع libcrux_ml_dsa_hash_functions_portable_squeeze_پہلا_بلاک_shake256(self);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::DsaXof for libcrux_ml_dsa::hash_functions::portable::Shake256}
*/
ساكن KRML_MUSTINLINE Eurydice_arr_ff
libcrux_ml_dsa_hash_functions_portable_squeeze_اگلا_بلاک_61(Eurydice_arr_7c *self)
{
  أرجع libcrux_ml_dsa_hash_functions_portable_squeeze_اگلا_بلاک_shake256(self);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::Xof for libcrux_ml_dsa::hash_functions::portable::Shake256Xof}
*/
ساكن مضمن فراغ
libcrux_ml_dsa_hash_functions_portable_absorb_26(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *self,
  Eurydice_borrow_ٹکڑا_u8 داخلہ
)
{
  libcrux_sha3_portable_incremental_absorb_42(self, داخلہ);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::Xof for libcrux_ml_dsa::hash_functions::portable::Shake256Xof}
*/
ساكن مضمن فراغ
libcrux_ml_dsa_hash_functions_portable_absorb_final_26(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *self,
  Eurydice_borrow_ٹکڑا_u8 داخلہ
)
{
  libcrux_sha3_portable_incremental_absorb_final_42(self, داخلہ);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::Xof for libcrux_ml_dsa::hash_functions::portable::Shake256Xof}
*/
ساكن مضمن libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
libcrux_ml_dsa_hash_functions_portable_init_26(فراغ)
{
  أرجع libcrux_sha3_portable_incremental_new_42();
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::Xof for libcrux_ml_dsa::hash_functions::portable::Shake256Xof}
*/
ساكن مضمن فراغ
libcrux_ml_dsa_hash_functions_portable_squeeze_26(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *self,
  Eurydice_mut_borrow_ٹکڑا_u8 باہرلا
)
{
  libcrux_sha3_portable_incremental_squeeze_42(self, باہرلا);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::XofX4 for libcrux_ml_dsa::hash_functions::portable::Shake256X4}
*/
ساكن KRML_MUSTINLINE libcrux_ml_dsa_hash_functions_portable_Shake256X4
libcrux_ml_dsa_hash_functions_portable_init_absorb_x4_9b(
  Eurydice_borrow_ٹکڑا_u8 input0,
  Eurydice_borrow_ٹکڑا_u8 input1,
  Eurydice_borrow_ٹکڑا_u8 input2,
  Eurydice_borrow_ٹکڑا_u8 input3
)
{
  أرجع libcrux_ml_dsa_hash_functions_portable_init_absorb_x4(input0, input1, input2, input3);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::XofX4 for libcrux_ml_dsa::hash_functions::portable::Shake256X4}
*/
ساكن KRML_MUSTINLINE Eurydice_arr_ff_x4
libcrux_ml_dsa_hash_functions_portable_squeeze_پہلا_بلاک_x4_9b(
  libcrux_ml_dsa_hash_functions_portable_Shake256X4 *self
)
{
  أرجع libcrux_ml_dsa_hash_functions_portable_squeeze_پہلا_بلاک_x4(self);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::XofX4 for libcrux_ml_dsa::hash_functions::portable::Shake256X4}
*/
ساكن KRML_MUSTINLINE Eurydice_arr_ff_x4
libcrux_ml_dsa_hash_functions_portable_squeeze_اگلا_بلاک_x4_9b(
  libcrux_ml_dsa_hash_functions_portable_Shake256X4 *self
)
{
  أرجع libcrux_ml_dsa_hash_functions_portable_squeeze_اگلا_بلاک_x4(self);
}

/**
A monomorphic instance of libcrux_ml_dsa.sample.sample_four_error_ring_elements
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_sample_sample_four_error_ring_elements_29(
  libcrux_ml_dsa_constants_Eta eta,
  Eurydice_borrow_ٹکڑا_u8 بیج,
  uint16_t شروع_اشاریہ,
  Eurydice_dst_ref_mut_44 re
)
{
  Eurydice_arr_91 seed0 = libcrux_ml_dsa_sample_جوڑو_error_domain_separator(بیج, شروع_اشاریہ);
  Eurydice_arr_91
  seed1 = libcrux_ml_dsa_sample_جوڑو_error_domain_separator(بیج, (uint32_t)شروع_اشاریہ + 1U);
  Eurydice_arr_91
  seed2 = libcrux_ml_dsa_sample_جوڑو_error_domain_separator(بیج, (uint32_t)شروع_اشاریہ + 2U);
  Eurydice_arr_91
  seed3 = libcrux_ml_dsa_sample_جوڑو_error_domain_separator(بیج, (uint32_t)شروع_اشاریہ + 3U);
  libcrux_ml_dsa_hash_functions_portable_Shake256X4
  state =
    libcrux_ml_dsa_hash_functions_portable_init_absorb_x4_9b(Eurydice_array_منزل_ٹکڑا_shared_f1(&seed0),
      Eurydice_array_منزل_ٹکڑا_shared_f1(&seed1),
      Eurydice_array_منزل_ٹکڑا_shared_f1(&seed2),
      Eurydice_array_منزل_ٹکڑا_shared_f1(&seed3));
  Eurydice_arr_ff_x4
  randomnesses0 = libcrux_ml_dsa_hash_functions_portable_squeeze_پہلا_بلاک_x4_9b(&state);
  Eurydice_arr_930
  باہرلا =
    { .انکڑے = { { .انکڑے = { 0U } }, { .انکڑے = { 0U } }, { .انکڑے = { 0U } }, { .انکڑے = { 0U } } } };
  ناپ_t sampled0 = (ناپ_t)0U;
  ناپ_t sampled1 = (ناپ_t)0U;
  ناپ_t sampled2 = (ناپ_t)0U;
  ناپ_t sampled3 = (ناپ_t)0U;
  libcrux_ml_dsa_constants_Eta uu____0 = eta;
  bool
  done0 =
    libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____0,
      Eurydice_array_منزل_ٹکڑا_shared_58(&randomnesses0.fst),
      &sampled0,
      باہرلا.انکڑے);
  libcrux_ml_dsa_constants_Eta uu____1 = eta;
  bool
  done1 =
    libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____1,
      Eurydice_array_منزل_ٹکڑا_shared_58(&randomnesses0.snd),
      &sampled1,
      &باہرلا.انکڑے[1U]);
  libcrux_ml_dsa_constants_Eta uu____2 = eta;
  bool
  done2 =
    libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____2,
      Eurydice_array_منزل_ٹکڑا_shared_58(&randomnesses0.thd),
      &sampled2,
      &باہرلا.انکڑے[2U]);
  libcrux_ml_dsa_constants_Eta uu____3 = eta;
  bool
  done3 =
    libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____3,
      Eurydice_array_منزل_ٹکڑا_shared_58(&randomnesses0.f3),
      &sampled3,
      &باہرلا.انکڑے[3U]);
  طالما (true)
  {
    إذا (done0)
    {
      إذا (done1)
      {
        إذا (done2)
        {
          إذا (done3)
          {
            اكسر;
          }
          وإلا
          {
            Eurydice_arr_ff_x4
            randomnesses = libcrux_ml_dsa_hash_functions_portable_squeeze_اگلا_بلاک_x4_9b(&state);
            إذا (!done0)
            {
              libcrux_ml_dsa_constants_Eta uu____4 = eta;
              done0 =
                libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____4,
                  Eurydice_array_منزل_ٹکڑا_shared_58(&randomnesses.fst),
                  &sampled0,
                  باہرلا.انکڑے);
            }
            إذا (!done1)
            {
              libcrux_ml_dsa_constants_Eta uu____5 = eta;
              done1 =
                libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____5,
                  Eurydice_array_منزل_ٹکڑا_shared_58(&randomnesses.snd),
                  &sampled1,
                  &باہرلا.انکڑے[1U]);
            }
            إذا (!done2)
            {
              libcrux_ml_dsa_constants_Eta uu____6 = eta;
              done2 =
                libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____6,
                  Eurydice_array_منزل_ٹکڑا_shared_58(&randomnesses.thd),
                  &sampled2,
                  &باہرلا.انکڑے[2U]);
            }
            إذا (!done3)
            {
              libcrux_ml_dsa_constants_Eta uu____7 = eta;
              done3 =
                libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____7,
                  Eurydice_array_منزل_ٹکڑا_shared_58(&randomnesses.f3),
                  &sampled3,
                  &باہرلا.انکڑے[3U]);
            }
          }
        }
        وإلا
        {
          Eurydice_arr_ff_x4
          randomnesses = libcrux_ml_dsa_hash_functions_portable_squeeze_اگلا_بلاک_x4_9b(&state);
          إذا (!done0)
          {
            libcrux_ml_dsa_constants_Eta uu____8 = eta;
            done0 =
              libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____8,
                Eurydice_array_منزل_ٹکڑا_shared_58(&randomnesses.fst),
                &sampled0,
                باہرلا.انکڑے);
          }
          إذا (!done1)
          {
            libcrux_ml_dsa_constants_Eta uu____9 = eta;
            done1 =
              libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____9,
                Eurydice_array_منزل_ٹکڑا_shared_58(&randomnesses.snd),
                &sampled1,
                &باہرلا.انکڑے[1U]);
          }
          إذا (!done2)
          {
            libcrux_ml_dsa_constants_Eta uu____10 = eta;
            done2 =
              libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____10,
                Eurydice_array_منزل_ٹکڑا_shared_58(&randomnesses.thd),
                &sampled2,
                &باہرلا.انکڑے[2U]);
          }
          إذا (!done3)
          {
            libcrux_ml_dsa_constants_Eta uu____11 = eta;
            done3 =
              libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____11,
                Eurydice_array_منزل_ٹکڑا_shared_58(&randomnesses.f3),
                &sampled3,
                &باہرلا.انکڑے[3U]);
          }
        }
      }
      وإلا
      {
        Eurydice_arr_ff_x4
        randomnesses = libcrux_ml_dsa_hash_functions_portable_squeeze_اگلا_بلاک_x4_9b(&state);
        إذا (!done0)
        {
          libcrux_ml_dsa_constants_Eta uu____12 = eta;
          done0 =
            libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____12,
              Eurydice_array_منزل_ٹکڑا_shared_58(&randomnesses.fst),
              &sampled0,
              باہرلا.انکڑے);
        }
        إذا (!done1)
        {
          libcrux_ml_dsa_constants_Eta uu____13 = eta;
          done1 =
            libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____13,
              Eurydice_array_منزل_ٹکڑا_shared_58(&randomnesses.snd),
              &sampled1,
              &باہرلا.انکڑے[1U]);
        }
        إذا (!done2)
        {
          libcrux_ml_dsa_constants_Eta uu____14 = eta;
          done2 =
            libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____14,
              Eurydice_array_منزل_ٹکڑا_shared_58(&randomnesses.thd),
              &sampled2,
              &باہرلا.انکڑے[2U]);
        }
        إذا (!done3)
        {
          libcrux_ml_dsa_constants_Eta uu____15 = eta;
          done3 =
            libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____15,
              Eurydice_array_منزل_ٹکڑا_shared_58(&randomnesses.f3),
              &sampled3,
              &باہرلا.انکڑے[3U]);
        }
      }
    }
    وإلا
    {
      Eurydice_arr_ff_x4
      randomnesses = libcrux_ml_dsa_hash_functions_portable_squeeze_اگلا_بلاک_x4_9b(&state);
      إذا (!done0)
      {
        libcrux_ml_dsa_constants_Eta uu____16 = eta;
        done0 =
          libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____16,
            Eurydice_array_منزل_ٹکڑا_shared_58(&randomnesses.fst),
            &sampled0,
            باہرلا.انکڑے);
      }
      إذا (!done1)
      {
        libcrux_ml_dsa_constants_Eta uu____17 = eta;
        done1 =
          libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____17,
            Eurydice_array_منزل_ٹکڑا_shared_58(&randomnesses.snd),
            &sampled1,
            &باہرلا.انکڑے[1U]);
      }
      إذا (!done2)
      {
        libcrux_ml_dsa_constants_Eta uu____18 = eta;
        done2 =
          libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____18,
            Eurydice_array_منزل_ٹکڑا_shared_58(&randomnesses.thd),
            &sampled2,
            &باہرلا.انکڑے[2U]);
      }
      إذا (!done3)
      {
        libcrux_ml_dsa_constants_Eta uu____19 = eta;
        done3 =
          libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____19,
            Eurydice_array_منزل_ٹکڑا_shared_58(&randomnesses.f3),
            &sampled3,
            &باہرلا.انکڑے[3U]);
      }
    }
  }
  ناپ_t max0 = (ناپ_t)(uint32_t)شروع_اشاریہ + (ناپ_t)4U;
  ناپ_t max;
  إذا (re.meta < max0)
  {
    max = re.meta;
  }
  وإلا
  {
    max = max0;
  }
  لكل (ناپ_t i = (ناپ_t)(uint32_t)شروع_اشاریہ; i < max; i++)
  {
    ناپ_t i0 = i;
    libcrux_ml_dsa_polynomial_from_i32_array_ff_37(Eurydice_array_منزل_ٹکڑا_shared_2c0(&باہرلا.انکڑے[i0
        % (ناپ_t)4U]),
      &re.ptr[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.samplex4.sample_s1_and_s2
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_samplex4_sample_s1_and_s2_29(
  libcrux_ml_dsa_constants_Eta eta,
  Eurydice_borrow_ٹکڑا_u8 بیج,
  Eurydice_dst_ref_mut_44 s1_s2
)
{
  ناپ_t len = s1_s2.meta;
  لكل (ناپ_t i = (ناپ_t)0U; i < len / (ناپ_t)4U; i++)
  {
    ناپ_t i0 = i;
    libcrux_ml_dsa_sample_sample_four_error_ring_elements_29(eta,
      بیج,
      4U * (uint32_t)(uint16_t)i0,
      s1_s2);
  }
  ناپ_t remainder = len % (ناپ_t)4U;
  إذا (remainder != (ناپ_t)0U)
  {
    libcrux_ml_dsa_sample_sample_four_error_ring_elements_29(eta,
      بیج,
      (uint16_t)(len - remainder),
      s1_s2);
  }
}

/**
 Sample and write out up to four ring elements.

 If i <= `elements_requested`, a field element with domain separated
 seed according to the provided index is generated in
 `tmp_stack[i]`. After successful rejection sampling in
 `tmp_stack[i]`, the ring element is written to `matrix` at the
 provided index in `indices[i]`.
 `rand_stack` is a working buffer that holds initial Shake output.
*/
/**
A monomorphic instance of libcrux_ml_dsa.sample.sample_up_to_four_ring_elements_flat
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_hash_functions_portable_Shake128X4
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_sample_sample_اتے_منزل_four_ring_elements_flat_63(
  ناپ_t columns,
  Eurydice_borrow_ٹکڑا_u8 بیج,
  Eurydice_dst_ref_mut_44 میٹرکس,
  Eurydice_arr_d10 *rand_stack0,
  Eurydice_arr_d10 *rand_stack1,
  Eurydice_arr_d10 *rand_stack2,
  Eurydice_arr_d10 *rand_stack3,
  Eurydice_dst_ref_mut_33 tmp_ڈھیر,
  ناپ_t شروع_اشاریہ,
  ناپ_t elements_requested
)
{
  Eurydice_arr_31
  seed0 =
    libcrux_ml_dsa_sample_جوڑو_domain_separator(بیج,
      libcrux_ml_dsa_sample_sample_اتے_منزل_four_ring_elements_flat_xy(شروع_اشاریہ, columns));
  Eurydice_arr_31
  seed1 =
    libcrux_ml_dsa_sample_جوڑو_domain_separator(بیج,
      libcrux_ml_dsa_sample_sample_اتے_منزل_four_ring_elements_flat_xy(شروع_اشاریہ + (ناپ_t)1U,
        columns));
  Eurydice_arr_31
  seed2 =
    libcrux_ml_dsa_sample_جوڑو_domain_separator(بیج,
      libcrux_ml_dsa_sample_sample_اتے_منزل_four_ring_elements_flat_xy(شروع_اشاریہ + (ناپ_t)2U,
        columns));
  Eurydice_arr_31
  seed3 =
    libcrux_ml_dsa_sample_جوڑو_domain_separator(بیج,
      libcrux_ml_dsa_sample_sample_اتے_منزل_four_ring_elements_flat_xy(شروع_اشاریہ + (ناپ_t)3U,
        columns));
  libcrux_ml_dsa_hash_functions_portable_Shake128X4
  state =
    libcrux_ml_dsa_hash_functions_portable_init_absorb_11(Eurydice_array_منزل_ٹکڑا_shared_e9(&seed0),
      Eurydice_array_منزل_ٹکڑا_shared_e9(&seed1),
      Eurydice_array_منزل_ٹکڑا_shared_e9(&seed2),
      Eurydice_array_منزل_ٹکڑا_shared_e9(&seed3));
  libcrux_ml_dsa_hash_functions_portable_squeeze_پہلا_five_بلاکاں_11(&state,
    rand_stack0,
    rand_stack1,
    rand_stack2,
    rand_stack3);
  ناپ_t sampled0 = (ناپ_t)0U;
  ناپ_t sampled1 = (ناپ_t)0U;
  ناپ_t sampled2 = (ناپ_t)0U;
  ناپ_t sampled3 = (ناپ_t)0U;
  bool
  done0 =
    libcrux_ml_dsa_sample_rejection_sample_less_than_میدان_modulus_37(Eurydice_array_منزل_ٹکڑا_shared_4c(rand_stack0),
      &sampled0,
      tmp_ڈھیر.ptr);
  bool
  done1 =
    libcrux_ml_dsa_sample_rejection_sample_less_than_میدان_modulus_37(Eurydice_array_منزل_ٹکڑا_shared_4c(rand_stack1),
      &sampled1,
      &tmp_ڈھیر.ptr[1U]);
  bool
  done2 =
    libcrux_ml_dsa_sample_rejection_sample_less_than_میدان_modulus_37(Eurydice_array_منزل_ٹکڑا_shared_4c(rand_stack2),
      &sampled2,
      &tmp_ڈھیر.ptr[2U]);
  bool
  done3 =
    libcrux_ml_dsa_sample_rejection_sample_less_than_میدان_modulus_37(Eurydice_array_منزل_ٹکڑا_shared_4c(rand_stack3),
      &sampled3,
      &tmp_ڈھیر.ptr[3U]);
  طالما (true)
  {
    إذا (done0)
    {
      إذا (done1)
      {
        إذا (done2)
        {
          إذا (done3)
          {
            اكسر;
          }
          وإلا
          {
            Eurydice_arr_c5_x4
            randomnesses = libcrux_ml_dsa_hash_functions_portable_squeeze_اگلا_بلاک_11(&state);
            إذا (!done0)
            {
              done0 =
                libcrux_ml_dsa_sample_rejection_sample_less_than_میدان_modulus_37(Eurydice_array_منزل_ٹکڑا_shared_2c(&randomnesses.fst),
                  &sampled0,
                  tmp_ڈھیر.ptr);
            }
            إذا (!done1)
            {
              done1 =
                libcrux_ml_dsa_sample_rejection_sample_less_than_میدان_modulus_37(Eurydice_array_منزل_ٹکڑا_shared_2c(&randomnesses.snd),
                  &sampled1,
                  &tmp_ڈھیر.ptr[1U]);
            }
            إذا (!done2)
            {
              done2 =
                libcrux_ml_dsa_sample_rejection_sample_less_than_میدان_modulus_37(Eurydice_array_منزل_ٹکڑا_shared_2c(&randomnesses.thd),
                  &sampled2,
                  &tmp_ڈھیر.ptr[2U]);
            }
            إذا (!done3)
            {
              done3 =
                libcrux_ml_dsa_sample_rejection_sample_less_than_میدان_modulus_37(Eurydice_array_منزل_ٹکڑا_shared_2c(&randomnesses.f3),
                  &sampled3,
                  &tmp_ڈھیر.ptr[3U]);
            }
          }
        }
        وإلا
        {
          Eurydice_arr_c5_x4
          randomnesses = libcrux_ml_dsa_hash_functions_portable_squeeze_اگلا_بلاک_11(&state);
          إذا (!done0)
          {
            done0 =
              libcrux_ml_dsa_sample_rejection_sample_less_than_میدان_modulus_37(Eurydice_array_منزل_ٹکڑا_shared_2c(&randomnesses.fst),
                &sampled0,
                tmp_ڈھیر.ptr);
          }
          إذا (!done1)
          {
            done1 =
              libcrux_ml_dsa_sample_rejection_sample_less_than_میدان_modulus_37(Eurydice_array_منزل_ٹکڑا_shared_2c(&randomnesses.snd),
                &sampled1,
                &tmp_ڈھیر.ptr[1U]);
          }
          إذا (!done2)
          {
            done2 =
              libcrux_ml_dsa_sample_rejection_sample_less_than_میدان_modulus_37(Eurydice_array_منزل_ٹکڑا_shared_2c(&randomnesses.thd),
                &sampled2,
                &tmp_ڈھیر.ptr[2U]);
          }
          إذا (!done3)
          {
            done3 =
              libcrux_ml_dsa_sample_rejection_sample_less_than_میدان_modulus_37(Eurydice_array_منزل_ٹکڑا_shared_2c(&randomnesses.f3),
                &sampled3,
                &tmp_ڈھیر.ptr[3U]);
          }
        }
      }
      وإلا
      {
        Eurydice_arr_c5_x4
        randomnesses = libcrux_ml_dsa_hash_functions_portable_squeeze_اگلا_بلاک_11(&state);
        إذا (!done0)
        {
          done0 =
            libcrux_ml_dsa_sample_rejection_sample_less_than_میدان_modulus_37(Eurydice_array_منزل_ٹکڑا_shared_2c(&randomnesses.fst),
              &sampled0,
              tmp_ڈھیر.ptr);
        }
        إذا (!done1)
        {
          done1 =
            libcrux_ml_dsa_sample_rejection_sample_less_than_میدان_modulus_37(Eurydice_array_منزل_ٹکڑا_shared_2c(&randomnesses.snd),
              &sampled1,
              &tmp_ڈھیر.ptr[1U]);
        }
        إذا (!done2)
        {
          done2 =
            libcrux_ml_dsa_sample_rejection_sample_less_than_میدان_modulus_37(Eurydice_array_منزل_ٹکڑا_shared_2c(&randomnesses.thd),
              &sampled2,
              &tmp_ڈھیر.ptr[2U]);
        }
        إذا (!done3)
        {
          done3 =
            libcrux_ml_dsa_sample_rejection_sample_less_than_میدان_modulus_37(Eurydice_array_منزل_ٹکڑا_shared_2c(&randomnesses.f3),
              &sampled3,
              &tmp_ڈھیر.ptr[3U]);
        }
      }
    }
    وإلا
    {
      Eurydice_arr_c5_x4
      randomnesses = libcrux_ml_dsa_hash_functions_portable_squeeze_اگلا_بلاک_11(&state);
      إذا (!done0)
      {
        done0 =
          libcrux_ml_dsa_sample_rejection_sample_less_than_میدان_modulus_37(Eurydice_array_منزل_ٹکڑا_shared_2c(&randomnesses.fst),
            &sampled0,
            tmp_ڈھیر.ptr);
      }
      إذا (!done1)
      {
        done1 =
          libcrux_ml_dsa_sample_rejection_sample_less_than_میدان_modulus_37(Eurydice_array_منزل_ٹکڑا_shared_2c(&randomnesses.snd),
            &sampled1,
            &tmp_ڈھیر.ptr[1U]);
      }
      إذا (!done2)
      {
        done2 =
          libcrux_ml_dsa_sample_rejection_sample_less_than_میدان_modulus_37(Eurydice_array_منزل_ٹکڑا_shared_2c(&randomnesses.thd),
            &sampled2,
            &tmp_ڈھیر.ptr[2U]);
      }
      إذا (!done3)
      {
        done3 =
          libcrux_ml_dsa_sample_rejection_sample_less_than_میدان_modulus_37(Eurydice_array_منزل_ٹکڑا_shared_2c(&randomnesses.f3),
            &sampled3,
            &tmp_ڈھیر.ptr[3U]);
      }
    }
  }
  لكل (ناپ_t i = (ناپ_t)0U; i < elements_requested; i++)
  {
    ناپ_t k = i;
    libcrux_ml_dsa_polynomial_from_i32_array_ff_37(Eurydice_array_منزل_ٹکڑا_shared_2c0(&tmp_ڈھیر.ptr[k]),
      &میٹرکس.ptr[شروع_اشاریہ + k]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.samplex4.matrix_flat
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_hash_functions_portable_Shake128X4
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_samplex4_میٹرکس_flat_63(
  ناپ_t columns,
  Eurydice_borrow_ٹکڑا_u8 بیج,
  Eurydice_dst_ref_mut_44 میٹرکس
)
{
  Eurydice_arr_d10 rand_stack0 = { .انکڑے = { 0U } };
  Eurydice_arr_d10 rand_stack1 = { .انکڑے = { 0U } };
  Eurydice_arr_d10 rand_stack2 = { .انکڑے = { 0U } };
  Eurydice_arr_d10 rand_stack3 = { .انکڑے = { 0U } };
  Eurydice_arr_930
  tmp_ڈھیر =
    { .انکڑے = { { .انکڑے = { 0U } }, { .انکڑے = { 0U } }, { .انکڑے = { 0U } }, { .انکڑے = { 0U } } } };
  لكل (ناپ_t i = (ناپ_t)0U; i < میٹرکس.meta / (ناپ_t)4U + (ناپ_t)1U; i++)
  {
    ناپ_t شروع_اشاریہ = i;
    ناپ_t شروع_index0 = شروع_اشاریہ * (ناپ_t)4U;
    إذا (شروع_index0 >= میٹرکس.meta)
    {
      اكسر;
    }
    ناپ_t elements_requested;
    إذا (شروع_index0 + (ناپ_t)4U <= میٹرکس.meta)
    {
      elements_requested = (ناپ_t)4U;
    }
    وإلا
    {
      elements_requested = میٹرکس.meta - شروع_index0;
    }
    libcrux_ml_dsa_sample_sample_اتے_منزل_four_ring_elements_flat_63(columns,
      بیج,
      میٹرکس,
      &rand_stack0,
      &rand_stack1,
      &rand_stack2,
      &rand_stack3,
      Eurydice_array_منزل_ٹکڑا_mut_7e(&tmp_ڈھیر),
      شروع_index0,
      elements_requested);
  }
}

/**
This function found in impl {libcrux_ml_dsa::samplex4::X4Sampler for libcrux_ml_dsa::samplex4::portable::PortableSampler}
*/
/**
A monomorphic instance of libcrux_ml_dsa.samplex4.portable.matrix_flat_a8
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ساكن مضمن فراغ
libcrux_ml_dsa_samplex4_portable_میٹرکس_flat_a8_37(
  ناپ_t columns,
  Eurydice_borrow_ٹکڑا_u8 بیج,
  Eurydice_dst_ref_mut_44 میٹرکس
)
{
  libcrux_ml_dsa_samplex4_میٹرکس_flat_63(columns, بیج, میٹرکس);
}

/**
A monomorphic instance of libcrux_ml_dsa.hash_functions.portable.shake256
with const generics
- OUTPUT_LENGTH= 64
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_hash_functions_portable_shake256_c9(
  Eurydice_borrow_ٹکڑا_u8 داخلہ,
  Eurydice_arr_c7 *باہرلا
)
{
  libcrux_sha3_portable_shake256(Eurydice_array_منزل_ٹکڑا_mut_17(باہرلا), داخلہ);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::DsaXof for libcrux_ml_dsa::hash_functions::portable::Shake256}
*/
/**
A monomorphic instance of libcrux_ml_dsa.hash_functions.portable.shake256_61
with const generics
- OUTPUT_LENGTH= 64
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_hash_functions_portable_shake256_61_c9(
  Eurydice_borrow_ٹکڑا_u8 داخلہ,
  Eurydice_arr_c7 *باہرلا
)
{
  libcrux_ml_dsa_hash_functions_portable_shake256_c9(داخلہ, باہرلا);
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.signing_key.generate_serialized
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_hash_functions_portable_Shake256
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_encoding_signing_کلید_generate_serialized_2e(
  libcrux_ml_dsa_constants_Eta eta,
  ناپ_t error_ring_element_ناپ,
  Eurydice_borrow_ٹکڑا_u8 بیج_میٹرکس,
  Eurydice_borrow_ٹکڑا_u8 بیج_signing,
  Eurydice_borrow_ٹکڑا_u8 verification_کلید,
  Eurydice_dst_ref_shared_44 s1_2,
  Eurydice_dst_ref_shared_44 t0,
  Eurydice_mut_borrow_ٹکڑا_u8 signing_کلید_serialized
)
{
  ناپ_t وتھ = (ناپ_t)0U;
  Eurydice_ٹکڑا_copy(Eurydice_ٹکڑا_subslice_mut_c8(signing_کلید_serialized,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .شروع = وتھ,
          .سرا = وتھ + LIBCRUX_ML_DSA_CONSTANTS_بیج_FOR_A_ناپ
        }
      )),
    بیج_میٹرکس,
    uint8_t);
  وتھ += LIBCRUX_ML_DSA_CONSTANTS_بیج_FOR_A_ناپ;
  Eurydice_ٹکڑا_copy(Eurydice_ٹکڑا_subslice_mut_c8(signing_کلید_serialized,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .شروع = وتھ,
          .سرا = وتھ + LIBCRUX_ML_DSA_CONSTANTS_بیج_FOR_SIGNING_ناپ
        }
      )),
    بیج_signing,
    uint8_t);
  وتھ += LIBCRUX_ML_DSA_CONSTANTS_بیج_FOR_SIGNING_ناپ;
  Eurydice_arr_c7 verification_کلید_hash = { .انکڑے = { 0U } };
  libcrux_ml_dsa_hash_functions_portable_shake256_61_c9(verification_کلید,
    &verification_کلید_hash);
  Eurydice_ٹکڑا_copy(Eurydice_ٹکڑا_subslice_mut_c8(signing_کلید_serialized,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .شروع = وتھ,
          .سرا = وتھ + LIBCRUX_ML_DSA_CONSTANTS_بائٹاں_FOR_VERIFICATION_کلید_HASH
        }
      )),
    Eurydice_array_منزل_ٹکڑا_shared_17(&verification_کلید_hash),
    uint8_t);
  وتھ += LIBCRUX_ML_DSA_CONSTANTS_بائٹاں_FOR_VERIFICATION_کلید_HASH;
  لكل (ناپ_t i = (ناپ_t)0U; i < s1_2.meta; i++)
  {
    ناپ_t i0 = i;
    libcrux_ml_dsa_encoding_error_serialize_37(eta,
      &s1_2.ptr[i0],
      Eurydice_ٹکڑا_subslice_mut_c8(signing_کلید_serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .شروع = وتھ,
            .سرا = وتھ + error_ring_element_ناپ
          }
        )));
    وتھ += error_ring_element_ناپ;
  }
  لكل (ناپ_t i = (ناپ_t)0U; i < t0.meta; i++)
  {
    ناپ_t _cloop_j = i;
    ثابت Eurydice_arr_a3 *ring_element = &t0.ptr[_cloop_j];
    libcrux_ml_dsa_encoding_t0_serialize_37(ring_element,
      Eurydice_ٹکڑا_subslice_mut_c8(signing_کلید_serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .شروع = وتھ,
            .سرا = وتھ + LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_دا_T0_S_ناپ
          }
        )));
    وتھ += LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_دا_T0_S_ناپ;
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_44.generate_key_pair
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_generate_کلید_pair_5a(
  Eurydice_arr_ec randomness,
  Eurydice_mut_borrow_ٹکڑا_u8 signing_کلید,
  Eurydice_mut_borrow_ٹکڑا_u8 verification_کلید
)
{
  Eurydice_arr_89 بیج_expanded0 = { .انکڑے = { 0U } };
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
  shake = libcrux_ml_dsa_hash_functions_portable_init_26();
  libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake,
    Eurydice_array_منزل_ٹکڑا_shared_01(&randomness));
  /* original Rust expression is not an lvalue in C */
  Eurydice_array_u8x2
  lvalue =
    {
      .انکڑے = {
        (uint8_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_صفاں_وچ_A,
        (uint8_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_وچ_A
      }
    };
  libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake,
    Eurydice_array_منزل_ٹکڑا_shared_82(&lvalue));
  libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake,
    Eurydice_array_منزل_ٹکڑا_mut_78(&بیج_expanded0));
  Eurydice_borrow_ٹکڑا_u8_x2
  uu____0 =
    Eurydice_ٹکڑا_ونڈو_at(Eurydice_array_منزل_ٹکڑا_shared_78(&بیج_expanded0),
      LIBCRUX_ML_DSA_CONSTANTS_بیج_FOR_A_ناپ,
      uint8_t,
      Eurydice_borrow_ٹکڑا_u8_x2);
  Eurydice_borrow_ٹکڑا_u8 بیج_for_a = uu____0.fst;
  Eurydice_borrow_ٹکڑا_u8 بیج_expanded = uu____0.snd;
  Eurydice_borrow_ٹکڑا_u8_x2
  uu____1 =
    Eurydice_ٹکڑا_ونڈو_at(بیج_expanded,
      LIBCRUX_ML_DSA_CONSTANTS_بیج_FOR_ERROR_VECTORS_ناپ,
      uint8_t,
      Eurydice_borrow_ٹکڑا_u8_x2);
  Eurydice_borrow_ٹکڑا_u8 بیج_for_error_vectors = uu____1.fst;
  Eurydice_borrow_ٹکڑا_u8 بیج_for_signing = uu____1.snd;
  Eurydice_arr_8f s1_s2;
  Eurydice_arr_a3 repeat_expression0[8U];
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)8U; i++)
  {
    repeat_expression0[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  حافظہ_نقل(s1_s2.انکڑے, repeat_expression0, (ناپ_t)8U * حجم (Eurydice_arr_a3));
  libcrux_ml_dsa_samplex4_sample_s1_and_s2_29(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ETA,
    بیج_for_error_vectors,
    Eurydice_array_منزل_ٹکڑا_mut_20(&s1_s2));
  Eurydice_arr_9d t0;
  Eurydice_arr_a3 repeat_expression1[4U];
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)4U; i++)
  {
    repeat_expression1[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  حافظہ_نقل(t0.انکڑے, repeat_expression1, (ناپ_t)4U * حجم (Eurydice_arr_a3));
  Eurydice_arr_2f a_as_ntt;
  Eurydice_arr_a3 repeat_expression2[16U];
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)16U; i++)
  {
    repeat_expression2[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  حافظہ_نقل(a_as_ntt.انکڑے, repeat_expression2, (ناپ_t)16U * حجم (Eurydice_arr_a3));
  libcrux_ml_dsa_samplex4_portable_میٹرکس_flat_a8_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_وچ_A,
    بیج_for_a,
    Eurydice_array_منزل_ٹکڑا_mut_200(&a_as_ntt));
  Eurydice_arr_9d s1_ntt;
  Eurydice_arr_a3 repeat_expression3[4U];
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)4U; i++)
  {
    repeat_expression3[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  حافظہ_نقل(s1_ntt.انکڑے, repeat_expression3, (ناپ_t)4U * حجم (Eurydice_arr_a3));
  Eurydice_ٹکڑا_copy(Eurydice_array_منزل_ٹکڑا_mut_201(&s1_ntt),
    Eurydice_array_منزل_subslice_shared_25(&s1_s2,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .شروع = (ناپ_t)0U,
          .سرا = LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_وچ_A
        }
      )),
    Eurydice_arr_a3);
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)4U; i++)
  {
    ناپ_t i0 = i;
    libcrux_ml_dsa_ntt_ntt_37(&s1_ntt.انکڑے[i0]);
  }
  libcrux_ml_dsa_میٹرکس_compute_as1_plus_s2_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_صفاں_وچ_A,
    LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_وچ_A,
    Eurydice_array_منزل_ٹکڑا_mut_200(&a_as_ntt),
    Eurydice_array_منزل_ٹکڑا_shared_20(&s1_ntt),
    Eurydice_array_منزل_ٹکڑا_shared_200(&s1_s2),
    Eurydice_array_منزل_ٹکڑا_mut_201(&t0));
  Eurydice_arr_9d t1;
  Eurydice_arr_a3 repeat_عبارت[4U];
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)4U; i++)
  {
    repeat_عبارت[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  حافظہ_نقل(t1.انکڑے, repeat_عبارت, (ناپ_t)4U * حجم (Eurydice_arr_a3));
  libcrux_ml_dsa_arithmetic_power2round_سمتیہ_37(Eurydice_array_منزل_ٹکڑا_mut_201(&t0),
    Eurydice_array_منزل_ٹکڑا_mut_201(&t1));
  libcrux_ml_dsa_encoding_verification_کلید_generate_serialized_37(بیج_for_a,
    Eurydice_array_منزل_ٹکڑا_shared_20(&t1),
    verification_کلید);
  libcrux_ml_dsa_encoding_signing_کلید_generate_serialized_2e(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ETA,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_ERROR_RING_ELEMENT_ناپ,
    بیج_for_a,
    بیج_for_signing,
    (
      KRML_CLITERAL(Eurydice_borrow_ٹکڑا_u8){
        .ptr = verification_کلید.ptr,
        .meta = verification_کلید.meta
      }
    ),
    Eurydice_array_منزل_ٹکڑا_shared_200(&s1_s2),
    Eurydice_array_منزل_ٹکڑا_shared_20(&t0),
    signing_کلید);
}

/**
 Generate key pair.
*/
ساكن مضمن فراغ
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_44_generate_کلید_pair(
  Eurydice_arr_ec randomness,
  Eurydice_arr_10 *signing_کلید,
  Eurydice_arr_02 *verification_کلید
)
{
  libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_generate_کلید_pair_5a(randomness,
    Eurydice_array_منزل_ٹکڑا_mut_34(signing_کلید),
    Eurydice_array_منزل_ٹکڑا_mut_9f0(verification_کلید));
}

/**
 This corresponds to line 6 in algorithm 7 in FIPS 204 (line 7 in algorithm
 8, resp.).

 If `domain_separation_context` is supplied, applies domain
 separation and length encoding to the context string,
 before appending the message (in the regular variant) or the
 pre-hash OID as well as the pre-hashed message digest. Otherwise,
 it is assumed that `message` already contains domain separation
 information.

 In FIPS 204 M' is the concatenation of the domain separated context, any
 potential pre-hash OID and the message (or the message pre-hash). We do not
 explicitely construct the concatenation in memory since it is of statically unknown
 length, but feed its components directly into the incremental XOF.

 Refer to line 10 of Algorithm 2 (and line 5 of Algorithm 3, resp.) in [FIPS
 204](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf#section.5)
 for details on the domain separation for regular ML-DSA. Line
 23 of Algorithm 4 (and line 18 of Algorithm 5,resp.) describe domain separation for the HashMl-DSA
 variant.
*/
/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.derive_message_representative
with types libcrux_ml_dsa_hash_functions_portable_Shake256Xof
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_ml_dsa_generic_derive_سنیہا_representative_43(
  Eurydice_borrow_ٹکڑا_u8 verification_کلید_hash,
  ثابت core_option_Option_84 *domain_separation_context,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_arr_c7 *سنیہا_representative
)
{
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
  shake = libcrux_ml_dsa_hash_functions_portable_init_26();
  libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake, verification_کلید_hash);
  إذا (domain_separation_context->ٹیگ == core_option_Some)
  {
    ثابت
    libcrux_ml_dsa_pre_hash_DomainSeparationContext
    *domain_separation_context0 = &domain_separation_context->f0;
    libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *uu____0 = &shake;
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_82
    lvalue0 =
      {
        .انکڑے = {
          (uint8_t)core_option__core__option__Option_T__TraitClause_0___is_some(libcrux_ml_dsa_pre_hash_pre_hash_oid_88(domain_separation_context0),
            Eurydice_arr_c9,
            bool)
        }
      };
    libcrux_ml_dsa_hash_functions_portable_absorb_26(uu____0,
      Eurydice_array_منزل_ٹکڑا_shared_79(&lvalue0));
    libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *uu____1 = &shake;
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_82
    lvalue =
      { .انکڑے = { (uint8_t)libcrux_ml_dsa_pre_hash_context_88(domain_separation_context0).meta } };
    libcrux_ml_dsa_hash_functions_portable_absorb_26(uu____1,
      Eurydice_array_منزل_ٹکڑا_shared_79(&lvalue));
    libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake,
      libcrux_ml_dsa_pre_hash_context_88(domain_separation_context0));
    ثابت
    core_option_Option_57
    *uu____2 = libcrux_ml_dsa_pre_hash_pre_hash_oid_88(domain_separation_context0);
    إذا (uu____2->ٹیگ == core_option_Some)
    {
      ثابت Eurydice_arr_c9 *pre_hash_oid = &uu____2->f0;
      libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake,
        Eurydice_array_منزل_ٹکڑا_shared_2f(pre_hash_oid));
    }
  }
  libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake, سنیہا);
  libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake,
    Eurydice_array_منزل_ٹکڑا_mut_17(سنیہا_representative));
}

/**
A monomorphic instance of libcrux_ml_dsa.hash_functions.portable.shake256
with const generics
- OUTPUT_LENGTH= 576
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_hash_functions_portable_shake256_5a(
  Eurydice_borrow_ٹکڑا_u8 داخلہ,
  Eurydice_arr_220 *باہرلا
)
{
  libcrux_sha3_portable_shake256(Eurydice_array_منزل_ٹکڑا_mut_8a(باہرلا), داخلہ);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::XofX4 for libcrux_ml_dsa::hash_functions::portable::Shake256X4}
*/
/**
A monomorphic instance of libcrux_ml_dsa.hash_functions.portable.shake256_x4_9b
with const generics
- OUT_LEN= 576
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_hash_functions_portable_shake256_x4_9b_5a(
  Eurydice_borrow_ٹکڑا_u8 input0,
  Eurydice_borrow_ٹکڑا_u8 input1,
  Eurydice_borrow_ٹکڑا_u8 input2,
  Eurydice_borrow_ٹکڑا_u8 input3,
  Eurydice_arr_220 *out0,
  Eurydice_arr_220 *out1,
  Eurydice_arr_220 *out2,
  Eurydice_arr_220 *out3
)
{
  libcrux_ml_dsa_hash_functions_portable_shake256_5a(input0, out0);
  libcrux_ml_dsa_hash_functions_portable_shake256_5a(input1, out1);
  libcrux_ml_dsa_hash_functions_portable_shake256_5a(input2, out2);
  libcrux_ml_dsa_hash_functions_portable_shake256_5a(input3, out3);
}

/**
A monomorphic instance of libcrux_ml_dsa.hash_functions.portable.shake256
with const generics
- OUTPUT_LENGTH= 640
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_hash_functions_portable_shake256_0e(
  Eurydice_borrow_ٹکڑا_u8 داخلہ,
  Eurydice_arr_20 *باہرلا
)
{
  libcrux_sha3_portable_shake256(Eurydice_array_منزل_ٹکڑا_mut_4f(باہرلا), داخلہ);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::XofX4 for libcrux_ml_dsa::hash_functions::portable::Shake256X4}
*/
/**
A monomorphic instance of libcrux_ml_dsa.hash_functions.portable.shake256_x4_9b
with const generics
- OUT_LEN= 640
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_hash_functions_portable_shake256_x4_9b_0e(
  Eurydice_borrow_ٹکڑا_u8 input0,
  Eurydice_borrow_ٹکڑا_u8 input1,
  Eurydice_borrow_ٹکڑا_u8 input2,
  Eurydice_borrow_ٹکڑا_u8 input3,
  Eurydice_arr_20 *out0,
  Eurydice_arr_20 *out1,
  Eurydice_arr_20 *out2,
  Eurydice_arr_20 *out3
)
{
  libcrux_ml_dsa_hash_functions_portable_shake256_0e(input0, out0);
  libcrux_ml_dsa_hash_functions_portable_shake256_0e(input1, out1);
  libcrux_ml_dsa_hash_functions_portable_shake256_0e(input2, out2);
  libcrux_ml_dsa_hash_functions_portable_shake256_0e(input3, out3);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::DsaXof for libcrux_ml_dsa::hash_functions::portable::Shake256}
*/
/**
A monomorphic instance of libcrux_ml_dsa.hash_functions.portable.shake256_61
with const generics
- OUTPUT_LENGTH= 640
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_hash_functions_portable_shake256_61_0e(
  Eurydice_borrow_ٹکڑا_u8 داخلہ,
  Eurydice_arr_20 *باہرلا
)
{
  libcrux_ml_dsa_hash_functions_portable_shake256_0e(داخلہ, باہرلا);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::DsaXof for libcrux_ml_dsa::hash_functions::portable::Shake256}
*/
/**
A monomorphic instance of libcrux_ml_dsa.hash_functions.portable.shake256_61
with const generics
- OUTPUT_LENGTH= 576
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_hash_functions_portable_shake256_61_5a(
  Eurydice_borrow_ٹکڑا_u8 داخلہ,
  Eurydice_arr_220 *باہرلا
)
{
  libcrux_ml_dsa_hash_functions_portable_shake256_5a(داخلہ, باہرلا);
}

/**
A monomorphic instance of libcrux_ml_dsa.sample.sample_mask_ring_element
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_hash_functions_portable_Shake256
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_sample_sample_نقاب_ring_element_2e(
  ثابت Eurydice_arr_91 *بیج,
  Eurydice_arr_a3 *نتیجہ,
  ناپ_t gamma1_exponent
)
{
  بدل (gamma1_exponent)
  {
    حالة 17U:
      {
        اكسر;
      }
    حالة 19U:
      {
        Eurydice_arr_20 باہرلا = { .انکڑے = { 0U } };
        libcrux_ml_dsa_hash_functions_portable_shake256_61_0e(Eurydice_array_منزل_ٹکڑا_shared_f1(بیج),
          &باہرلا);
        libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
          Eurydice_array_منزل_ٹکڑا_shared_4f(&باہرلا),
          نتیجہ);
        أرجع;
      }
    افتراضي:
      {
        KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __FILE__, __LINE__, "panic!");
        KRML_HOST_EXIT(255U);
      }
  }
  Eurydice_arr_220 باہرلا = { .انکڑے = { 0U } };
  libcrux_ml_dsa_hash_functions_portable_shake256_61_5a(Eurydice_array_منزل_ٹکڑا_shared_f1(بیج),
    &باہرلا);
  libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
    Eurydice_array_منزل_ٹکڑا_shared_8a(&باہرلا),
    نتیجہ);
}

/**
A monomorphic instance of libcrux_ml_dsa.sample.sample_mask_vector
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_sample_sample_نقاب_سمتیہ_67(
  ناپ_t dimension,
  ناپ_t gamma1_exponent,
  ثابت Eurydice_arr_c7 *بیج,
  uint16_t *domain_separator,
  Eurydice_dst_ref_mut_44 نقاب
)
{
  Eurydice_arr_91
  seed0 =
    libcrux_ml_dsa_sample_جوڑو_error_domain_separator(Eurydice_array_منزل_ٹکڑا_shared_17(بیج),
      domain_separator[0U]);
  Eurydice_arr_91
  seed1 =
    libcrux_ml_dsa_sample_جوڑو_error_domain_separator(Eurydice_array_منزل_ٹکڑا_shared_17(بیج),
      (uint32_t)domain_separator[0U] + 1U);
  Eurydice_arr_91
  seed2 =
    libcrux_ml_dsa_sample_جوڑو_error_domain_separator(Eurydice_array_منزل_ٹکڑا_shared_17(بیج),
      (uint32_t)domain_separator[0U] + 2U);
  Eurydice_arr_91
  seed3 =
    libcrux_ml_dsa_sample_جوڑو_error_domain_separator(Eurydice_array_منزل_ٹکڑا_shared_17(بیج),
      (uint32_t)domain_separator[0U] + 3U);
  domain_separator[0U] = (uint32_t)domain_separator[0U] + 4U;
  بدل (gamma1_exponent)
  {
    حالة 17U:
      {
        Eurydice_arr_220 out0 = { .انکڑے = { 0U } };
        Eurydice_arr_220 out1 = { .انکڑے = { 0U } };
        Eurydice_arr_220 out2 = { .انکڑے = { 0U } };
        Eurydice_arr_220 out3 = { .انکڑے = { 0U } };
        libcrux_ml_dsa_hash_functions_portable_shake256_x4_9b_5a(Eurydice_array_منزل_ٹکڑا_shared_f1(&seed0),
          Eurydice_array_منزل_ٹکڑا_shared_f1(&seed1),
          Eurydice_array_منزل_ٹکڑا_shared_f1(&seed2),
          Eurydice_array_منزل_ٹکڑا_shared_f1(&seed3),
          &out0,
          &out1,
          &out2,
          &out3);
        libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
          Eurydice_array_منزل_ٹکڑا_shared_8a(&out0),
          نقاب.ptr);
        libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
          Eurydice_array_منزل_ٹکڑا_shared_8a(&out1),
          &نقاب.ptr[1U]);
        libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
          Eurydice_array_منزل_ٹکڑا_shared_8a(&out2),
          &نقاب.ptr[2U]);
        libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
          Eurydice_array_منزل_ٹکڑا_shared_8a(&out3),
          &نقاب.ptr[3U]);
        اكسر;
      }
    حالة 19U:
      {
        Eurydice_arr_20 out0 = { .انکڑے = { 0U } };
        Eurydice_arr_20 out1 = { .انکڑے = { 0U } };
        Eurydice_arr_20 out2 = { .انکڑے = { 0U } };
        Eurydice_arr_20 out3 = { .انکڑے = { 0U } };
        libcrux_ml_dsa_hash_functions_portable_shake256_x4_9b_0e(Eurydice_array_منزل_ٹکڑا_shared_f1(&seed0),
          Eurydice_array_منزل_ٹکڑا_shared_f1(&seed1),
          Eurydice_array_منزل_ٹکڑا_shared_f1(&seed2),
          Eurydice_array_منزل_ٹکڑا_shared_f1(&seed3),
          &out0,
          &out1,
          &out2,
          &out3);
        libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
          Eurydice_array_منزل_ٹکڑا_shared_4f(&out0),
          نقاب.ptr);
        libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
          Eurydice_array_منزل_ٹکڑا_shared_4f(&out1),
          &نقاب.ptr[1U]);
        libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
          Eurydice_array_منزل_ٹکڑا_shared_4f(&out2),
          &نقاب.ptr[2U]);
        libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
          Eurydice_array_منزل_ٹکڑا_shared_4f(&out3),
          &نقاب.ptr[3U]);
        اكسر;
      }
    افتراضي:
      {
        KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __FILE__, __LINE__, "panic!");
        KRML_HOST_EXIT(255U);
      }
  }
  لكل (ناپ_t i = (ناپ_t)4U; i < dimension; i++)
  {
    ناپ_t i0 = i;
    Eurydice_arr_91
    seed4 =
      libcrux_ml_dsa_sample_جوڑو_error_domain_separator(Eurydice_array_منزل_ٹکڑا_shared_17(بیج),
        domain_separator[0U]);
    domain_separator[0U] = (uint32_t)domain_separator[0U] + 1U;
    libcrux_ml_dsa_sample_sample_نقاب_ring_element_2e(&seed4, &نقاب.ptr[i0], gamma1_exponent);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.sample.sample_challenge_ring_element
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_hash_functions_portable_Shake256
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_sample_sample_challenge_ring_element_2e(
  Eurydice_borrow_ٹکڑا_u8 بیج,
  ناپ_t نمبر_دا_ones,
  Eurydice_arr_a3 *re
)
{
  Eurydice_arr_7c state = libcrux_ml_dsa_hash_functions_portable_init_absorb_final_61(بیج);
  Eurydice_arr_ff
  randomness0 = libcrux_ml_dsa_hash_functions_portable_squeeze_پہلا_بلاک_61(&state);
  Eurydice_array_u8x8 arr;
  حافظہ_نقل(arr.انکڑے,
    Eurydice_array_منزل_subslice_shared_d40(&randomness0,
      (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = (ناپ_t)0U, .سرا = (ناپ_t)8U })).ptr,
    (ناپ_t)8U * حجم (uint8_t));
  uint64_t
  signs =
    core_عدد_u64_from_le_بائٹاں(core_نتیجہ_unwrap_26_e0((
          KRML_CLITERAL(core_نتیجہ_نتیجہ_8e){ .ٹیگ = core_نتیجہ_Ok, .val = { .case_Ok = arr } }
        )));
  Eurydice_arr_6c نتیجہ = { .انکڑے = { 0U } };
  ناپ_t باہرلا_اشاریہ = (ناپ_t)256U - نمبر_دا_ones;
  bool
  پورا =
    libcrux_ml_dsa_sample_inside_باہرلا_shuffle(Eurydice_array_منزل_subslice_from_shared_5f(&randomness0,
        (ناپ_t)8U),
      &باہرلا_اشاریہ,
      &signs,
      &نتیجہ);
  طالما (true)
  {
    إذا (پورا)
    {
      اكسر;
    }
    وإلا
    {
      Eurydice_arr_ff
      randomness = libcrux_ml_dsa_hash_functions_portable_squeeze_اگلا_بلاک_61(&state);
      پورا =
        libcrux_ml_dsa_sample_inside_باہرلا_shuffle(Eurydice_array_منزل_ٹکڑا_shared_58(&randomness),
          &باہرلا_اشاریہ,
          &signs,
          &نتیجہ);
    }
  }
  libcrux_ml_dsa_polynomial_from_i32_array_ff_37(Eurydice_array_منزل_ٹکڑا_shared_af(&نتیجہ), re);
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_44.sign_internal
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
ساكن KRML_MUSTINLINE core_نتیجہ_نتیجہ_53
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_sign_اندرونی_5a(
  Eurydice_borrow_ٹکڑا_u8 signing_کلید,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  core_option_Option_84 domain_separation_context,
  Eurydice_arr_ec randomness,
  Eurydice_arr_85 *signature
)
{
  Eurydice_borrow_ٹکڑا_u8_x2
  uu____0 =
    Eurydice_ٹکڑا_ونڈو_at(signing_کلید,
      LIBCRUX_ML_DSA_CONSTANTS_بیج_FOR_A_ناپ,
      uint8_t,
      Eurydice_borrow_ٹکڑا_u8_x2);
  Eurydice_borrow_ٹکڑا_u8 بیج_for_a = uu____0.fst;
  Eurydice_borrow_ٹکڑا_u8 بچیا_serialized0 = uu____0.snd;
  Eurydice_borrow_ٹکڑا_u8_x2
  uu____1 =
    Eurydice_ٹکڑا_ونڈو_at(بچیا_serialized0,
      LIBCRUX_ML_DSA_CONSTANTS_بیج_FOR_SIGNING_ناپ,
      uint8_t,
      Eurydice_borrow_ٹکڑا_u8_x2);
  Eurydice_borrow_ٹکڑا_u8 بیج_for_signing = uu____1.fst;
  Eurydice_borrow_ٹکڑا_u8 بچیا_serialized1 = uu____1.snd;
  Eurydice_borrow_ٹکڑا_u8_x2
  uu____2 =
    Eurydice_ٹکڑا_ونڈو_at(بچیا_serialized1,
      LIBCRUX_ML_DSA_CONSTANTS_بائٹاں_FOR_VERIFICATION_کلید_HASH,
      uint8_t,
      Eurydice_borrow_ٹکڑا_u8_x2);
  Eurydice_borrow_ٹکڑا_u8 verification_کلید_hash = uu____2.fst;
  Eurydice_borrow_ٹکڑا_u8 بچیا_serialized2 = uu____2.snd;
  Eurydice_borrow_ٹکڑا_u8_x2
  uu____3 =
    Eurydice_ٹکڑا_ونڈو_at(بچیا_serialized2,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_ERROR_RING_ELEMENT_ناپ *
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_وچ_A,
      uint8_t,
      Eurydice_borrow_ٹکڑا_u8_x2);
  Eurydice_borrow_ٹکڑا_u8 s1_serialized = uu____3.fst;
  Eurydice_borrow_ٹکڑا_u8 بچیا_serialized = uu____3.snd;
  Eurydice_borrow_ٹکڑا_u8_x2
  uu____4 =
    Eurydice_ٹکڑا_ونڈو_at(بچیا_serialized,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_ERROR_RING_ELEMENT_ناپ *
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_صفاں_وچ_A,
      uint8_t,
      Eurydice_borrow_ٹکڑا_u8_x2);
  Eurydice_borrow_ٹکڑا_u8 s2_serialized = uu____4.fst;
  Eurydice_borrow_ٹکڑا_u8 t0_serialized = uu____4.snd;
  Eurydice_arr_9d s1_as_ntt;
  Eurydice_arr_a3 repeat_expression0[4U];
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)4U; i++)
  {
    repeat_expression0[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  حافظہ_نقل(s1_as_ntt.انکڑے, repeat_expression0, (ناپ_t)4U * حجم (Eurydice_arr_a3));
  Eurydice_arr_9d s2_as_ntt;
  Eurydice_arr_a3 repeat_expression1[4U];
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)4U; i++)
  {
    repeat_expression1[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  حافظہ_نقل(s2_as_ntt.انکڑے, repeat_expression1, (ناپ_t)4U * حجم (Eurydice_arr_a3));
  Eurydice_arr_9d t0_as_ntt;
  Eurydice_arr_a3 repeat_expression2[4U];
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)4U; i++)
  {
    repeat_expression2[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  حافظہ_نقل(t0_as_ntt.انکڑے, repeat_expression2, (ناپ_t)4U * حجم (Eurydice_arr_a3));
  libcrux_ml_dsa_encoding_error_deserialize_منزل_سمتیہ_then_ntt_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ETA,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_ERROR_RING_ELEMENT_ناپ,
    s1_serialized,
    Eurydice_array_منزل_ٹکڑا_mut_201(&s1_as_ntt));
  libcrux_ml_dsa_encoding_error_deserialize_منزل_سمتیہ_then_ntt_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ETA,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_ERROR_RING_ELEMENT_ناپ,
    s2_serialized,
    Eurydice_array_منزل_ٹکڑا_mut_201(&s2_as_ntt));
  libcrux_ml_dsa_encoding_t0_deserialize_منزل_سمتیہ_then_ntt_37(t0_serialized,
    Eurydice_array_منزل_ٹکڑا_mut_201(&t0_as_ntt));
  Eurydice_arr_2f میٹرکس;
  Eurydice_arr_a3 repeat_expression3[16U];
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)16U; i++)
  {
    repeat_expression3[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  حافظہ_نقل(میٹرکس.انکڑے, repeat_expression3, (ناپ_t)16U * حجم (Eurydice_arr_a3));
  libcrux_ml_dsa_samplex4_portable_میٹرکس_flat_a8_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_وچ_A,
    بیج_for_a,
    Eurydice_array_منزل_ٹکڑا_mut_200(&میٹرکس));
  Eurydice_arr_c7 سنیہا_representative = { .انکڑے = { 0U } };
  libcrux_ml_dsa_ml_dsa_generic_derive_سنیہا_representative_43(verification_کلید_hash,
    &domain_separation_context,
    سنیہا,
    &سنیہا_representative);
  Eurydice_arr_c7 نقاب_بیج = { .انکڑے = { 0U } };
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
  shake0 = libcrux_ml_dsa_hash_functions_portable_init_26();
  libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake0, بیج_for_signing);
  libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake0,
    Eurydice_array_منزل_ٹکڑا_shared_01(&randomness));
  libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake0,
    Eurydice_array_منزل_ٹکڑا_shared_17(&سنیہا_representative));
  libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake0,
    Eurydice_array_منزل_ٹکڑا_mut_17(&نقاب_بیج));
  uint16_t domain_separator_for_نقاب = 0U;
  ناپ_t attempt = (ناپ_t)0U;
  core_option_Option_14 commitment_hash0 = { .ٹیگ = core_option_None };
  core_option_Option_d9 signer_response0 = { .ٹیگ = core_option_None };
  core_option_Option_51 hint0 = { .ٹیگ = core_option_None };
  طالما (attempt < LIBCRUX_ML_DSA_CONSTANTS_REJECTION_SAMPLE_BOUND_SIGN)
  {
    attempt++;
    Eurydice_arr_9d نقاب;
    Eurydice_arr_a3 repeat_expression4[4U];
    لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)4U; i++)
    {
      repeat_expression4[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    حافظہ_نقل(نقاب.انکڑے, repeat_expression4, (ناپ_t)4U * حجم (Eurydice_arr_a3));
    Eurydice_arr_9d w0;
    Eurydice_arr_a3 repeat_expression5[4U];
    لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)4U; i++)
    {
      repeat_expression5[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    حافظہ_نقل(w0.انکڑے, repeat_expression5, (ناپ_t)4U * حجم (Eurydice_arr_a3));
    Eurydice_arr_9d commitment;
    Eurydice_arr_a3 repeat_expression6[4U];
    لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)4U; i++)
    {
      repeat_expression6[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    حافظہ_نقل(commitment.انکڑے, repeat_expression6, (ناپ_t)4U * حجم (Eurydice_arr_a3));
    libcrux_ml_dsa_sample_sample_نقاب_سمتیہ_67(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_وچ_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_GAMMA1_EXPONENT,
      &نقاب_بیج,
      &domain_separator_for_نقاب,
      Eurydice_array_منزل_ٹکڑا_mut_201(&نقاب));
    Eurydice_arr_9d a_x_نقاب;
    Eurydice_arr_a3 repeat_عبارت[4U];
    لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)4U; i++)
    {
      repeat_عبارت[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    حافظہ_نقل(a_x_نقاب.انکڑے, repeat_عبارت, (ناپ_t)4U * حجم (Eurydice_arr_a3));
    Eurydice_arr_9d
    نقاب_ntt =
      core_array__core__clone__Clone_for__T__N___clone((ناپ_t)4U,
        &نقاب,
        Eurydice_arr_a3,
        Eurydice_arr_9d);
    لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)4U; i++)
    {
      ناپ_t i0 = i;
      libcrux_ml_dsa_ntt_ntt_37(&نقاب_ntt.انکڑے[i0]);
    }
    libcrux_ml_dsa_میٹرکس_compute_میٹرکس_x_نقاب_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_صفاں_وچ_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_وچ_A,
      Eurydice_array_منزل_ٹکڑا_shared_201(&میٹرکس),
      Eurydice_array_منزل_ٹکڑا_shared_20(&نقاب_ntt),
      Eurydice_array_منزل_ٹکڑا_mut_201(&a_x_نقاب));
    libcrux_ml_dsa_arithmetic_decompose_سمتیہ_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_صفاں_وچ_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_GAMMA2,
      Eurydice_array_منزل_ٹکڑا_shared_20(&a_x_نقاب),
      Eurydice_array_منزل_ٹکڑا_mut_201(&w0),
      Eurydice_array_منزل_ٹکڑا_mut_201(&commitment));
    Eurydice_arr_ec commitment_hash_candidate = { .انکڑے = { 0U } };
    Eurydice_arr_d2 commitment_serialized = { .انکڑے = { 0U } };
    libcrux_ml_dsa_encoding_commitment_serialize_سمتیہ_37(LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_COMMITMENT_RING_ELEMENT_ناپ,
      Eurydice_array_منزل_ٹکڑا_shared_20(&commitment),
      Eurydice_array_منزل_ٹکڑا_mut_27(&commitment_serialized));
    libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
    shake = libcrux_ml_dsa_hash_functions_portable_init_26();
    libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake,
      Eurydice_array_منزل_ٹکڑا_shared_17(&سنیہا_representative));
    libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake,
      Eurydice_array_منزل_ٹکڑا_shared_27(&commitment_serialized));
    libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake,
      Eurydice_array_منزل_ٹکڑا_mut_01(&commitment_hash_candidate));
    Eurydice_arr_a3 verifier_challenge = libcrux_ml_dsa_polynomial_zero_ff_37();
    libcrux_ml_dsa_sample_sample_challenge_ring_element_2e(Eurydice_array_منزل_ٹکڑا_shared_01(&commitment_hash_candidate),
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ONES_وچ_VERIFIER_CHALLENGE,
      &verifier_challenge);
    libcrux_ml_dsa_ntt_ntt_37(&verifier_challenge);
    Eurydice_arr_9d
    challenge_times_s1 =
      core_array__core__clone__Clone_for__T__N___clone((ناپ_t)4U,
        &s1_as_ntt,
        Eurydice_arr_a3,
        Eurydice_arr_9d);
    Eurydice_arr_9d
    challenge_times_s2 =
      core_array__core__clone__Clone_for__T__N___clone((ناپ_t)4U,
        &s2_as_ntt,
        Eurydice_arr_a3,
        Eurydice_arr_9d);
    libcrux_ml_dsa_میٹرکس_سمتیہ_times_ring_element_37(Eurydice_array_منزل_ٹکڑا_mut_201(&challenge_times_s1),
      &verifier_challenge);
    libcrux_ml_dsa_میٹرکس_سمتیہ_times_ring_element_37(Eurydice_array_منزل_ٹکڑا_mut_201(&challenge_times_s2),
      &verifier_challenge);
    libcrux_ml_dsa_میٹرکس_جوڑو_vectors_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_وچ_A,
      Eurydice_array_منزل_ٹکڑا_mut_201(&نقاب),
      Eurydice_array_منزل_ٹکڑا_shared_20(&challenge_times_s1));
    libcrux_ml_dsa_میٹرکس_گھٹاؤ_vectors_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_صفاں_وچ_A,
      Eurydice_array_منزل_ٹکڑا_mut_201(&w0),
      Eurydice_array_منزل_ٹکڑا_shared_20(&challenge_times_s2));
    إذا
    (
      !libcrux_ml_dsa_arithmetic_سمتیہ_infinity_norm_exceeds_37(Eurydice_array_منزل_ٹکڑا_shared_20(&نقاب),
        (int32_t)((uint32_t)1 << (uint32_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_GAMMA1_EXPONENT) -
          LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_BETA)
    )
    {
      إذا
      (
        !libcrux_ml_dsa_arithmetic_سمتیہ_infinity_norm_exceeds_37(Eurydice_array_منزل_ٹکڑا_shared_20(&w0),
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_GAMMA2 - LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_BETA)
      )
      {
        Eurydice_arr_9d
        challenge_times_t0 =
          core_array__core__clone__Clone_for__T__N___clone((ناپ_t)4U,
            &t0_as_ntt,
            Eurydice_arr_a3,
            Eurydice_arr_9d);
        libcrux_ml_dsa_میٹرکس_سمتیہ_times_ring_element_37(Eurydice_array_منزل_ٹکڑا_mut_201(&challenge_times_t0),
          &verifier_challenge);
        إذا
        (
          !libcrux_ml_dsa_arithmetic_سمتیہ_infinity_norm_exceeds_37(Eurydice_array_منزل_ٹکڑا_shared_20(&challenge_times_t0),
            LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_GAMMA2)
        )
        {
          libcrux_ml_dsa_میٹرکس_جوڑو_vectors_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_صفاں_وچ_A,
            Eurydice_array_منزل_ٹکڑا_mut_201(&w0),
            Eurydice_array_منزل_ٹکڑا_shared_20(&challenge_times_t0));
          Eurydice_arr_b7
          hint_candidate =
            {
              .انکڑے = {
                { .انکڑے = { 0U } },
                { .انکڑے = { 0U } },
                { .انکڑے = { 0U } },
                { .انکڑے = { 0U } }
              }
            };
          ناپ_t
          ones_وچ_hint =
            libcrux_ml_dsa_arithmetic_make_hint_37(Eurydice_array_منزل_ٹکڑا_shared_20(&w0),
              Eurydice_array_منزل_ٹکڑا_shared_20(&commitment),
              LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_GAMMA2,
              Eurydice_array_منزل_ٹکڑا_mut_86(&hint_candidate));
          إذا (!(ones_وچ_hint > LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_MAX_ONES_وچ_HINT))
          {
            attempt = LIBCRUX_ML_DSA_CONSTANTS_REJECTION_SAMPLE_BOUND_SIGN;
            commitment_hash0 =
              (
                KRML_CLITERAL(core_option_Option_14){
                  .ٹیگ = core_option_Some,
                  .f0 = commitment_hash_candidate
                }
              );
            signer_response0 =
              (KRML_CLITERAL(core_option_Option_d9){ .ٹیگ = core_option_Some, .f0 = نقاب });
            hint0 =
              (
                KRML_CLITERAL(core_option_Option_51){
                  .ٹیگ = core_option_Some,
                  .f0 = hint_candidate
                }
              );
          }
        }
      }
    }
  }
  core_نتیجہ_نتیجہ_53 uu____5;
  إذا (commitment_hash0.ٹیگ == core_option_None)
  {
    uu____5 =
      (
        KRML_CLITERAL(core_نتیجہ_نتیجہ_53){
          .ٹیگ = core_نتیجہ_Err,
          .f0 = libcrux_ml_dsa_types_SigningError_RejectionSamplingError
        }
      );
  }
  وإلا
  {
    Eurydice_arr_ec commitment_hash = commitment_hash0.f0;
    Eurydice_arr_ec commitment_hash1 = commitment_hash;
    إذا (signer_response0.ٹیگ == core_option_None)
    {
      uu____5 =
        (
          KRML_CLITERAL(core_نتیجہ_نتیجہ_53){
            .ٹیگ = core_نتیجہ_Err,
            .f0 = libcrux_ml_dsa_types_SigningError_RejectionSamplingError
          }
        );
    }
    وإلا
    {
      Eurydice_arr_9d signer_response = signer_response0.f0;
      Eurydice_arr_9d signer_response1 = signer_response;
      إذا (!(hint0.ٹیگ == core_option_None))
      {
        Eurydice_arr_b7 hint = hint0.f0;
        Eurydice_arr_b7 hint1 = hint;
        libcrux_ml_dsa_encoding_signature_serialize_37(Eurydice_array_منزل_ٹکڑا_shared_01(&commitment_hash1),
          Eurydice_array_منزل_ٹکڑا_shared_20(&signer_response1),
          Eurydice_array_منزل_ٹکڑا_shared_86(&hint1),
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COMMITMENT_HASH_ناپ,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_وچ_A,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_صفاں_وچ_A,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_GAMMA1_EXPONENT,
          LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_GAMMA1_RING_ELEMENT_ناپ,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_MAX_ONES_وچ_HINT,
          Eurydice_array_منزل_ٹکڑا_mut_0d(signature));
        أرجع (KRML_CLITERAL(core_نتیجہ_نتیجہ_53){ .ٹیگ = core_نتیجہ_Ok });
      }
      uu____5 =
        (
          KRML_CLITERAL(core_نتیجہ_نتیجہ_53){
            .ٹیگ = core_نتیجہ_Err,
            .f0 = libcrux_ml_dsa_types_SigningError_RejectionSamplingError
          }
        );
    }
  }
  أرجع uu____5;
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_44.sign_mut
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
ساكن KRML_MUSTINLINE core_نتیجہ_نتیجہ_53
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_sign_mut_5a(
  Eurydice_borrow_ٹکڑا_u8 signing_کلید,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_borrow_ٹکڑا_u8 context,
  Eurydice_arr_ec randomness,
  Eurydice_arr_85 *signature
)
{
  core_نتیجہ_نتیجہ_a8
  uu____0 =
    libcrux_ml_dsa_pre_hash_new_88(context,
      (KRML_CLITERAL(core_option_Option_57){ .ٹیگ = core_option_None }));
  إذا (!(uu____0.ٹیگ == core_نتیجہ_Ok))
  {
    أرجع
      (
        KRML_CLITERAL(core_نتیجہ_نتیجہ_53){
          .ٹیگ = core_نتیجہ_Err,
          .f0 = libcrux_ml_dsa_types_SigningError_ContextTooLongError
        }
      );
  }
  libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
  libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
  أرجع
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_sign_اندرونی_5a(signing_کلید,
      سنیہا,
      (
        KRML_CLITERAL(core_option_Option_84){
          .ٹیگ = core_option_Some,
          .f0 = domain_separation_context
        }
      ),
      randomness,
      signature);
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_44.sign
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
ساكن KRML_MUSTINLINE core_نتیجہ_نتیجہ_48
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_sign_5a(
  Eurydice_borrow_ٹکڑا_u8 signing_کلید,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_borrow_ٹکڑا_u8 context,
  Eurydice_arr_ec randomness
)
{
  Eurydice_arr_85 signature = libcrux_ml_dsa_types_zero_c5_37();
  core_نتیجہ_نتیجہ_53
  uu____0 =
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_sign_mut_5a(signing_کلید,
      سنیہا,
      context,
      randomness,
      &signature);
  core_نتیجہ_نتیجہ_48 uu____1;
  إذا (uu____0.ٹیگ == core_نتیجہ_Ok)
  {
    uu____1 =
      (
        KRML_CLITERAL(core_نتیجہ_نتیجہ_48){
          .ٹیگ = core_نتیجہ_Ok,
          .val = { .case_Ok = signature }
        }
      );
  }
  وإلا
  {
    libcrux_ml_dsa_types_SigningError e = uu____0.f0;
    uu____1 =
      (KRML_CLITERAL(core_نتیجہ_نتیجہ_48){ .ٹیگ = core_نتیجہ_Err, .val = { .case_Err = e } });
  }
  أرجع uu____1;
}

/**
 Sign.
*/
ساكن مضمن core_نتیجہ_نتیجہ_48
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_44_sign(
  ثابت Eurydice_arr_10 *signing_کلید,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_borrow_ٹکڑا_u8 context,
  Eurydice_arr_ec randomness
)
{
  أرجع
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_sign_5a(Eurydice_array_منزل_ٹکڑا_shared_34(signing_کلید),
      سنیہا,
      context,
      randomness);
}

/**
 Sign.
*/
ساكن مضمن core_نتیجہ_نتیجہ_53
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_44_sign_mut(
  ثابت Eurydice_arr_10 *signing_کلید,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_borrow_ٹکڑا_u8 context,
  Eurydice_arr_ec randomness,
  Eurydice_arr_85 *signature
)
{
  أرجع
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_sign_mut_5a(Eurydice_array_منزل_ٹکڑا_shared_34(signing_کلید),
      سنیہا,
      context,
      randomness,
      signature);
}

/**
This function found in impl {libcrux_ml_dsa::pre_hash::PreHash for libcrux_ml_dsa::pre_hash::SHAKE128_PH}
*/
/**
A monomorphic instance of libcrux_ml_dsa.pre_hash.hash_30
with types libcrux_ml_dsa_hash_functions_portable_Shake128
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_pre_hash_hash_30_83(
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_mut_borrow_ٹکڑا_u8 output
)
{
  libcrux_ml_dsa_hash_functions_portable_shake128_7b(سنیہا, output);
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_44.sign_pre_hashed_mut
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4, libcrux_ml_dsa_pre_hash_SHAKE128_PH
with const generics

*/
ساكن KRML_MUSTINLINE core_نتیجہ_نتیجہ_53
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_sign_pre_hashed_mut_3f(
  Eurydice_borrow_ٹکڑا_u8 signing_کلید,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_borrow_ٹکڑا_u8 context,
  Eurydice_mut_borrow_ٹکڑا_u8 pre_hash_بفر,
  Eurydice_arr_ec randomness,
  Eurydice_arr_85 *signature
)
{
  إذا (!(context.meta > LIBCRUX_ML_DSA_CONSTANTS_CONTEXT_MAX_LEN))
  {
    libcrux_ml_dsa_pre_hash_hash_30_83(سنیہا, pre_hash_بفر);
    core_نتیجہ_نتیجہ_a8
    uu____0 =
      libcrux_ml_dsa_pre_hash_new_88(context,
        (
          KRML_CLITERAL(core_option_Option_57){
            .ٹیگ = core_option_Some,
            .f0 = libcrux_ml_dsa_pre_hash_oid_30()
          }
        ));
    إذا (!(uu____0.ٹیگ == core_نتیجہ_Ok))
    {
      أرجع
        (
          KRML_CLITERAL(core_نتیجہ_نتیجہ_53){
            .ٹیگ = core_نتیجہ_Err,
            .f0 = libcrux_ml_dsa_types_SigningError_ContextTooLongError
          }
        );
    }
    libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
    libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
    أرجع
      libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_sign_اندرونی_5a(signing_کلید,
        (
          KRML_CLITERAL(Eurydice_borrow_ٹکڑا_u8){
            .ptr = pre_hash_بفر.ptr,
            .meta = pre_hash_بفر.meta
          }
        ),
        (
          KRML_CLITERAL(core_option_Option_84){
            .ٹیگ = core_option_Some,
            .f0 = domain_separation_context
          }
        ),
        randomness,
        signature);
  }
  أرجع
    (
      KRML_CLITERAL(core_نتیجہ_نتیجہ_53){
        .ٹیگ = core_نتیجہ_Err,
        .f0 = libcrux_ml_dsa_types_SigningError_ContextTooLongError
      }
    );
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_44.sign_pre_hashed
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4, libcrux_ml_dsa_pre_hash_SHAKE128_PH
with const generics

*/
ساكن KRML_MUSTINLINE core_نتیجہ_نتیجہ_48
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_sign_pre_hashed_3f(
  Eurydice_borrow_ٹکڑا_u8 signing_کلید,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_borrow_ٹکڑا_u8 context,
  Eurydice_mut_borrow_ٹکڑا_u8 pre_hash_بفر,
  Eurydice_arr_ec randomness
)
{
  Eurydice_arr_85 signature = libcrux_ml_dsa_types_zero_c5_37();
  core_نتیجہ_نتیجہ_53
  uu____0 =
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_sign_pre_hashed_mut_3f(signing_کلید,
      سنیہا,
      context,
      pre_hash_بفر,
      randomness,
      &signature);
  core_نتیجہ_نتیجہ_48 uu____1;
  إذا (uu____0.ٹیگ == core_نتیجہ_Ok)
  {
    uu____1 =
      (
        KRML_CLITERAL(core_نتیجہ_نتیجہ_48){
          .ٹیگ = core_نتیجہ_Ok,
          .val = { .case_Ok = signature }
        }
      );
  }
  وإلا
  {
    libcrux_ml_dsa_types_SigningError e = uu____0.f0;
    uu____1 =
      (KRML_CLITERAL(core_نتیجہ_نتیجہ_48){ .ٹیگ = core_نتیجہ_Err, .val = { .case_Err = e } });
  }
  أرجع uu____1;
}

/**
 Sign (pre-hashed).
*/
ساكن مضمن core_نتیجہ_نتیجہ_48
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_44_sign_pre_hashed_shake128(
  ثابت Eurydice_arr_10 *signing_کلید,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_borrow_ٹکڑا_u8 context,
  Eurydice_mut_borrow_ٹکڑا_u8 pre_hash_بفر,
  Eurydice_arr_ec randomness
)
{
  أرجع
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_sign_pre_hashed_3f(Eurydice_array_منزل_ٹکڑا_shared_34(signing_کلید),
      سنیہا,
      context,
      pre_hash_بفر,
      randomness);
}

/**
 The internal verification API.

 If no `domain_separation_context` is supplied, it is assumed that
 `message` already contains the domain separation.
*/
/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_44.verify_internal
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof
with const generics

*/
ساكن KRML_MUSTINLINE core_نتیجہ_نتیجہ_41
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_verify_اندرونی_5a(
  ثابت Eurydice_arr_02 *verification_کلید,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  core_option_Option_84 domain_separation_context,
  ثابت Eurydice_arr_85 *signature_serialized
)
{
  Eurydice_borrow_ٹکڑا_u8_x2
  uu____0 =
    Eurydice_ٹکڑا_ونڈو_at(Eurydice_array_منزل_ٹکڑا_shared_9f(verification_کلید),
      LIBCRUX_ML_DSA_CONSTANTS_بیج_FOR_A_ناپ,
      uint8_t,
      Eurydice_borrow_ٹکڑا_u8_x2);
  Eurydice_borrow_ٹکڑا_u8 بیج_for_a = uu____0.fst;
  Eurydice_borrow_ٹکڑا_u8 t1_serialized = uu____0.snd;
  Eurydice_arr_9d t1;
  Eurydice_arr_a3 repeat_expression0[4U];
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)4U; i++)
  {
    repeat_expression0[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  حافظہ_نقل(t1.انکڑے, repeat_expression0, (ناپ_t)4U * حجم (Eurydice_arr_a3));
  libcrux_ml_dsa_encoding_verification_کلید_deserialize_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_صفاں_وچ_A,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_VERIFICATION_کلید_ناپ,
    t1_serialized,
    Eurydice_array_منزل_ٹکڑا_mut_201(&t1));
  Eurydice_arr_ec deserialized_commitment_hash = { .انکڑے = { 0U } };
  Eurydice_arr_9d deserialized_signer_response;
  Eurydice_arr_a3 repeat_expression1[4U];
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)4U; i++)
  {
    repeat_expression1[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  حافظہ_نقل(deserialized_signer_response.انکڑے,
    repeat_expression1,
    (ناپ_t)4U * حجم (Eurydice_arr_a3));
  Eurydice_arr_b7
  deserialized_hint =
    { .انکڑے = { { .انکڑے = { 0U } }, { .انکڑے = { 0U } }, { .انکڑے = { 0U } }, { .انکڑے = { 0U } } } };
  core_نتیجہ_نتیجہ_41
  uu____1 =
    libcrux_ml_dsa_encoding_signature_deserialize_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_وچ_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_صفاں_وچ_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COMMITMENT_HASH_ناپ,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_GAMMA1_EXPONENT,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_GAMMA1_RING_ELEMENT_ناپ,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_MAX_ONES_وچ_HINT,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_SIGNATURE_ناپ,
      Eurydice_array_منزل_ٹکڑا_shared_0d(signature_serialized),
      Eurydice_array_منزل_ٹکڑا_mut_01(&deserialized_commitment_hash),
      Eurydice_array_منزل_ٹکڑا_mut_201(&deserialized_signer_response),
      Eurydice_array_منزل_ٹکڑا_mut_86(&deserialized_hint));
  core_نتیجہ_نتیجہ_41 uu____2;
  إذا (uu____1.ٹیگ == core_نتیجہ_Ok)
  {
    إذا
    (
      libcrux_ml_dsa_arithmetic_سمتیہ_infinity_norm_exceeds_37(Eurydice_array_منزل_ٹکڑا_shared_20(&deserialized_signer_response),
        (int32_t)((uint32_t)1 << (uint32_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_GAMMA1_EXPONENT) -
          LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_BETA)
    )
    {
      uu____2 =
        (
          KRML_CLITERAL(core_نتیجہ_نتیجہ_41){
            .ٹیگ = core_نتیجہ_Err,
            .f0 = libcrux_ml_dsa_types_VerificationError_SignerResponseExceedsBoundError
          }
        );
    }
    وإلا
    {
      Eurydice_arr_2f میٹرکس;
      Eurydice_arr_a3 repeat_عبارت[16U];
      لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)16U; i++)
      {
        repeat_عبارت[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
      }
      حافظہ_نقل(میٹرکس.انکڑے, repeat_عبارت, (ناپ_t)16U * حجم (Eurydice_arr_a3));
      libcrux_ml_dsa_samplex4_portable_میٹرکس_flat_a8_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_وچ_A,
        بیج_for_a,
        Eurydice_array_منزل_ٹکڑا_mut_200(&میٹرکس));
      Eurydice_arr_c7 verification_کلید_hash = { .انکڑے = { 0U } };
      libcrux_ml_dsa_hash_functions_portable_shake256_61_c9(Eurydice_array_منزل_ٹکڑا_shared_9f(verification_کلید),
        &verification_کلید_hash);
      Eurydice_arr_c7 سنیہا_representative = { .انکڑے = { 0U } };
      libcrux_ml_dsa_ml_dsa_generic_derive_سنیہا_representative_43(Eurydice_array_منزل_ٹکڑا_shared_17(&verification_کلید_hash),
        &domain_separation_context,
        سنیہا,
        &سنیہا_representative);
      Eurydice_arr_a3 verifier_challenge = libcrux_ml_dsa_polynomial_zero_ff_37();
      libcrux_ml_dsa_sample_sample_challenge_ring_element_2e(Eurydice_array_منزل_ٹکڑا_shared_01(&deserialized_commitment_hash),
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ONES_وچ_VERIFIER_CHALLENGE,
        &verifier_challenge);
      libcrux_ml_dsa_ntt_ntt_37(&verifier_challenge);
      لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)4U; i++)
      {
        ناپ_t i0 = i;
        libcrux_ml_dsa_ntt_ntt_37(&deserialized_signer_response.انکڑے[i0]);
      }
      libcrux_ml_dsa_میٹرکس_compute_w_approx_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_صفاں_وچ_A,
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_وچ_A,
        Eurydice_array_منزل_ٹکڑا_shared_201(&میٹرکس),
        Eurydice_array_منزل_ٹکڑا_shared_20(&deserialized_signer_response),
        &verifier_challenge,
        Eurydice_array_منزل_ٹکڑا_mut_201(&t1));
      Eurydice_arr_ec recomputed_commitment_hash = { .انکڑے = { 0U } };
      libcrux_ml_dsa_arithmetic_use_hint_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_GAMMA2,
        Eurydice_array_منزل_ٹکڑا_shared_86(&deserialized_hint),
        Eurydice_array_منزل_ٹکڑا_mut_201(&t1));
      Eurydice_arr_d2 commitment_serialized = { .انکڑے = { 0U } };
      libcrux_ml_dsa_encoding_commitment_serialize_سمتیہ_37(LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_COMMITMENT_RING_ELEMENT_ناپ,
        Eurydice_array_منزل_ٹکڑا_shared_20(&t1),
        Eurydice_array_منزل_ٹکڑا_mut_27(&commitment_serialized));
      libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
      shake = libcrux_ml_dsa_hash_functions_portable_init_26();
      libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake,
        Eurydice_array_منزل_ٹکڑا_shared_17(&سنیہا_representative));
      libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake,
        Eurydice_array_منزل_ٹکڑا_shared_27(&commitment_serialized));
      libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake,
        Eurydice_array_منزل_ٹکڑا_mut_01(&recomputed_commitment_hash));
      إذا
      (
        Eurydice_array_eq((ناپ_t)32U,
          &deserialized_commitment_hash,
          &recomputed_commitment_hash,
          uint8_t)
      )
      {
        uu____2 = (KRML_CLITERAL(core_نتیجہ_نتیجہ_41){ .ٹیگ = core_نتیجہ_Ok });
      }
      وإلا
      {
        uu____2 =
          (
            KRML_CLITERAL(core_نتیجہ_نتیجہ_41){
              .ٹیگ = core_نتیجہ_Err,
              .f0 = libcrux_ml_dsa_types_Verification_Error_Commitment_Hashes_Dont_میل_Error
            }
          );
      }
    }
  }
  وإلا
  {
    libcrux_ml_dsa_types_VerificationError e = uu____1.f0;
    uu____2 = (KRML_CLITERAL(core_نتیجہ_نتیجہ_41){ .ٹیگ = core_نتیجہ_Err, .f0 = e });
  }
  أرجع uu____2;
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_44.verify
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof
with const generics

*/
ساكن KRML_MUSTINLINE core_نتیجہ_نتیجہ_41
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_verify_5a(
  ثابت Eurydice_arr_02 *verification_کلید_serialized,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_borrow_ٹکڑا_u8 context,
  ثابت Eurydice_arr_85 *signature_serialized
)
{
  core_نتیجہ_نتیجہ_a8
  uu____0 =
    libcrux_ml_dsa_pre_hash_new_88(context,
      (KRML_CLITERAL(core_option_Option_57){ .ٹیگ = core_option_None }));
  إذا (!(uu____0.ٹیگ == core_نتیجہ_Ok))
  {
    أرجع
      (
        KRML_CLITERAL(core_نتیجہ_نتیجہ_41){
          .ٹیگ = core_نتیجہ_Err,
          .f0 = libcrux_ml_dsa_types_VerificationError_VerificationContextTooLongError
        }
      );
  }
  libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
  libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
  أرجع
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_verify_اندرونی_5a(verification_کلید_serialized,
      سنیہا,
      (
        KRML_CLITERAL(core_option_Option_84){
          .ٹیگ = core_option_Some,
          .f0 = domain_separation_context
        }
      ),
      signature_serialized);
}

/**
 Verify.
*/
ساكن مضمن core_نتیجہ_نتیجہ_41
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_44_verify(
  ثابت Eurydice_arr_02 *verification_کلید,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_borrow_ٹکڑا_u8 context,
  ثابت Eurydice_arr_85 *signature
)
{
  أرجع
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_verify_5a(verification_کلید,
      سنیہا,
      context,
      signature);
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_44.verify_pre_hashed
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_pre_hash_SHAKE128_PH
with const generics

*/
ساكن KRML_MUSTINLINE core_نتیجہ_نتیجہ_41
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_verify_pre_hashed_3f(
  ثابت Eurydice_arr_02 *verification_کلید_serialized,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_borrow_ٹکڑا_u8 context,
  Eurydice_mut_borrow_ٹکڑا_u8 pre_hash_بفر,
  ثابت Eurydice_arr_85 *signature_serialized
)
{
  libcrux_ml_dsa_pre_hash_hash_30_83(سنیہا, pre_hash_بفر);
  core_نتیجہ_نتیجہ_a8
  uu____0 =
    libcrux_ml_dsa_pre_hash_new_88(context,
      (
        KRML_CLITERAL(core_option_Option_57){
          .ٹیگ = core_option_Some,
          .f0 = libcrux_ml_dsa_pre_hash_oid_30()
        }
      ));
  إذا (!(uu____0.ٹیگ == core_نتیجہ_Ok))
  {
    أرجع
      (
        KRML_CLITERAL(core_نتیجہ_نتیجہ_41){
          .ٹیگ = core_نتیجہ_Err,
          .f0 = libcrux_ml_dsa_types_VerificationError_VerificationContextTooLongError
        }
      );
  }
  libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
  libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
  أرجع
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_verify_اندرونی_5a(verification_کلید_serialized,
      (
        KRML_CLITERAL(Eurydice_borrow_ٹکڑا_u8){
          .ptr = pre_hash_بفر.ptr,
          .meta = pre_hash_بفر.meta
        }
      ),
      (
        KRML_CLITERAL(core_option_Option_84){
          .ٹیگ = core_option_Some,
          .f0 = domain_separation_context
        }
      ),
      signature_serialized);
}

/**
 Verify (pre-hashed with SHAKE-128).
*/
ساكن مضمن core_نتیجہ_نتیجہ_41
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_44_verify_pre_hashed_shake128(
  ثابت Eurydice_arr_02 *verification_کلید,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_borrow_ٹکڑا_u8 context,
  Eurydice_mut_borrow_ٹکڑا_u8 pre_hash_بفر,
  ثابت Eurydice_arr_85 *signature
)
{
  أرجع
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_verify_pre_hashed_3f(verification_کلید,
      سنیہا,
      context,
      pre_hash_بفر,
      signature);
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_65.generate_key_pair
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_generate_کلید_pair_5a(
  Eurydice_arr_ec randomness,
  Eurydice_mut_borrow_ٹکڑا_u8 signing_کلید,
  Eurydice_mut_borrow_ٹکڑا_u8 verification_کلید
)
{
  Eurydice_arr_89 بیج_expanded0 = { .انکڑے = { 0U } };
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
  shake = libcrux_ml_dsa_hash_functions_portable_init_26();
  libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake,
    Eurydice_array_منزل_ٹکڑا_shared_01(&randomness));
  /* original Rust expression is not an lvalue in C */
  Eurydice_array_u8x2
  lvalue =
    {
      .انکڑے = {
        (uint8_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_صفاں_وچ_A,
        (uint8_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_وچ_A
      }
    };
  libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake,
    Eurydice_array_منزل_ٹکڑا_shared_82(&lvalue));
  libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake,
    Eurydice_array_منزل_ٹکڑا_mut_78(&بیج_expanded0));
  Eurydice_borrow_ٹکڑا_u8_x2
  uu____0 =
    Eurydice_ٹکڑا_ونڈو_at(Eurydice_array_منزل_ٹکڑا_shared_78(&بیج_expanded0),
      LIBCRUX_ML_DSA_CONSTANTS_بیج_FOR_A_ناپ,
      uint8_t,
      Eurydice_borrow_ٹکڑا_u8_x2);
  Eurydice_borrow_ٹکڑا_u8 بیج_for_a = uu____0.fst;
  Eurydice_borrow_ٹکڑا_u8 بیج_expanded = uu____0.snd;
  Eurydice_borrow_ٹکڑا_u8_x2
  uu____1 =
    Eurydice_ٹکڑا_ونڈو_at(بیج_expanded,
      LIBCRUX_ML_DSA_CONSTANTS_بیج_FOR_ERROR_VECTORS_ناپ,
      uint8_t,
      Eurydice_borrow_ٹکڑا_u8_x2);
  Eurydice_borrow_ٹکڑا_u8 بیج_for_error_vectors = uu____1.fst;
  Eurydice_borrow_ٹکڑا_u8 بیج_for_signing = uu____1.snd;
  Eurydice_arr_47 s1_s2;
  Eurydice_arr_a3 repeat_expression0[11U];
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)11U; i++)
  {
    repeat_expression0[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  حافظہ_نقل(s1_s2.انکڑے, repeat_expression0, (ناپ_t)11U * حجم (Eurydice_arr_a3));
  libcrux_ml_dsa_samplex4_sample_s1_and_s2_29(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ETA,
    بیج_for_error_vectors,
    Eurydice_array_منزل_ٹکڑا_mut_202(&s1_s2));
  Eurydice_arr_dc1 t0;
  Eurydice_arr_a3 repeat_expression1[6U];
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)6U; i++)
  {
    repeat_expression1[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  حافظہ_نقل(t0.انکڑے, repeat_expression1, (ناپ_t)6U * حجم (Eurydice_arr_a3));
  Eurydice_arr_5a a_as_ntt;
  Eurydice_arr_a3 repeat_expression2[30U];
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)30U; i++)
  {
    repeat_expression2[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  حافظہ_نقل(a_as_ntt.انکڑے, repeat_expression2, (ناپ_t)30U * حجم (Eurydice_arr_a3));
  libcrux_ml_dsa_samplex4_portable_میٹرکس_flat_a8_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_وچ_A,
    بیج_for_a,
    Eurydice_array_منزل_ٹکڑا_mut_203(&a_as_ntt));
  Eurydice_arr_5d s1_ntt;
  Eurydice_arr_a3 repeat_expression3[5U];
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)5U; i++)
  {
    repeat_expression3[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  حافظہ_نقل(s1_ntt.انکڑے, repeat_expression3, (ناپ_t)5U * حجم (Eurydice_arr_a3));
  Eurydice_ٹکڑا_copy(Eurydice_array_منزل_ٹکڑا_mut_204(&s1_ntt),
    Eurydice_array_منزل_subslice_shared_250(&s1_s2,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .شروع = (ناپ_t)0U,
          .سرا = LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_وچ_A
        }
      )),
    Eurydice_arr_a3);
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)5U; i++)
  {
    ناپ_t i0 = i;
    libcrux_ml_dsa_ntt_ntt_37(&s1_ntt.انکڑے[i0]);
  }
  libcrux_ml_dsa_میٹرکس_compute_as1_plus_s2_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_صفاں_وچ_A,
    LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_وچ_A,
    Eurydice_array_منزل_ٹکڑا_mut_203(&a_as_ntt),
    Eurydice_array_منزل_ٹکڑا_shared_202(&s1_ntt),
    Eurydice_array_منزل_ٹکڑا_shared_203(&s1_s2),
    Eurydice_array_منزل_ٹکڑا_mut_205(&t0));
  Eurydice_arr_dc1 t1;
  Eurydice_arr_a3 repeat_عبارت[6U];
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)6U; i++)
  {
    repeat_عبارت[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  حافظہ_نقل(t1.انکڑے, repeat_عبارت, (ناپ_t)6U * حجم (Eurydice_arr_a3));
  libcrux_ml_dsa_arithmetic_power2round_سمتیہ_37(Eurydice_array_منزل_ٹکڑا_mut_205(&t0),
    Eurydice_array_منزل_ٹکڑا_mut_205(&t1));
  libcrux_ml_dsa_encoding_verification_کلید_generate_serialized_37(بیج_for_a,
    Eurydice_array_منزل_ٹکڑا_shared_204(&t1),
    verification_کلید);
  libcrux_ml_dsa_encoding_signing_کلید_generate_serialized_2e(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ETA,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_ERROR_RING_ELEMENT_ناپ,
    بیج_for_a,
    بیج_for_signing,
    (
      KRML_CLITERAL(Eurydice_borrow_ٹکڑا_u8){
        .ptr = verification_کلید.ptr,
        .meta = verification_کلید.meta
      }
    ),
    Eurydice_array_منزل_ٹکڑا_shared_203(&s1_s2),
    Eurydice_array_منزل_ٹکڑا_shared_204(&t0),
    signing_کلید);
}

/**
 Generate key pair.
*/
ساكن مضمن فراغ
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_generate_کلید_pair(
  Eurydice_arr_ec randomness,
  Eurydice_arr_24 *signing_کلید,
  Eurydice_arr_29 *verification_کلید
)
{
  libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_generate_کلید_pair_5a(randomness,
    Eurydice_array_منزل_ٹکڑا_mut_98(signing_کلید),
    Eurydice_array_منزل_ٹکڑا_mut_37(verification_کلید));
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_65.sign_internal
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
ساكن KRML_MUSTINLINE core_نتیجہ_نتیجہ_53
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_اندرونی_5a(
  Eurydice_borrow_ٹکڑا_u8 signing_کلید,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  core_option_Option_84 domain_separation_context,
  Eurydice_arr_ec randomness,
  Eurydice_arr_0c *signature
)
{
  Eurydice_borrow_ٹکڑا_u8_x2
  uu____0 =
    Eurydice_ٹکڑا_ونڈو_at(signing_کلید,
      LIBCRUX_ML_DSA_CONSTANTS_بیج_FOR_A_ناپ,
      uint8_t,
      Eurydice_borrow_ٹکڑا_u8_x2);
  Eurydice_borrow_ٹکڑا_u8 بیج_for_a = uu____0.fst;
  Eurydice_borrow_ٹکڑا_u8 بچیا_serialized0 = uu____0.snd;
  Eurydice_borrow_ٹکڑا_u8_x2
  uu____1 =
    Eurydice_ٹکڑا_ونڈو_at(بچیا_serialized0,
      LIBCRUX_ML_DSA_CONSTANTS_بیج_FOR_SIGNING_ناپ,
      uint8_t,
      Eurydice_borrow_ٹکڑا_u8_x2);
  Eurydice_borrow_ٹکڑا_u8 بیج_for_signing = uu____1.fst;
  Eurydice_borrow_ٹکڑا_u8 بچیا_serialized1 = uu____1.snd;
  Eurydice_borrow_ٹکڑا_u8_x2
  uu____2 =
    Eurydice_ٹکڑا_ونڈو_at(بچیا_serialized1,
      LIBCRUX_ML_DSA_CONSTANTS_بائٹاں_FOR_VERIFICATION_کلید_HASH,
      uint8_t,
      Eurydice_borrow_ٹکڑا_u8_x2);
  Eurydice_borrow_ٹکڑا_u8 verification_کلید_hash = uu____2.fst;
  Eurydice_borrow_ٹکڑا_u8 بچیا_serialized2 = uu____2.snd;
  Eurydice_borrow_ٹکڑا_u8_x2
  uu____3 =
    Eurydice_ٹکڑا_ونڈو_at(بچیا_serialized2,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_ERROR_RING_ELEMENT_ناپ *
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_وچ_A,
      uint8_t,
      Eurydice_borrow_ٹکڑا_u8_x2);
  Eurydice_borrow_ٹکڑا_u8 s1_serialized = uu____3.fst;
  Eurydice_borrow_ٹکڑا_u8 بچیا_serialized = uu____3.snd;
  Eurydice_borrow_ٹکڑا_u8_x2
  uu____4 =
    Eurydice_ٹکڑا_ونڈو_at(بچیا_serialized,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_ERROR_RING_ELEMENT_ناپ *
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_صفاں_وچ_A,
      uint8_t,
      Eurydice_borrow_ٹکڑا_u8_x2);
  Eurydice_borrow_ٹکڑا_u8 s2_serialized = uu____4.fst;
  Eurydice_borrow_ٹکڑا_u8 t0_serialized = uu____4.snd;
  Eurydice_arr_5d s1_as_ntt;
  Eurydice_arr_a3 repeat_expression0[5U];
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)5U; i++)
  {
    repeat_expression0[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  حافظہ_نقل(s1_as_ntt.انکڑے, repeat_expression0, (ناپ_t)5U * حجم (Eurydice_arr_a3));
  Eurydice_arr_dc1 s2_as_ntt;
  Eurydice_arr_a3 repeat_expression1[6U];
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)6U; i++)
  {
    repeat_expression1[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  حافظہ_نقل(s2_as_ntt.انکڑے, repeat_expression1, (ناپ_t)6U * حجم (Eurydice_arr_a3));
  Eurydice_arr_dc1 t0_as_ntt;
  Eurydice_arr_a3 repeat_expression2[6U];
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)6U; i++)
  {
    repeat_expression2[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  حافظہ_نقل(t0_as_ntt.انکڑے, repeat_expression2, (ناپ_t)6U * حجم (Eurydice_arr_a3));
  libcrux_ml_dsa_encoding_error_deserialize_منزل_سمتیہ_then_ntt_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ETA,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_ERROR_RING_ELEMENT_ناپ,
    s1_serialized,
    Eurydice_array_منزل_ٹکڑا_mut_204(&s1_as_ntt));
  libcrux_ml_dsa_encoding_error_deserialize_منزل_سمتیہ_then_ntt_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ETA,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_ERROR_RING_ELEMENT_ناپ,
    s2_serialized,
    Eurydice_array_منزل_ٹکڑا_mut_205(&s2_as_ntt));
  libcrux_ml_dsa_encoding_t0_deserialize_منزل_سمتیہ_then_ntt_37(t0_serialized,
    Eurydice_array_منزل_ٹکڑا_mut_205(&t0_as_ntt));
  Eurydice_arr_5a میٹرکس;
  Eurydice_arr_a3 repeat_expression3[30U];
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)30U; i++)
  {
    repeat_expression3[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  حافظہ_نقل(میٹرکس.انکڑے, repeat_expression3, (ناپ_t)30U * حجم (Eurydice_arr_a3));
  libcrux_ml_dsa_samplex4_portable_میٹرکس_flat_a8_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_وچ_A,
    بیج_for_a,
    Eurydice_array_منزل_ٹکڑا_mut_203(&میٹرکس));
  Eurydice_arr_c7 سنیہا_representative = { .انکڑے = { 0U } };
  libcrux_ml_dsa_ml_dsa_generic_derive_سنیہا_representative_43(verification_کلید_hash,
    &domain_separation_context,
    سنیہا,
    &سنیہا_representative);
  Eurydice_arr_c7 نقاب_بیج = { .انکڑے = { 0U } };
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
  shake0 = libcrux_ml_dsa_hash_functions_portable_init_26();
  libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake0, بیج_for_signing);
  libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake0,
    Eurydice_array_منزل_ٹکڑا_shared_01(&randomness));
  libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake0,
    Eurydice_array_منزل_ٹکڑا_shared_17(&سنیہا_representative));
  libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake0,
    Eurydice_array_منزل_ٹکڑا_mut_17(&نقاب_بیج));
  uint16_t domain_separator_for_نقاب = 0U;
  ناپ_t attempt = (ناپ_t)0U;
  core_option_Option_81 commitment_hash0 = { .ٹیگ = core_option_None };
  core_option_Option_1e signer_response0 = { .ٹیگ = core_option_None };
  core_option_Option_05 hint0 = { .ٹیگ = core_option_None };
  طالما (attempt < LIBCRUX_ML_DSA_CONSTANTS_REJECTION_SAMPLE_BOUND_SIGN)
  {
    attempt++;
    Eurydice_arr_5d نقاب;
    Eurydice_arr_a3 repeat_expression4[5U];
    لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)5U; i++)
    {
      repeat_expression4[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    حافظہ_نقل(نقاب.انکڑے, repeat_expression4, (ناپ_t)5U * حجم (Eurydice_arr_a3));
    Eurydice_arr_dc1 w0;
    Eurydice_arr_a3 repeat_expression5[6U];
    لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)6U; i++)
    {
      repeat_expression5[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    حافظہ_نقل(w0.انکڑے, repeat_expression5, (ناپ_t)6U * حجم (Eurydice_arr_a3));
    Eurydice_arr_dc1 commitment;
    Eurydice_arr_a3 repeat_expression6[6U];
    لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)6U; i++)
    {
      repeat_expression6[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    حافظہ_نقل(commitment.انکڑے, repeat_expression6, (ناپ_t)6U * حجم (Eurydice_arr_a3));
    libcrux_ml_dsa_sample_sample_نقاب_سمتیہ_67(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_وچ_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA1_EXPONENT,
      &نقاب_بیج,
      &domain_separator_for_نقاب,
      Eurydice_array_منزل_ٹکڑا_mut_204(&نقاب));
    Eurydice_arr_dc1 a_x_نقاب;
    Eurydice_arr_a3 repeat_عبارت[6U];
    لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)6U; i++)
    {
      repeat_عبارت[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    حافظہ_نقل(a_x_نقاب.انکڑے, repeat_عبارت, (ناپ_t)6U * حجم (Eurydice_arr_a3));
    Eurydice_arr_5d
    نقاب_ntt =
      core_array__core__clone__Clone_for__T__N___clone((ناپ_t)5U,
        &نقاب,
        Eurydice_arr_a3,
        Eurydice_arr_5d);
    لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)5U; i++)
    {
      ناپ_t i0 = i;
      libcrux_ml_dsa_ntt_ntt_37(&نقاب_ntt.انکڑے[i0]);
    }
    libcrux_ml_dsa_میٹرکس_compute_میٹرکس_x_نقاب_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_صفاں_وچ_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_وچ_A,
      Eurydice_array_منزل_ٹکڑا_shared_205(&میٹرکس),
      Eurydice_array_منزل_ٹکڑا_shared_202(&نقاب_ntt),
      Eurydice_array_منزل_ٹکڑا_mut_205(&a_x_نقاب));
    libcrux_ml_dsa_arithmetic_decompose_سمتیہ_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_صفاں_وچ_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA2,
      Eurydice_array_منزل_ٹکڑا_shared_204(&a_x_نقاب),
      Eurydice_array_منزل_ٹکڑا_mut_205(&w0),
      Eurydice_array_منزل_ٹکڑا_mut_205(&commitment));
    Eurydice_arr_65 commitment_hash_candidate = { .انکڑے = { 0U } };
    Eurydice_arr_d2 commitment_serialized = { .انکڑے = { 0U } };
    libcrux_ml_dsa_encoding_commitment_serialize_سمتیہ_37(LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_COMMITMENT_RING_ELEMENT_ناپ,
      Eurydice_array_منزل_ٹکڑا_shared_204(&commitment),
      Eurydice_array_منزل_ٹکڑا_mut_27(&commitment_serialized));
    libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
    shake = libcrux_ml_dsa_hash_functions_portable_init_26();
    libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake,
      Eurydice_array_منزل_ٹکڑا_shared_17(&سنیہا_representative));
    libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake,
      Eurydice_array_منزل_ٹکڑا_shared_27(&commitment_serialized));
    libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake,
      Eurydice_array_منزل_ٹکڑا_mut_9f(&commitment_hash_candidate));
    Eurydice_arr_a3 verifier_challenge = libcrux_ml_dsa_polynomial_zero_ff_37();
    libcrux_ml_dsa_sample_sample_challenge_ring_element_2e(Eurydice_array_منزل_ٹکڑا_shared_9f0(&commitment_hash_candidate),
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ONES_وچ_VERIFIER_CHALLENGE,
      &verifier_challenge);
    libcrux_ml_dsa_ntt_ntt_37(&verifier_challenge);
    Eurydice_arr_5d
    challenge_times_s1 =
      core_array__core__clone__Clone_for__T__N___clone((ناپ_t)5U,
        &s1_as_ntt,
        Eurydice_arr_a3,
        Eurydice_arr_5d);
    Eurydice_arr_dc1
    challenge_times_s2 =
      core_array__core__clone__Clone_for__T__N___clone((ناپ_t)6U,
        &s2_as_ntt,
        Eurydice_arr_a3,
        Eurydice_arr_dc1);
    libcrux_ml_dsa_میٹرکس_سمتیہ_times_ring_element_37(Eurydice_array_منزل_ٹکڑا_mut_204(&challenge_times_s1),
      &verifier_challenge);
    libcrux_ml_dsa_میٹرکس_سمتیہ_times_ring_element_37(Eurydice_array_منزل_ٹکڑا_mut_205(&challenge_times_s2),
      &verifier_challenge);
    libcrux_ml_dsa_میٹرکس_جوڑو_vectors_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_وچ_A,
      Eurydice_array_منزل_ٹکڑا_mut_204(&نقاب),
      Eurydice_array_منزل_ٹکڑا_shared_202(&challenge_times_s1));
    libcrux_ml_dsa_میٹرکس_گھٹاؤ_vectors_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_صفاں_وچ_A,
      Eurydice_array_منزل_ٹکڑا_mut_205(&w0),
      Eurydice_array_منزل_ٹکڑا_shared_204(&challenge_times_s2));
    إذا
    (
      !libcrux_ml_dsa_arithmetic_سمتیہ_infinity_norm_exceeds_37(Eurydice_array_منزل_ٹکڑا_shared_202(&نقاب),
        (int32_t)((uint32_t)1 << (uint32_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA1_EXPONENT) -
          LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_BETA)
    )
    {
      إذا
      (
        !libcrux_ml_dsa_arithmetic_سمتیہ_infinity_norm_exceeds_37(Eurydice_array_منزل_ٹکڑا_shared_204(&w0),
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA2 - LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_BETA)
      )
      {
        Eurydice_arr_dc1
        challenge_times_t0 =
          core_array__core__clone__Clone_for__T__N___clone((ناپ_t)6U,
            &t0_as_ntt,
            Eurydice_arr_a3,
            Eurydice_arr_dc1);
        libcrux_ml_dsa_میٹرکس_سمتیہ_times_ring_element_37(Eurydice_array_منزل_ٹکڑا_mut_205(&challenge_times_t0),
          &verifier_challenge);
        إذا
        (
          !libcrux_ml_dsa_arithmetic_سمتیہ_infinity_norm_exceeds_37(Eurydice_array_منزل_ٹکڑا_shared_204(&challenge_times_t0),
            LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA2)
        )
        {
          libcrux_ml_dsa_میٹرکس_جوڑو_vectors_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_صفاں_وچ_A,
            Eurydice_array_منزل_ٹکڑا_mut_205(&w0),
            Eurydice_array_منزل_ٹکڑا_shared_204(&challenge_times_t0));
          Eurydice_arr_5d0
          hint_candidate =
            {
              .انکڑے = {
                { .انکڑے = { 0U } }, { .انکڑے = { 0U } }, { .انکڑے = { 0U } }, { .انکڑے = { 0U } },
                { .انکڑے = { 0U } }, { .انکڑے = { 0U } }
              }
            };
          ناپ_t
          ones_وچ_hint =
            libcrux_ml_dsa_arithmetic_make_hint_37(Eurydice_array_منزل_ٹکڑا_shared_204(&w0),
              Eurydice_array_منزل_ٹکڑا_shared_204(&commitment),
              LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA2,
              Eurydice_array_منزل_ٹکڑا_mut_860(&hint_candidate));
          إذا (!(ones_وچ_hint > LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_MAX_ONES_وچ_HINT))
          {
            attempt = LIBCRUX_ML_DSA_CONSTANTS_REJECTION_SAMPLE_BOUND_SIGN;
            commitment_hash0 =
              (
                KRML_CLITERAL(core_option_Option_81){
                  .ٹیگ = core_option_Some,
                  .f0 = commitment_hash_candidate
                }
              );
            signer_response0 =
              (KRML_CLITERAL(core_option_Option_1e){ .ٹیگ = core_option_Some, .f0 = نقاب });
            hint0 =
              (
                KRML_CLITERAL(core_option_Option_05){
                  .ٹیگ = core_option_Some,
                  .f0 = hint_candidate
                }
              );
          }
        }
      }
    }
  }
  core_نتیجہ_نتیجہ_53 uu____5;
  إذا (commitment_hash0.ٹیگ == core_option_None)
  {
    uu____5 =
      (
        KRML_CLITERAL(core_نتیجہ_نتیجہ_53){
          .ٹیگ = core_نتیجہ_Err,
          .f0 = libcrux_ml_dsa_types_SigningError_RejectionSamplingError
        }
      );
  }
  وإلا
  {
    Eurydice_arr_65 commitment_hash = commitment_hash0.f0;
    Eurydice_arr_65 commitment_hash1 = commitment_hash;
    إذا (signer_response0.ٹیگ == core_option_None)
    {
      uu____5 =
        (
          KRML_CLITERAL(core_نتیجہ_نتیجہ_53){
            .ٹیگ = core_نتیجہ_Err,
            .f0 = libcrux_ml_dsa_types_SigningError_RejectionSamplingError
          }
        );
    }
    وإلا
    {
      Eurydice_arr_5d signer_response = signer_response0.f0;
      Eurydice_arr_5d signer_response1 = signer_response;
      إذا (!(hint0.ٹیگ == core_option_None))
      {
        Eurydice_arr_5d0 hint = hint0.f0;
        Eurydice_arr_5d0 hint1 = hint;
        libcrux_ml_dsa_encoding_signature_serialize_37(Eurydice_array_منزل_ٹکڑا_shared_9f0(&commitment_hash1),
          Eurydice_array_منزل_ٹکڑا_shared_202(&signer_response1),
          Eurydice_array_منزل_ٹکڑا_shared_860(&hint1),
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COMMITMENT_HASH_ناپ,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_وچ_A,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_صفاں_وچ_A,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA1_EXPONENT,
          LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_GAMMA1_RING_ELEMENT_ناپ,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_MAX_ONES_وچ_HINT,
          Eurydice_array_منزل_ٹکڑا_mut_6b(signature));
        أرجع (KRML_CLITERAL(core_نتیجہ_نتیجہ_53){ .ٹیگ = core_نتیجہ_Ok });
      }
      uu____5 =
        (
          KRML_CLITERAL(core_نتیجہ_نتیجہ_53){
            .ٹیگ = core_نتیجہ_Err,
            .f0 = libcrux_ml_dsa_types_SigningError_RejectionSamplingError
          }
        );
    }
  }
  أرجع uu____5;
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_65.sign_mut
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
ساكن KRML_MUSTINLINE core_نتیجہ_نتیجہ_53
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_mut_5a(
  Eurydice_borrow_ٹکڑا_u8 signing_کلید,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_borrow_ٹکڑا_u8 context,
  Eurydice_arr_ec randomness,
  Eurydice_arr_0c *signature
)
{
  core_نتیجہ_نتیجہ_a8
  uu____0 =
    libcrux_ml_dsa_pre_hash_new_88(context,
      (KRML_CLITERAL(core_option_Option_57){ .ٹیگ = core_option_None }));
  إذا (!(uu____0.ٹیگ == core_نتیجہ_Ok))
  {
    أرجع
      (
        KRML_CLITERAL(core_نتیجہ_نتیجہ_53){
          .ٹیگ = core_نتیجہ_Err,
          .f0 = libcrux_ml_dsa_types_SigningError_ContextTooLongError
        }
      );
  }
  libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
  libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
  أرجع
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_اندرونی_5a(signing_کلید,
      سنیہا,
      (
        KRML_CLITERAL(core_option_Option_84){
          .ٹیگ = core_option_Some,
          .f0 = domain_separation_context
        }
      ),
      randomness,
      signature);
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_65.sign
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
ساكن KRML_MUSTINLINE core_نتیجہ_نتیجہ_8c
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_5a(
  Eurydice_borrow_ٹکڑا_u8 signing_کلید,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_borrow_ٹکڑا_u8 context,
  Eurydice_arr_ec randomness
)
{
  Eurydice_arr_0c signature = libcrux_ml_dsa_types_zero_c5_5c();
  core_نتیجہ_نتیجہ_53
  uu____0 =
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_mut_5a(signing_کلید,
      سنیہا,
      context,
      randomness,
      &signature);
  core_نتیجہ_نتیجہ_8c uu____1;
  إذا (uu____0.ٹیگ == core_نتیجہ_Ok)
  {
    uu____1 =
      (
        KRML_CLITERAL(core_نتیجہ_نتیجہ_8c){
          .ٹیگ = core_نتیجہ_Ok,
          .val = { .case_Ok = signature }
        }
      );
  }
  وإلا
  {
    libcrux_ml_dsa_types_SigningError e = uu____0.f0;
    uu____1 =
      (KRML_CLITERAL(core_نتیجہ_نتیجہ_8c){ .ٹیگ = core_نتیجہ_Err, .val = { .case_Err = e } });
  }
  أرجع uu____1;
}

/**
 Sign.
*/
ساكن مضمن core_نتیجہ_نتیجہ_8c
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_sign(
  ثابت Eurydice_arr_24 *signing_کلید,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_borrow_ٹکڑا_u8 context,
  Eurydice_arr_ec randomness
)
{
  أرجع
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_5a(Eurydice_array_منزل_ٹکڑا_shared_98(signing_کلید),
      سنیہا,
      context,
      randomness);
}

/**
 Sign.
*/
ساكن مضمن core_نتیجہ_نتیجہ_53
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_sign_mut(
  ثابت Eurydice_arr_24 *signing_کلید,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_borrow_ٹکڑا_u8 context,
  Eurydice_arr_ec randomness,
  Eurydice_arr_0c *signature
)
{
  أرجع
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_mut_5a(Eurydice_array_منزل_ٹکڑا_shared_98(signing_کلید),
      سنیہا,
      context,
      randomness,
      signature);
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_65.sign_pre_hashed_mut
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4, libcrux_ml_dsa_pre_hash_SHAKE128_PH
with const generics

*/
ساكن KRML_MUSTINLINE core_نتیجہ_نتیجہ_53
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_pre_hashed_mut_3f(
  Eurydice_borrow_ٹکڑا_u8 signing_کلید,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_borrow_ٹکڑا_u8 context,
  Eurydice_mut_borrow_ٹکڑا_u8 pre_hash_بفر,
  Eurydice_arr_ec randomness,
  Eurydice_arr_0c *signature
)
{
  إذا (!(context.meta > LIBCRUX_ML_DSA_CONSTANTS_CONTEXT_MAX_LEN))
  {
    libcrux_ml_dsa_pre_hash_hash_30_83(سنیہا, pre_hash_بفر);
    core_نتیجہ_نتیجہ_a8
    uu____0 =
      libcrux_ml_dsa_pre_hash_new_88(context,
        (
          KRML_CLITERAL(core_option_Option_57){
            .ٹیگ = core_option_Some,
            .f0 = libcrux_ml_dsa_pre_hash_oid_30()
          }
        ));
    إذا (!(uu____0.ٹیگ == core_نتیجہ_Ok))
    {
      أرجع
        (
          KRML_CLITERAL(core_نتیجہ_نتیجہ_53){
            .ٹیگ = core_نتیجہ_Err,
            .f0 = libcrux_ml_dsa_types_SigningError_ContextTooLongError
          }
        );
    }
    libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
    libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
    أرجع
      libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_اندرونی_5a(signing_کلید,
        (
          KRML_CLITERAL(Eurydice_borrow_ٹکڑا_u8){
            .ptr = pre_hash_بفر.ptr,
            .meta = pre_hash_بفر.meta
          }
        ),
        (
          KRML_CLITERAL(core_option_Option_84){
            .ٹیگ = core_option_Some,
            .f0 = domain_separation_context
          }
        ),
        randomness,
        signature);
  }
  أرجع
    (
      KRML_CLITERAL(core_نتیجہ_نتیجہ_53){
        .ٹیگ = core_نتیجہ_Err,
        .f0 = libcrux_ml_dsa_types_SigningError_ContextTooLongError
      }
    );
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_65.sign_pre_hashed
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4, libcrux_ml_dsa_pre_hash_SHAKE128_PH
with const generics

*/
ساكن KRML_MUSTINLINE core_نتیجہ_نتیجہ_8c
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_pre_hashed_3f(
  Eurydice_borrow_ٹکڑا_u8 signing_کلید,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_borrow_ٹکڑا_u8 context,
  Eurydice_mut_borrow_ٹکڑا_u8 pre_hash_بفر,
  Eurydice_arr_ec randomness
)
{
  Eurydice_arr_0c signature = libcrux_ml_dsa_types_zero_c5_5c();
  core_نتیجہ_نتیجہ_53
  uu____0 =
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_pre_hashed_mut_3f(signing_کلید,
      سنیہا,
      context,
      pre_hash_بفر,
      randomness,
      &signature);
  core_نتیجہ_نتیجہ_8c uu____1;
  إذا (uu____0.ٹیگ == core_نتیجہ_Ok)
  {
    uu____1 =
      (
        KRML_CLITERAL(core_نتیجہ_نتیجہ_8c){
          .ٹیگ = core_نتیجہ_Ok,
          .val = { .case_Ok = signature }
        }
      );
  }
  وإلا
  {
    libcrux_ml_dsa_types_SigningError e = uu____0.f0;
    uu____1 =
      (KRML_CLITERAL(core_نتیجہ_نتیجہ_8c){ .ٹیگ = core_نتیجہ_Err, .val = { .case_Err = e } });
  }
  أرجع uu____1;
}

/**
 Sign (pre-hashed).
*/
ساكن مضمن core_نتیجہ_نتیجہ_8c
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_sign_pre_hashed_shake128(
  ثابت Eurydice_arr_24 *signing_کلید,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_borrow_ٹکڑا_u8 context,
  Eurydice_mut_borrow_ٹکڑا_u8 pre_hash_بفر,
  Eurydice_arr_ec randomness
)
{
  أرجع
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_pre_hashed_3f(Eurydice_array_منزل_ٹکڑا_shared_98(signing_کلید),
      سنیہا,
      context,
      pre_hash_بفر,
      randomness);
}

/**
 The internal verification API.

 If no `domain_separation_context` is supplied, it is assumed that
 `message` already contains the domain separation.
*/
/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_65.verify_internal
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof
with const generics

*/
ساكن KRML_MUSTINLINE core_نتیجہ_نتیجہ_41
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_verify_اندرونی_5a(
  ثابت Eurydice_arr_29 *verification_کلید,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  core_option_Option_84 domain_separation_context,
  ثابت Eurydice_arr_0c *signature_serialized
)
{
  Eurydice_borrow_ٹکڑا_u8_x2
  uu____0 =
    Eurydice_ٹکڑا_ونڈو_at(Eurydice_array_منزل_ٹکڑا_shared_37(verification_کلید),
      LIBCRUX_ML_DSA_CONSTANTS_بیج_FOR_A_ناپ,
      uint8_t,
      Eurydice_borrow_ٹکڑا_u8_x2);
  Eurydice_borrow_ٹکڑا_u8 بیج_for_a = uu____0.fst;
  Eurydice_borrow_ٹکڑا_u8 t1_serialized = uu____0.snd;
  Eurydice_arr_dc1 t1;
  Eurydice_arr_a3 repeat_expression0[6U];
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)6U; i++)
  {
    repeat_expression0[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  حافظہ_نقل(t1.انکڑے, repeat_expression0, (ناپ_t)6U * حجم (Eurydice_arr_a3));
  libcrux_ml_dsa_encoding_verification_کلید_deserialize_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_صفاں_وچ_A,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_VERIFICATION_کلید_ناپ,
    t1_serialized,
    Eurydice_array_منزل_ٹکڑا_mut_205(&t1));
  Eurydice_arr_65 deserialized_commitment_hash = { .انکڑے = { 0U } };
  Eurydice_arr_5d deserialized_signer_response;
  Eurydice_arr_a3 repeat_expression1[5U];
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)5U; i++)
  {
    repeat_expression1[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  حافظہ_نقل(deserialized_signer_response.انکڑے,
    repeat_expression1,
    (ناپ_t)5U * حجم (Eurydice_arr_a3));
  Eurydice_arr_5d0
  deserialized_hint =
    {
      .انکڑے = {
        { .انکڑے = { 0U } }, { .انکڑے = { 0U } }, { .انکڑے = { 0U } }, { .انکڑے = { 0U } },
        { .انکڑے = { 0U } }, { .انکڑے = { 0U } }
      }
    };
  core_نتیجہ_نتیجہ_41
  uu____1 =
    libcrux_ml_dsa_encoding_signature_deserialize_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_وچ_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_صفاں_وچ_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COMMITMENT_HASH_ناپ,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA1_EXPONENT,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_GAMMA1_RING_ELEMENT_ناپ,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_MAX_ONES_وچ_HINT,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_SIGNATURE_ناپ,
      Eurydice_array_منزل_ٹکڑا_shared_6b(signature_serialized),
      Eurydice_array_منزل_ٹکڑا_mut_9f(&deserialized_commitment_hash),
      Eurydice_array_منزل_ٹکڑا_mut_204(&deserialized_signer_response),
      Eurydice_array_منزل_ٹکڑا_mut_860(&deserialized_hint));
  core_نتیجہ_نتیجہ_41 uu____2;
  إذا (uu____1.ٹیگ == core_نتیجہ_Ok)
  {
    إذا
    (
      libcrux_ml_dsa_arithmetic_سمتیہ_infinity_norm_exceeds_37(Eurydice_array_منزل_ٹکڑا_shared_202(&deserialized_signer_response),
        (int32_t)((uint32_t)1 << (uint32_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA1_EXPONENT) -
          LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_BETA)
    )
    {
      uu____2 =
        (
          KRML_CLITERAL(core_نتیجہ_نتیجہ_41){
            .ٹیگ = core_نتیجہ_Err,
            .f0 = libcrux_ml_dsa_types_VerificationError_SignerResponseExceedsBoundError
          }
        );
    }
    وإلا
    {
      Eurydice_arr_5a میٹرکس;
      Eurydice_arr_a3 repeat_عبارت[30U];
      لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)30U; i++)
      {
        repeat_عبارت[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
      }
      حافظہ_نقل(میٹرکس.انکڑے, repeat_عبارت, (ناپ_t)30U * حجم (Eurydice_arr_a3));
      libcrux_ml_dsa_samplex4_portable_میٹرکس_flat_a8_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_وچ_A,
        بیج_for_a,
        Eurydice_array_منزل_ٹکڑا_mut_203(&میٹرکس));
      Eurydice_arr_c7 verification_کلید_hash = { .انکڑے = { 0U } };
      libcrux_ml_dsa_hash_functions_portable_shake256_61_c9(Eurydice_array_منزل_ٹکڑا_shared_37(verification_کلید),
        &verification_کلید_hash);
      Eurydice_arr_c7 سنیہا_representative = { .انکڑے = { 0U } };
      libcrux_ml_dsa_ml_dsa_generic_derive_سنیہا_representative_43(Eurydice_array_منزل_ٹکڑا_shared_17(&verification_کلید_hash),
        &domain_separation_context,
        سنیہا,
        &سنیہا_representative);
      Eurydice_arr_a3 verifier_challenge = libcrux_ml_dsa_polynomial_zero_ff_37();
      libcrux_ml_dsa_sample_sample_challenge_ring_element_2e(Eurydice_array_منزل_ٹکڑا_shared_9f0(&deserialized_commitment_hash),
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ONES_وچ_VERIFIER_CHALLENGE,
        &verifier_challenge);
      libcrux_ml_dsa_ntt_ntt_37(&verifier_challenge);
      لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)5U; i++)
      {
        ناپ_t i0 = i;
        libcrux_ml_dsa_ntt_ntt_37(&deserialized_signer_response.انکڑے[i0]);
      }
      libcrux_ml_dsa_میٹرکس_compute_w_approx_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_صفاں_وچ_A,
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_وچ_A,
        Eurydice_array_منزل_ٹکڑا_shared_205(&میٹرکس),
        Eurydice_array_منزل_ٹکڑا_shared_202(&deserialized_signer_response),
        &verifier_challenge,
        Eurydice_array_منزل_ٹکڑا_mut_205(&t1));
      Eurydice_arr_65 recomputed_commitment_hash = { .انکڑے = { 0U } };
      libcrux_ml_dsa_arithmetic_use_hint_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA2,
        Eurydice_array_منزل_ٹکڑا_shared_860(&deserialized_hint),
        Eurydice_array_منزل_ٹکڑا_mut_205(&t1));
      Eurydice_arr_d2 commitment_serialized = { .انکڑے = { 0U } };
      libcrux_ml_dsa_encoding_commitment_serialize_سمتیہ_37(LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_COMMITMENT_RING_ELEMENT_ناپ,
        Eurydice_array_منزل_ٹکڑا_shared_204(&t1),
        Eurydice_array_منزل_ٹکڑا_mut_27(&commitment_serialized));
      libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
      shake = libcrux_ml_dsa_hash_functions_portable_init_26();
      libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake,
        Eurydice_array_منزل_ٹکڑا_shared_17(&سنیہا_representative));
      libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake,
        Eurydice_array_منزل_ٹکڑا_shared_27(&commitment_serialized));
      libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake,
        Eurydice_array_منزل_ٹکڑا_mut_9f(&recomputed_commitment_hash));
      إذا
      (
        Eurydice_array_eq((ناپ_t)48U,
          &deserialized_commitment_hash,
          &recomputed_commitment_hash,
          uint8_t)
      )
      {
        uu____2 = (KRML_CLITERAL(core_نتیجہ_نتیجہ_41){ .ٹیگ = core_نتیجہ_Ok });
      }
      وإلا
      {
        uu____2 =
          (
            KRML_CLITERAL(core_نتیجہ_نتیجہ_41){
              .ٹیگ = core_نتیجہ_Err,
              .f0 = libcrux_ml_dsa_types_Verification_Error_Commitment_Hashes_Dont_میل_Error
            }
          );
      }
    }
  }
  وإلا
  {
    libcrux_ml_dsa_types_VerificationError e = uu____1.f0;
    uu____2 = (KRML_CLITERAL(core_نتیجہ_نتیجہ_41){ .ٹیگ = core_نتیجہ_Err, .f0 = e });
  }
  أرجع uu____2;
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_65.verify
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof
with const generics

*/
ساكن KRML_MUSTINLINE core_نتیجہ_نتیجہ_41
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_verify_5a(
  ثابت Eurydice_arr_29 *verification_کلید_serialized,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_borrow_ٹکڑا_u8 context,
  ثابت Eurydice_arr_0c *signature_serialized
)
{
  core_نتیجہ_نتیجہ_a8
  uu____0 =
    libcrux_ml_dsa_pre_hash_new_88(context,
      (KRML_CLITERAL(core_option_Option_57){ .ٹیگ = core_option_None }));
  إذا (!(uu____0.ٹیگ == core_نتیجہ_Ok))
  {
    أرجع
      (
        KRML_CLITERAL(core_نتیجہ_نتیجہ_41){
          .ٹیگ = core_نتیجہ_Err,
          .f0 = libcrux_ml_dsa_types_VerificationError_VerificationContextTooLongError
        }
      );
  }
  libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
  libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
  أرجع
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_verify_اندرونی_5a(verification_کلید_serialized,
      سنیہا,
      (
        KRML_CLITERAL(core_option_Option_84){
          .ٹیگ = core_option_Some,
          .f0 = domain_separation_context
        }
      ),
      signature_serialized);
}

/**
 Verify.
*/
ساكن مضمن core_نتیجہ_نتیجہ_41
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_verify(
  ثابت Eurydice_arr_29 *verification_کلید,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_borrow_ٹکڑا_u8 context,
  ثابت Eurydice_arr_0c *signature
)
{
  أرجع
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_verify_5a(verification_کلید,
      سنیہا,
      context,
      signature);
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_65.verify_pre_hashed
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_pre_hash_SHAKE128_PH
with const generics

*/
ساكن KRML_MUSTINLINE core_نتیجہ_نتیجہ_41
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_verify_pre_hashed_3f(
  ثابت Eurydice_arr_29 *verification_کلید_serialized,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_borrow_ٹکڑا_u8 context,
  Eurydice_mut_borrow_ٹکڑا_u8 pre_hash_بفر,
  ثابت Eurydice_arr_0c *signature_serialized
)
{
  libcrux_ml_dsa_pre_hash_hash_30_83(سنیہا, pre_hash_بفر);
  core_نتیجہ_نتیجہ_a8
  uu____0 =
    libcrux_ml_dsa_pre_hash_new_88(context,
      (
        KRML_CLITERAL(core_option_Option_57){
          .ٹیگ = core_option_Some,
          .f0 = libcrux_ml_dsa_pre_hash_oid_30()
        }
      ));
  إذا (!(uu____0.ٹیگ == core_نتیجہ_Ok))
  {
    أرجع
      (
        KRML_CLITERAL(core_نتیجہ_نتیجہ_41){
          .ٹیگ = core_نتیجہ_Err,
          .f0 = libcrux_ml_dsa_types_VerificationError_VerificationContextTooLongError
        }
      );
  }
  libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
  libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
  أرجع
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_verify_اندرونی_5a(verification_کلید_serialized,
      (
        KRML_CLITERAL(Eurydice_borrow_ٹکڑا_u8){
          .ptr = pre_hash_بفر.ptr,
          .meta = pre_hash_بفر.meta
        }
      ),
      (
        KRML_CLITERAL(core_option_Option_84){
          .ٹیگ = core_option_Some,
          .f0 = domain_separation_context
        }
      ),
      signature_serialized);
}

/**
 Verify (pre-hashed with SHAKE-128).
*/
ساكن مضمن core_نتیجہ_نتیجہ_41
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_verify_pre_hashed_shake128(
  ثابت Eurydice_arr_29 *verification_کلید,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_borrow_ٹکڑا_u8 context,
  Eurydice_mut_borrow_ٹکڑا_u8 pre_hash_بفر,
  ثابت Eurydice_arr_0c *signature
)
{
  أرجع
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_verify_pre_hashed_3f(verification_کلید,
      سنیہا,
      context,
      pre_hash_بفر,
      signature);
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_87.generate_key_pair
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_generate_کلید_pair_5a(
  Eurydice_arr_ec randomness,
  Eurydice_mut_borrow_ٹکڑا_u8 signing_کلید,
  Eurydice_mut_borrow_ٹکڑا_u8 verification_کلید
)
{
  Eurydice_arr_89 بیج_expanded0 = { .انکڑے = { 0U } };
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
  shake = libcrux_ml_dsa_hash_functions_portable_init_26();
  libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake,
    Eurydice_array_منزل_ٹکڑا_shared_01(&randomness));
  /* original Rust expression is not an lvalue in C */
  Eurydice_array_u8x2
  lvalue =
    {
      .انکڑے = {
        (uint8_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_صفاں_وچ_A,
        (uint8_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_وچ_A
      }
    };
  libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake,
    Eurydice_array_منزل_ٹکڑا_shared_82(&lvalue));
  libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake,
    Eurydice_array_منزل_ٹکڑا_mut_78(&بیج_expanded0));
  Eurydice_borrow_ٹکڑا_u8_x2
  uu____0 =
    Eurydice_ٹکڑا_ونڈو_at(Eurydice_array_منزل_ٹکڑا_shared_78(&بیج_expanded0),
      LIBCRUX_ML_DSA_CONSTANTS_بیج_FOR_A_ناپ,
      uint8_t,
      Eurydice_borrow_ٹکڑا_u8_x2);
  Eurydice_borrow_ٹکڑا_u8 بیج_for_a = uu____0.fst;
  Eurydice_borrow_ٹکڑا_u8 بیج_expanded = uu____0.snd;
  Eurydice_borrow_ٹکڑا_u8_x2
  uu____1 =
    Eurydice_ٹکڑا_ونڈو_at(بیج_expanded,
      LIBCRUX_ML_DSA_CONSTANTS_بیج_FOR_ERROR_VECTORS_ناپ,
      uint8_t,
      Eurydice_borrow_ٹکڑا_u8_x2);
  Eurydice_borrow_ٹکڑا_u8 بیج_for_error_vectors = uu____1.fst;
  Eurydice_borrow_ٹکڑا_u8 بیج_for_signing = uu____1.snd;
  Eurydice_arr_92 s1_s2;
  Eurydice_arr_a3 repeat_expression0[15U];
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)15U; i++)
  {
    repeat_expression0[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  حافظہ_نقل(s1_s2.انکڑے, repeat_expression0, (ناپ_t)15U * حجم (Eurydice_arr_a3));
  libcrux_ml_dsa_samplex4_sample_s1_and_s2_29(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ETA,
    بیج_for_error_vectors,
    Eurydice_array_منزل_ٹکڑا_mut_206(&s1_s2));
  Eurydice_arr_8f t0;
  Eurydice_arr_a3 repeat_expression1[8U];
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)8U; i++)
  {
    repeat_expression1[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  حافظہ_نقل(t0.انکڑے, repeat_expression1, (ناپ_t)8U * حجم (Eurydice_arr_a3));
  Eurydice_arr_0f a_as_ntt;
  Eurydice_arr_a3 repeat_expression2[56U];
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)56U; i++)
  {
    repeat_expression2[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  حافظہ_نقل(a_as_ntt.انکڑے, repeat_expression2, (ناپ_t)56U * حجم (Eurydice_arr_a3));
  libcrux_ml_dsa_samplex4_portable_میٹرکس_flat_a8_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_وچ_A,
    بیج_for_a,
    Eurydice_array_منزل_ٹکڑا_mut_207(&a_as_ntt));
  Eurydice_arr_bb s1_ntt;
  Eurydice_arr_a3 repeat_expression3[7U];
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)7U; i++)
  {
    repeat_expression3[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  حافظہ_نقل(s1_ntt.انکڑے, repeat_expression3, (ناپ_t)7U * حجم (Eurydice_arr_a3));
  Eurydice_ٹکڑا_copy(Eurydice_array_منزل_ٹکڑا_mut_208(&s1_ntt),
    Eurydice_array_منزل_subslice_shared_251(&s1_s2,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .شروع = (ناپ_t)0U,
          .سرا = LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_وچ_A
        }
      )),
    Eurydice_arr_a3);
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)7U; i++)
  {
    ناپ_t i0 = i;
    libcrux_ml_dsa_ntt_ntt_37(&s1_ntt.انکڑے[i0]);
  }
  libcrux_ml_dsa_میٹرکس_compute_as1_plus_s2_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_صفاں_وچ_A,
    LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_وچ_A,
    Eurydice_array_منزل_ٹکڑا_mut_207(&a_as_ntt),
    Eurydice_array_منزل_ٹکڑا_shared_206(&s1_ntt),
    Eurydice_array_منزل_ٹکڑا_shared_207(&s1_s2),
    Eurydice_array_منزل_ٹکڑا_mut_20(&t0));
  Eurydice_arr_8f t1;
  Eurydice_arr_a3 repeat_عبارت[8U];
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)8U; i++)
  {
    repeat_عبارت[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  حافظہ_نقل(t1.انکڑے, repeat_عبارت, (ناپ_t)8U * حجم (Eurydice_arr_a3));
  libcrux_ml_dsa_arithmetic_power2round_سمتیہ_37(Eurydice_array_منزل_ٹکڑا_mut_20(&t0),
    Eurydice_array_منزل_ٹکڑا_mut_20(&t1));
  libcrux_ml_dsa_encoding_verification_کلید_generate_serialized_37(بیج_for_a,
    Eurydice_array_منزل_ٹکڑا_shared_200(&t1),
    verification_کلید);
  libcrux_ml_dsa_encoding_signing_کلید_generate_serialized_2e(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ETA,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_ERROR_RING_ELEMENT_ناپ,
    بیج_for_a,
    بیج_for_signing,
    (
      KRML_CLITERAL(Eurydice_borrow_ٹکڑا_u8){
        .ptr = verification_کلید.ptr,
        .meta = verification_کلید.meta
      }
    ),
    Eurydice_array_منزل_ٹکڑا_shared_207(&s1_s2),
    Eurydice_array_منزل_ٹکڑا_shared_200(&t0),
    signing_کلید);
}

/**
 Generate key pair.
*/
ساكن مضمن فراغ
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_87_generate_کلید_pair(
  Eurydice_arr_ec randomness,
  Eurydice_arr_e2 *signing_کلید,
  Eurydice_arr_43 *verification_کلید
)
{
  libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_generate_کلید_pair_5a(randomness,
    Eurydice_array_منزل_ٹکڑا_mut_f7(signing_کلید),
    Eurydice_array_منزل_ٹکڑا_mut_fc(verification_کلید));
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_87.sign_internal
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
ساكن KRML_MUSTINLINE core_نتیجہ_نتیجہ_53
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_sign_اندرونی_5a(
  Eurydice_borrow_ٹکڑا_u8 signing_کلید,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  core_option_Option_84 domain_separation_context,
  Eurydice_arr_ec randomness,
  Eurydice_arr_93 *signature
)
{
  Eurydice_borrow_ٹکڑا_u8_x2
  uu____0 =
    Eurydice_ٹکڑا_ونڈو_at(signing_کلید,
      LIBCRUX_ML_DSA_CONSTANTS_بیج_FOR_A_ناپ,
      uint8_t,
      Eurydice_borrow_ٹکڑا_u8_x2);
  Eurydice_borrow_ٹکڑا_u8 بیج_for_a = uu____0.fst;
  Eurydice_borrow_ٹکڑا_u8 بچیا_serialized0 = uu____0.snd;
  Eurydice_borrow_ٹکڑا_u8_x2
  uu____1 =
    Eurydice_ٹکڑا_ونڈو_at(بچیا_serialized0,
      LIBCRUX_ML_DSA_CONSTANTS_بیج_FOR_SIGNING_ناپ,
      uint8_t,
      Eurydice_borrow_ٹکڑا_u8_x2);
  Eurydice_borrow_ٹکڑا_u8 بیج_for_signing = uu____1.fst;
  Eurydice_borrow_ٹکڑا_u8 بچیا_serialized1 = uu____1.snd;
  Eurydice_borrow_ٹکڑا_u8_x2
  uu____2 =
    Eurydice_ٹکڑا_ونڈو_at(بچیا_serialized1,
      LIBCRUX_ML_DSA_CONSTANTS_بائٹاں_FOR_VERIFICATION_کلید_HASH,
      uint8_t,
      Eurydice_borrow_ٹکڑا_u8_x2);
  Eurydice_borrow_ٹکڑا_u8 verification_کلید_hash = uu____2.fst;
  Eurydice_borrow_ٹکڑا_u8 بچیا_serialized2 = uu____2.snd;
  Eurydice_borrow_ٹکڑا_u8_x2
  uu____3 =
    Eurydice_ٹکڑا_ونڈو_at(بچیا_serialized2,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_ERROR_RING_ELEMENT_ناپ *
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_وچ_A,
      uint8_t,
      Eurydice_borrow_ٹکڑا_u8_x2);
  Eurydice_borrow_ٹکڑا_u8 s1_serialized = uu____3.fst;
  Eurydice_borrow_ٹکڑا_u8 بچیا_serialized = uu____3.snd;
  Eurydice_borrow_ٹکڑا_u8_x2
  uu____4 =
    Eurydice_ٹکڑا_ونڈو_at(بچیا_serialized,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_ERROR_RING_ELEMENT_ناپ *
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_صفاں_وچ_A,
      uint8_t,
      Eurydice_borrow_ٹکڑا_u8_x2);
  Eurydice_borrow_ٹکڑا_u8 s2_serialized = uu____4.fst;
  Eurydice_borrow_ٹکڑا_u8 t0_serialized = uu____4.snd;
  Eurydice_arr_bb s1_as_ntt;
  Eurydice_arr_a3 repeat_expression0[7U];
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)7U; i++)
  {
    repeat_expression0[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  حافظہ_نقل(s1_as_ntt.انکڑے, repeat_expression0, (ناپ_t)7U * حجم (Eurydice_arr_a3));
  Eurydice_arr_8f s2_as_ntt;
  Eurydice_arr_a3 repeat_expression1[8U];
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)8U; i++)
  {
    repeat_expression1[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  حافظہ_نقل(s2_as_ntt.انکڑے, repeat_expression1, (ناپ_t)8U * حجم (Eurydice_arr_a3));
  Eurydice_arr_8f t0_as_ntt;
  Eurydice_arr_a3 repeat_expression2[8U];
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)8U; i++)
  {
    repeat_expression2[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  حافظہ_نقل(t0_as_ntt.انکڑے, repeat_expression2, (ناپ_t)8U * حجم (Eurydice_arr_a3));
  libcrux_ml_dsa_encoding_error_deserialize_منزل_سمتیہ_then_ntt_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ETA,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_ERROR_RING_ELEMENT_ناپ,
    s1_serialized,
    Eurydice_array_منزل_ٹکڑا_mut_208(&s1_as_ntt));
  libcrux_ml_dsa_encoding_error_deserialize_منزل_سمتیہ_then_ntt_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ETA,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_ERROR_RING_ELEMENT_ناپ,
    s2_serialized,
    Eurydice_array_منزل_ٹکڑا_mut_20(&s2_as_ntt));
  libcrux_ml_dsa_encoding_t0_deserialize_منزل_سمتیہ_then_ntt_37(t0_serialized,
    Eurydice_array_منزل_ٹکڑا_mut_20(&t0_as_ntt));
  Eurydice_arr_0f میٹرکس;
  Eurydice_arr_a3 repeat_expression3[56U];
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)56U; i++)
  {
    repeat_expression3[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  حافظہ_نقل(میٹرکس.انکڑے, repeat_expression3, (ناپ_t)56U * حجم (Eurydice_arr_a3));
  libcrux_ml_dsa_samplex4_portable_میٹرکس_flat_a8_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_وچ_A,
    بیج_for_a,
    Eurydice_array_منزل_ٹکڑا_mut_207(&میٹرکس));
  Eurydice_arr_c7 سنیہا_representative = { .انکڑے = { 0U } };
  libcrux_ml_dsa_ml_dsa_generic_derive_سنیہا_representative_43(verification_کلید_hash,
    &domain_separation_context,
    سنیہا,
    &سنیہا_representative);
  Eurydice_arr_c7 نقاب_بیج = { .انکڑے = { 0U } };
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
  shake0 = libcrux_ml_dsa_hash_functions_portable_init_26();
  libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake0, بیج_for_signing);
  libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake0,
    Eurydice_array_منزل_ٹکڑا_shared_01(&randomness));
  libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake0,
    Eurydice_array_منزل_ٹکڑا_shared_17(&سنیہا_representative));
  libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake0,
    Eurydice_array_منزل_ٹکڑا_mut_17(&نقاب_بیج));
  uint16_t domain_separator_for_نقاب = 0U;
  ناپ_t attempt = (ناپ_t)0U;
  core_option_Option_b2 commitment_hash0 = { .ٹیگ = core_option_None };
  core_option_Option_2d signer_response0 = { .ٹیگ = core_option_None };
  core_option_Option_45 hint0 = { .ٹیگ = core_option_None };
  طالما (attempt < LIBCRUX_ML_DSA_CONSTANTS_REJECTION_SAMPLE_BOUND_SIGN)
  {
    attempt++;
    Eurydice_arr_bb نقاب;
    Eurydice_arr_a3 repeat_expression4[7U];
    لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)7U; i++)
    {
      repeat_expression4[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    حافظہ_نقل(نقاب.انکڑے, repeat_expression4, (ناپ_t)7U * حجم (Eurydice_arr_a3));
    Eurydice_arr_8f w0;
    Eurydice_arr_a3 repeat_expression5[8U];
    لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)8U; i++)
    {
      repeat_expression5[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    حافظہ_نقل(w0.انکڑے, repeat_expression5, (ناپ_t)8U * حجم (Eurydice_arr_a3));
    Eurydice_arr_8f commitment;
    Eurydice_arr_a3 repeat_expression6[8U];
    لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)8U; i++)
    {
      repeat_expression6[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    حافظہ_نقل(commitment.انکڑے, repeat_expression6, (ناپ_t)8U * حجم (Eurydice_arr_a3));
    libcrux_ml_dsa_sample_sample_نقاب_سمتیہ_67(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_وچ_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_GAMMA1_EXPONENT,
      &نقاب_بیج,
      &domain_separator_for_نقاب,
      Eurydice_array_منزل_ٹکڑا_mut_208(&نقاب));
    Eurydice_arr_8f a_x_نقاب;
    Eurydice_arr_a3 repeat_عبارت[8U];
    لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)8U; i++)
    {
      repeat_عبارت[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    حافظہ_نقل(a_x_نقاب.انکڑے, repeat_عبارت, (ناپ_t)8U * حجم (Eurydice_arr_a3));
    Eurydice_arr_bb
    نقاب_ntt =
      core_array__core__clone__Clone_for__T__N___clone((ناپ_t)7U,
        &نقاب,
        Eurydice_arr_a3,
        Eurydice_arr_bb);
    لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)7U; i++)
    {
      ناپ_t i0 = i;
      libcrux_ml_dsa_ntt_ntt_37(&نقاب_ntt.انکڑے[i0]);
    }
    libcrux_ml_dsa_میٹرکس_compute_میٹرکس_x_نقاب_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_صفاں_وچ_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_وچ_A,
      Eurydice_array_منزل_ٹکڑا_shared_208(&میٹرکس),
      Eurydice_array_منزل_ٹکڑا_shared_206(&نقاب_ntt),
      Eurydice_array_منزل_ٹکڑا_mut_20(&a_x_نقاب));
    libcrux_ml_dsa_arithmetic_decompose_سمتیہ_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_صفاں_وچ_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_GAMMA2,
      Eurydice_array_منزل_ٹکڑا_shared_200(&a_x_نقاب),
      Eurydice_array_منزل_ٹکڑا_mut_20(&w0),
      Eurydice_array_منزل_ٹکڑا_mut_20(&commitment));
    Eurydice_arr_c7 commitment_hash_candidate = { .انکڑے = { 0U } };
    Eurydice_arr_1b commitment_serialized = { .انکڑے = { 0U } };
    libcrux_ml_dsa_encoding_commitment_serialize_سمتیہ_37(LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_COMMITMENT_RING_ELEMENT_ناپ,
      Eurydice_array_منزل_ٹکڑا_shared_200(&commitment),
      Eurydice_array_منزل_ٹکڑا_mut_68(&commitment_serialized));
    libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
    shake = libcrux_ml_dsa_hash_functions_portable_init_26();
    libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake,
      Eurydice_array_منزل_ٹکڑا_shared_17(&سنیہا_representative));
    libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake,
      Eurydice_array_منزل_ٹکڑا_shared_68(&commitment_serialized));
    libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake,
      Eurydice_array_منزل_ٹکڑا_mut_17(&commitment_hash_candidate));
    Eurydice_arr_a3 verifier_challenge = libcrux_ml_dsa_polynomial_zero_ff_37();
    libcrux_ml_dsa_sample_sample_challenge_ring_element_2e(Eurydice_array_منزل_ٹکڑا_shared_17(&commitment_hash_candidate),
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ONES_وچ_VERIFIER_CHALLENGE,
      &verifier_challenge);
    libcrux_ml_dsa_ntt_ntt_37(&verifier_challenge);
    Eurydice_arr_bb
    challenge_times_s1 =
      core_array__core__clone__Clone_for__T__N___clone((ناپ_t)7U,
        &s1_as_ntt,
        Eurydice_arr_a3,
        Eurydice_arr_bb);
    Eurydice_arr_8f
    challenge_times_s2 =
      core_array__core__clone__Clone_for__T__N___clone((ناپ_t)8U,
        &s2_as_ntt,
        Eurydice_arr_a3,
        Eurydice_arr_8f);
    libcrux_ml_dsa_میٹرکس_سمتیہ_times_ring_element_37(Eurydice_array_منزل_ٹکڑا_mut_208(&challenge_times_s1),
      &verifier_challenge);
    libcrux_ml_dsa_میٹرکس_سمتیہ_times_ring_element_37(Eurydice_array_منزل_ٹکڑا_mut_20(&challenge_times_s2),
      &verifier_challenge);
    libcrux_ml_dsa_میٹرکس_جوڑو_vectors_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_وچ_A,
      Eurydice_array_منزل_ٹکڑا_mut_208(&نقاب),
      Eurydice_array_منزل_ٹکڑا_shared_206(&challenge_times_s1));
    libcrux_ml_dsa_میٹرکس_گھٹاؤ_vectors_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_صفاں_وچ_A,
      Eurydice_array_منزل_ٹکڑا_mut_20(&w0),
      Eurydice_array_منزل_ٹکڑا_shared_200(&challenge_times_s2));
    إذا
    (
      !libcrux_ml_dsa_arithmetic_سمتیہ_infinity_norm_exceeds_37(Eurydice_array_منزل_ٹکڑا_shared_206(&نقاب),
        (int32_t)((uint32_t)1 << (uint32_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_GAMMA1_EXPONENT) -
          LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_BETA)
    )
    {
      إذا
      (
        !libcrux_ml_dsa_arithmetic_سمتیہ_infinity_norm_exceeds_37(Eurydice_array_منزل_ٹکڑا_shared_200(&w0),
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_GAMMA2 - LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_BETA)
      )
      {
        Eurydice_arr_8f
        challenge_times_t0 =
          core_array__core__clone__Clone_for__T__N___clone((ناپ_t)8U,
            &t0_as_ntt,
            Eurydice_arr_a3,
            Eurydice_arr_8f);
        libcrux_ml_dsa_میٹرکس_سمتیہ_times_ring_element_37(Eurydice_array_منزل_ٹکڑا_mut_20(&challenge_times_t0),
          &verifier_challenge);
        إذا
        (
          !libcrux_ml_dsa_arithmetic_سمتیہ_infinity_norm_exceeds_37(Eurydice_array_منزل_ٹکڑا_shared_200(&challenge_times_t0),
            LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_GAMMA2)
        )
        {
          libcrux_ml_dsa_میٹرکس_جوڑو_vectors_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_صفاں_وچ_A,
            Eurydice_array_منزل_ٹکڑا_mut_20(&w0),
            Eurydice_array_منزل_ٹکڑا_shared_200(&challenge_times_t0));
          Eurydice_arr_81
          hint_candidate =
            {
              .انکڑے = {
                { .انکڑے = { 0U } }, { .انکڑے = { 0U } }, { .انکڑے = { 0U } }, { .انکڑے = { 0U } },
                { .انکڑے = { 0U } }, { .انکڑے = { 0U } }, { .انکڑے = { 0U } }, { .انکڑے = { 0U } }
              }
            };
          ناپ_t
          ones_وچ_hint =
            libcrux_ml_dsa_arithmetic_make_hint_37(Eurydice_array_منزل_ٹکڑا_shared_200(&w0),
              Eurydice_array_منزل_ٹکڑا_shared_200(&commitment),
              LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_GAMMA2,
              Eurydice_array_منزل_ٹکڑا_mut_861(&hint_candidate));
          إذا (!(ones_وچ_hint > LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_MAX_ONES_وچ_HINT))
          {
            attempt = LIBCRUX_ML_DSA_CONSTANTS_REJECTION_SAMPLE_BOUND_SIGN;
            commitment_hash0 =
              (
                KRML_CLITERAL(core_option_Option_b2){
                  .ٹیگ = core_option_Some,
                  .f0 = commitment_hash_candidate
                }
              );
            signer_response0 =
              (KRML_CLITERAL(core_option_Option_2d){ .ٹیگ = core_option_Some, .f0 = نقاب });
            hint0 =
              (
                KRML_CLITERAL(core_option_Option_45){
                  .ٹیگ = core_option_Some,
                  .f0 = hint_candidate
                }
              );
          }
        }
      }
    }
  }
  core_نتیجہ_نتیجہ_53 uu____5;
  إذا (commitment_hash0.ٹیگ == core_option_None)
  {
    uu____5 =
      (
        KRML_CLITERAL(core_نتیجہ_نتیجہ_53){
          .ٹیگ = core_نتیجہ_Err,
          .f0 = libcrux_ml_dsa_types_SigningError_RejectionSamplingError
        }
      );
  }
  وإلا
  {
    Eurydice_arr_c7 commitment_hash = commitment_hash0.f0;
    Eurydice_arr_c7 commitment_hash1 = commitment_hash;
    إذا (signer_response0.ٹیگ == core_option_None)
    {
      uu____5 =
        (
          KRML_CLITERAL(core_نتیجہ_نتیجہ_53){
            .ٹیگ = core_نتیجہ_Err,
            .f0 = libcrux_ml_dsa_types_SigningError_RejectionSamplingError
          }
        );
    }
    وإلا
    {
      Eurydice_arr_bb signer_response = signer_response0.f0;
      Eurydice_arr_bb signer_response1 = signer_response;
      إذا (!(hint0.ٹیگ == core_option_None))
      {
        Eurydice_arr_81 hint = hint0.f0;
        Eurydice_arr_81 hint1 = hint;
        libcrux_ml_dsa_encoding_signature_serialize_37(Eurydice_array_منزل_ٹکڑا_shared_17(&commitment_hash1),
          Eurydice_array_منزل_ٹکڑا_shared_206(&signer_response1),
          Eurydice_array_منزل_ٹکڑا_shared_861(&hint1),
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COMMITMENT_HASH_ناپ,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_وچ_A,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_صفاں_وچ_A,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_GAMMA1_EXPONENT,
          LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_GAMMA1_RING_ELEMENT_ناپ,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_MAX_ONES_وچ_HINT,
          Eurydice_array_منزل_ٹکڑا_mut_11(signature));
        أرجع (KRML_CLITERAL(core_نتیجہ_نتیجہ_53){ .ٹیگ = core_نتیجہ_Ok });
      }
      uu____5 =
        (
          KRML_CLITERAL(core_نتیجہ_نتیجہ_53){
            .ٹیگ = core_نتیجہ_Err,
            .f0 = libcrux_ml_dsa_types_SigningError_RejectionSamplingError
          }
        );
    }
  }
  أرجع uu____5;
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_87.sign_mut
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
ساكن KRML_MUSTINLINE core_نتیجہ_نتیجہ_53
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_sign_mut_5a(
  Eurydice_borrow_ٹکڑا_u8 signing_کلید,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_borrow_ٹکڑا_u8 context,
  Eurydice_arr_ec randomness,
  Eurydice_arr_93 *signature
)
{
  core_نتیجہ_نتیجہ_a8
  uu____0 =
    libcrux_ml_dsa_pre_hash_new_88(context,
      (KRML_CLITERAL(core_option_Option_57){ .ٹیگ = core_option_None }));
  إذا (!(uu____0.ٹیگ == core_نتیجہ_Ok))
  {
    أرجع
      (
        KRML_CLITERAL(core_نتیجہ_نتیجہ_53){
          .ٹیگ = core_نتیجہ_Err,
          .f0 = libcrux_ml_dsa_types_SigningError_ContextTooLongError
        }
      );
  }
  libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
  libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
  أرجع
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_sign_اندرونی_5a(signing_کلید,
      سنیہا,
      (
        KRML_CLITERAL(core_option_Option_84){
          .ٹیگ = core_option_Some,
          .f0 = domain_separation_context
        }
      ),
      randomness,
      signature);
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_87.sign
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
ساكن KRML_MUSTINLINE core_نتیجہ_نتیجہ_8b
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_sign_5a(
  Eurydice_borrow_ٹکڑا_u8 signing_کلید,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_borrow_ٹکڑا_u8 context,
  Eurydice_arr_ec randomness
)
{
  Eurydice_arr_93 signature = libcrux_ml_dsa_types_zero_c5_f1();
  core_نتیجہ_نتیجہ_53
  uu____0 =
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_sign_mut_5a(signing_کلید,
      سنیہا,
      context,
      randomness,
      &signature);
  core_نتیجہ_نتیجہ_8b uu____1;
  إذا (uu____0.ٹیگ == core_نتیجہ_Ok)
  {
    uu____1 =
      (
        KRML_CLITERAL(core_نتیجہ_نتیجہ_8b){
          .ٹیگ = core_نتیجہ_Ok,
          .val = { .case_Ok = signature }
        }
      );
  }
  وإلا
  {
    libcrux_ml_dsa_types_SigningError e = uu____0.f0;
    uu____1 =
      (KRML_CLITERAL(core_نتیجہ_نتیجہ_8b){ .ٹیگ = core_نتیجہ_Err, .val = { .case_Err = e } });
  }
  أرجع uu____1;
}

/**
 Sign.
*/
ساكن مضمن core_نتیجہ_نتیجہ_8b
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_87_sign(
  ثابت Eurydice_arr_e2 *signing_کلید,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_borrow_ٹکڑا_u8 context,
  Eurydice_arr_ec randomness
)
{
  أرجع
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_sign_5a(Eurydice_array_منزل_ٹکڑا_shared_f7(signing_کلید),
      سنیہا,
      context,
      randomness);
}

/**
 Sign.
*/
ساكن مضمن core_نتیجہ_نتیجہ_53
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_87_sign_mut(
  ثابت Eurydice_arr_e2 *signing_کلید,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_borrow_ٹکڑا_u8 context,
  Eurydice_arr_ec randomness,
  Eurydice_arr_93 *signature
)
{
  أرجع
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_sign_mut_5a(Eurydice_array_منزل_ٹکڑا_shared_f7(signing_کلید),
      سنیہا,
      context,
      randomness,
      signature);
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_87.sign_pre_hashed_mut
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4, libcrux_ml_dsa_pre_hash_SHAKE128_PH
with const generics

*/
ساكن KRML_MUSTINLINE core_نتیجہ_نتیجہ_53
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_sign_pre_hashed_mut_3f(
  Eurydice_borrow_ٹکڑا_u8 signing_کلید,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_borrow_ٹکڑا_u8 context,
  Eurydice_mut_borrow_ٹکڑا_u8 pre_hash_بفر,
  Eurydice_arr_ec randomness,
  Eurydice_arr_93 *signature
)
{
  إذا (!(context.meta > LIBCRUX_ML_DSA_CONSTANTS_CONTEXT_MAX_LEN))
  {
    libcrux_ml_dsa_pre_hash_hash_30_83(سنیہا, pre_hash_بفر);
    core_نتیجہ_نتیجہ_a8
    uu____0 =
      libcrux_ml_dsa_pre_hash_new_88(context,
        (
          KRML_CLITERAL(core_option_Option_57){
            .ٹیگ = core_option_Some,
            .f0 = libcrux_ml_dsa_pre_hash_oid_30()
          }
        ));
    إذا (!(uu____0.ٹیگ == core_نتیجہ_Ok))
    {
      أرجع
        (
          KRML_CLITERAL(core_نتیجہ_نتیجہ_53){
            .ٹیگ = core_نتیجہ_Err,
            .f0 = libcrux_ml_dsa_types_SigningError_ContextTooLongError
          }
        );
    }
    libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
    libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
    أرجع
      libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_sign_اندرونی_5a(signing_کلید,
        (
          KRML_CLITERAL(Eurydice_borrow_ٹکڑا_u8){
            .ptr = pre_hash_بفر.ptr,
            .meta = pre_hash_بفر.meta
          }
        ),
        (
          KRML_CLITERAL(core_option_Option_84){
            .ٹیگ = core_option_Some,
            .f0 = domain_separation_context
          }
        ),
        randomness,
        signature);
  }
  أرجع
    (
      KRML_CLITERAL(core_نتیجہ_نتیجہ_53){
        .ٹیگ = core_نتیجہ_Err,
        .f0 = libcrux_ml_dsa_types_SigningError_ContextTooLongError
      }
    );
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_87.sign_pre_hashed
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4, libcrux_ml_dsa_pre_hash_SHAKE128_PH
with const generics

*/
ساكن KRML_MUSTINLINE core_نتیجہ_نتیجہ_8b
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_sign_pre_hashed_3f(
  Eurydice_borrow_ٹکڑا_u8 signing_کلید,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_borrow_ٹکڑا_u8 context,
  Eurydice_mut_borrow_ٹکڑا_u8 pre_hash_بفر,
  Eurydice_arr_ec randomness
)
{
  Eurydice_arr_93 signature = libcrux_ml_dsa_types_zero_c5_f1();
  core_نتیجہ_نتیجہ_53
  uu____0 =
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_sign_pre_hashed_mut_3f(signing_کلید,
      سنیہا,
      context,
      pre_hash_بفر,
      randomness,
      &signature);
  core_نتیجہ_نتیجہ_8b uu____1;
  إذا (uu____0.ٹیگ == core_نتیجہ_Ok)
  {
    uu____1 =
      (
        KRML_CLITERAL(core_نتیجہ_نتیجہ_8b){
          .ٹیگ = core_نتیجہ_Ok,
          .val = { .case_Ok = signature }
        }
      );
  }
  وإلا
  {
    libcrux_ml_dsa_types_SigningError e = uu____0.f0;
    uu____1 =
      (KRML_CLITERAL(core_نتیجہ_نتیجہ_8b){ .ٹیگ = core_نتیجہ_Err, .val = { .case_Err = e } });
  }
  أرجع uu____1;
}

/**
 Sign (pre-hashed).
*/
ساكن مضمن core_نتیجہ_نتیجہ_8b
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_87_sign_pre_hashed_shake128(
  ثابت Eurydice_arr_e2 *signing_کلید,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_borrow_ٹکڑا_u8 context,
  Eurydice_mut_borrow_ٹکڑا_u8 pre_hash_بفر,
  Eurydice_arr_ec randomness
)
{
  أرجع
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_sign_pre_hashed_3f(Eurydice_array_منزل_ٹکڑا_shared_f7(signing_کلید),
      سنیہا,
      context,
      pre_hash_بفر,
      randomness);
}

/**
 The internal verification API.

 If no `domain_separation_context` is supplied, it is assumed that
 `message` already contains the domain separation.
*/
/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_87.verify_internal
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof
with const generics

*/
ساكن KRML_MUSTINLINE core_نتیجہ_نتیجہ_41
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_verify_اندرونی_5a(
  ثابت Eurydice_arr_43 *verification_کلید,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  core_option_Option_84 domain_separation_context,
  ثابت Eurydice_arr_93 *signature_serialized
)
{
  Eurydice_borrow_ٹکڑا_u8_x2
  uu____0 =
    Eurydice_ٹکڑا_ونڈو_at(Eurydice_array_منزل_ٹکڑا_shared_fc(verification_کلید),
      LIBCRUX_ML_DSA_CONSTANTS_بیج_FOR_A_ناپ,
      uint8_t,
      Eurydice_borrow_ٹکڑا_u8_x2);
  Eurydice_borrow_ٹکڑا_u8 بیج_for_a = uu____0.fst;
  Eurydice_borrow_ٹکڑا_u8 t1_serialized = uu____0.snd;
  Eurydice_arr_8f t1;
  Eurydice_arr_a3 repeat_expression0[8U];
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)8U; i++)
  {
    repeat_expression0[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  حافظہ_نقل(t1.انکڑے, repeat_expression0, (ناپ_t)8U * حجم (Eurydice_arr_a3));
  libcrux_ml_dsa_encoding_verification_کلید_deserialize_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_صفاں_وچ_A,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_VERIFICATION_کلید_ناپ,
    t1_serialized,
    Eurydice_array_منزل_ٹکڑا_mut_20(&t1));
  Eurydice_arr_c7 deserialized_commitment_hash = { .انکڑے = { 0U } };
  Eurydice_arr_bb deserialized_signer_response;
  Eurydice_arr_a3 repeat_expression1[7U];
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)7U; i++)
  {
    repeat_expression1[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  حافظہ_نقل(deserialized_signer_response.انکڑے,
    repeat_expression1,
    (ناپ_t)7U * حجم (Eurydice_arr_a3));
  Eurydice_arr_81
  deserialized_hint =
    {
      .انکڑے = {
        { .انکڑے = { 0U } }, { .انکڑے = { 0U } }, { .انکڑے = { 0U } }, { .انکڑے = { 0U } },
        { .انکڑے = { 0U } }, { .انکڑے = { 0U } }, { .انکڑے = { 0U } }, { .انکڑے = { 0U } }
      }
    };
  core_نتیجہ_نتیجہ_41
  uu____1 =
    libcrux_ml_dsa_encoding_signature_deserialize_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_وچ_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_صفاں_وچ_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COMMITMENT_HASH_ناپ,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_GAMMA1_EXPONENT,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_GAMMA1_RING_ELEMENT_ناپ,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_MAX_ONES_وچ_HINT,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_SIGNATURE_ناپ,
      Eurydice_array_منزل_ٹکڑا_shared_11(signature_serialized),
      Eurydice_array_منزل_ٹکڑا_mut_17(&deserialized_commitment_hash),
      Eurydice_array_منزل_ٹکڑا_mut_208(&deserialized_signer_response),
      Eurydice_array_منزل_ٹکڑا_mut_861(&deserialized_hint));
  core_نتیجہ_نتیجہ_41 uu____2;
  إذا (uu____1.ٹیگ == core_نتیجہ_Ok)
  {
    إذا
    (
      libcrux_ml_dsa_arithmetic_سمتیہ_infinity_norm_exceeds_37(Eurydice_array_منزل_ٹکڑا_shared_206(&deserialized_signer_response),
        (int32_t)((uint32_t)1 << (uint32_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_GAMMA1_EXPONENT) -
          LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_BETA)
    )
    {
      uu____2 =
        (
          KRML_CLITERAL(core_نتیجہ_نتیجہ_41){
            .ٹیگ = core_نتیجہ_Err,
            .f0 = libcrux_ml_dsa_types_VerificationError_SignerResponseExceedsBoundError
          }
        );
    }
    وإلا
    {
      Eurydice_arr_0f میٹرکس;
      Eurydice_arr_a3 repeat_عبارت[56U];
      لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)56U; i++)
      {
        repeat_عبارت[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
      }
      حافظہ_نقل(میٹرکس.انکڑے, repeat_عبارت, (ناپ_t)56U * حجم (Eurydice_arr_a3));
      libcrux_ml_dsa_samplex4_portable_میٹرکس_flat_a8_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_وچ_A,
        بیج_for_a,
        Eurydice_array_منزل_ٹکڑا_mut_207(&میٹرکس));
      Eurydice_arr_c7 verification_کلید_hash = { .انکڑے = { 0U } };
      libcrux_ml_dsa_hash_functions_portable_shake256_61_c9(Eurydice_array_منزل_ٹکڑا_shared_fc(verification_کلید),
        &verification_کلید_hash);
      Eurydice_arr_c7 سنیہا_representative = { .انکڑے = { 0U } };
      libcrux_ml_dsa_ml_dsa_generic_derive_سنیہا_representative_43(Eurydice_array_منزل_ٹکڑا_shared_17(&verification_کلید_hash),
        &domain_separation_context,
        سنیہا,
        &سنیہا_representative);
      Eurydice_arr_a3 verifier_challenge = libcrux_ml_dsa_polynomial_zero_ff_37();
      libcrux_ml_dsa_sample_sample_challenge_ring_element_2e(Eurydice_array_منزل_ٹکڑا_shared_17(&deserialized_commitment_hash),
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ONES_وچ_VERIFIER_CHALLENGE,
        &verifier_challenge);
      libcrux_ml_dsa_ntt_ntt_37(&verifier_challenge);
      لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)7U; i++)
      {
        ناپ_t i0 = i;
        libcrux_ml_dsa_ntt_ntt_37(&deserialized_signer_response.انکڑے[i0]);
      }
      libcrux_ml_dsa_میٹرکس_compute_w_approx_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_صفاں_وچ_A,
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_وچ_A,
        Eurydice_array_منزل_ٹکڑا_shared_208(&میٹرکس),
        Eurydice_array_منزل_ٹکڑا_shared_206(&deserialized_signer_response),
        &verifier_challenge,
        Eurydice_array_منزل_ٹکڑا_mut_20(&t1));
      Eurydice_arr_c7 recomputed_commitment_hash = { .انکڑے = { 0U } };
      libcrux_ml_dsa_arithmetic_use_hint_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_GAMMA2,
        Eurydice_array_منزل_ٹکڑا_shared_861(&deserialized_hint),
        Eurydice_array_منزل_ٹکڑا_mut_20(&t1));
      Eurydice_arr_1b commitment_serialized = { .انکڑے = { 0U } };
      libcrux_ml_dsa_encoding_commitment_serialize_سمتیہ_37(LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_COMMITMENT_RING_ELEMENT_ناپ,
        Eurydice_array_منزل_ٹکڑا_shared_200(&t1),
        Eurydice_array_منزل_ٹکڑا_mut_68(&commitment_serialized));
      libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
      shake = libcrux_ml_dsa_hash_functions_portable_init_26();
      libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake,
        Eurydice_array_منزل_ٹکڑا_shared_17(&سنیہا_representative));
      libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake,
        Eurydice_array_منزل_ٹکڑا_shared_68(&commitment_serialized));
      libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake,
        Eurydice_array_منزل_ٹکڑا_mut_17(&recomputed_commitment_hash));
      إذا
      (
        Eurydice_array_eq((ناپ_t)64U,
          &deserialized_commitment_hash,
          &recomputed_commitment_hash,
          uint8_t)
      )
      {
        uu____2 = (KRML_CLITERAL(core_نتیجہ_نتیجہ_41){ .ٹیگ = core_نتیجہ_Ok });
      }
      وإلا
      {
        uu____2 =
          (
            KRML_CLITERAL(core_نتیجہ_نتیجہ_41){
              .ٹیگ = core_نتیجہ_Err,
              .f0 = libcrux_ml_dsa_types_Verification_Error_Commitment_Hashes_Dont_میل_Error
            }
          );
      }
    }
  }
  وإلا
  {
    libcrux_ml_dsa_types_VerificationError e = uu____1.f0;
    uu____2 = (KRML_CLITERAL(core_نتیجہ_نتیجہ_41){ .ٹیگ = core_نتیجہ_Err, .f0 = e });
  }
  أرجع uu____2;
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_87.verify
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof
with const generics

*/
ساكن KRML_MUSTINLINE core_نتیجہ_نتیجہ_41
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_verify_5a(
  ثابت Eurydice_arr_43 *verification_کلید_serialized,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_borrow_ٹکڑا_u8 context,
  ثابت Eurydice_arr_93 *signature_serialized
)
{
  core_نتیجہ_نتیجہ_a8
  uu____0 =
    libcrux_ml_dsa_pre_hash_new_88(context,
      (KRML_CLITERAL(core_option_Option_57){ .ٹیگ = core_option_None }));
  إذا (!(uu____0.ٹیگ == core_نتیجہ_Ok))
  {
    أرجع
      (
        KRML_CLITERAL(core_نتیجہ_نتیجہ_41){
          .ٹیگ = core_نتیجہ_Err,
          .f0 = libcrux_ml_dsa_types_VerificationError_VerificationContextTooLongError
        }
      );
  }
  libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
  libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
  أرجع
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_verify_اندرونی_5a(verification_کلید_serialized,
      سنیہا,
      (
        KRML_CLITERAL(core_option_Option_84){
          .ٹیگ = core_option_Some,
          .f0 = domain_separation_context
        }
      ),
      signature_serialized);
}

/**
 Verify.
*/
ساكن مضمن core_نتیجہ_نتیجہ_41
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_87_verify(
  ثابت Eurydice_arr_43 *verification_کلید,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_borrow_ٹکڑا_u8 context,
  ثابت Eurydice_arr_93 *signature
)
{
  أرجع
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_verify_5a(verification_کلید,
      سنیہا,
      context,
      signature);
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_87.verify_pre_hashed
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_pre_hash_SHAKE128_PH
with const generics

*/
ساكن KRML_MUSTINLINE core_نتیجہ_نتیجہ_41
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_verify_pre_hashed_3f(
  ثابت Eurydice_arr_43 *verification_کلید_serialized,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_borrow_ٹکڑا_u8 context,
  Eurydice_mut_borrow_ٹکڑا_u8 pre_hash_بفر,
  ثابت Eurydice_arr_93 *signature_serialized
)
{
  libcrux_ml_dsa_pre_hash_hash_30_83(سنیہا, pre_hash_بفر);
  core_نتیجہ_نتیجہ_a8
  uu____0 =
    libcrux_ml_dsa_pre_hash_new_88(context,
      (
        KRML_CLITERAL(core_option_Option_57){
          .ٹیگ = core_option_Some,
          .f0 = libcrux_ml_dsa_pre_hash_oid_30()
        }
      ));
  إذا (!(uu____0.ٹیگ == core_نتیجہ_Ok))
  {
    أرجع
      (
        KRML_CLITERAL(core_نتیجہ_نتیجہ_41){
          .ٹیگ = core_نتیجہ_Err,
          .f0 = libcrux_ml_dsa_types_VerificationError_VerificationContextTooLongError
        }
      );
  }
  libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
  libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
  أرجع
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_verify_اندرونی_5a(verification_کلید_serialized,
      (
        KRML_CLITERAL(Eurydice_borrow_ٹکڑا_u8){
          .ptr = pre_hash_بفر.ptr,
          .meta = pre_hash_بفر.meta
        }
      ),
      (
        KRML_CLITERAL(core_option_Option_84){
          .ٹیگ = core_option_Some,
          .f0 = domain_separation_context
        }
      ),
      signature_serialized);
}

/**
 Verify (pre-hashed with SHAKE-128).
*/
ساكن مضمن core_نتیجہ_نتیجہ_41
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_87_verify_pre_hashed_shake128(
  ثابت Eurydice_arr_43 *verification_کلید,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_borrow_ٹکڑا_u8 context,
  Eurydice_mut_borrow_ٹکڑا_u8 pre_hash_بفر,
  ثابت Eurydice_arr_93 *signature
)
{
  أرجع
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_verify_pre_hashed_3f(verification_کلید,
      سنیہا,
      context,
      pre_hash_بفر,
      signature);
}

#إذا defined(__cplusplus)
}
#جے_انت

#تعریف_کرو libcrux_mldsa_portable_H_DEFINED
#جے_انت /* libcrux_mldsa_portable_H */

/* from libcrux/combined_extraction/generated/libcrux_mldsa44_portable.h */
/*
 * SPDX-FileCopyrightText: 2025 Cryspen Sarl <info@cryspen.com>
 *
 * SPDX-License-Identifier: MIT or Apache-2.0
 *
 * This code was generated with the following revisions:
 * Charon: e656e17bff6ca5efac8ab6919b9b74cb9a8dd8ad
 * Eurydice: aaa9fa657fb6f09802edb890252040d94cd93982
 * Karamel: 8c19d41458ce5cbfea029ebc03334ba96d149039
 * F*: unset
 * Libcrux: c4e5e5e511bbc4c53f826163f57bfd10e9228911
 */


#جے_بنا_تعریف libcrux_mldsa44_portable_H
#تعریف_کرو libcrux_mldsa44_portable_H



#إذا defined(__cplusplus)
خارجي "C" {
#جے_انت


/**
 Generate an ML-DSA-44 Key Pair
*/
ساكن مضمن libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_MLDSA44_کلید_Pair
libcrux_ml_dsa_ml_dsa_44_portable_generate_کلید_pair(Eurydice_arr_ec randomness)
{
  Eurydice_arr_10 signing_کلید = { .انکڑے = { 0U } };
  Eurydice_arr_02 verification_کلید = { .انکڑے = { 0U } };
  libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_44_generate_کلید_pair(randomness,
    &signing_کلید,
    &verification_کلید);
  أرجع
    (
      KRML_CLITERAL(libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_MLDSA44_کلید_Pair){
        .signing_کلید = libcrux_ml_dsa_types_new_9b_ab(signing_کلید),
        .verification_کلید = libcrux_ml_dsa_types_new_7f_7d(verification_کلید)
      }
    );
}

/**
 Generate an ML-DSA-44 Signature

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
ساكن مضمن core_نتیجہ_نتیجہ_48
libcrux_ml_dsa_ml_dsa_44_portable_sign(
  ثابت Eurydice_arr_10 *signing_کلید,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_borrow_ٹکڑا_u8 context,
  Eurydice_arr_ec randomness
)
{
  أرجع
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_44_sign(libcrux_ml_dsa_types_as_ref_9b_ab(signing_کلید),
      سنیہا,
      context,
      randomness);
}

/**
 Generate an ML-DSA-44 Signature

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
ساكن مضمن core_نتیجہ_نتیجہ_53
libcrux_ml_dsa_ml_dsa_44_portable_sign_mut(
  ثابت Eurydice_arr_10 *signing_کلید,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_borrow_ٹکڑا_u8 context,
  Eurydice_arr_ec randomness,
  Eurydice_arr_85 *signature
)
{
  أرجع
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_44_sign_mut(libcrux_ml_dsa_types_as_ref_9b_ab(signing_کلید),
      سنیہا,
      context,
      randomness,
      signature);
}

/**
 Generate a HashML-DSA-44 Signature, with a SHAKE128 pre-hashing

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
ساكن مضمن core_نتیجہ_نتیجہ_48
libcrux_ml_dsa_ml_dsa_44_portable_sign_pre_hashed_shake128(
  ثابت Eurydice_arr_10 *signing_کلید,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_borrow_ٹکڑا_u8 context,
  Eurydice_arr_ec randomness
)
{
  Eurydice_arr_ec pre_hash_بفر = { .انکڑے = { 0U } };
  ثابت Eurydice_arr_10 *uu____0 = libcrux_ml_dsa_types_as_ref_9b_ab(signing_کلید);
  أرجع
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_44_sign_pre_hashed_shake128(uu____0,
      سنیہا,
      context,
      Eurydice_array_منزل_ٹکڑا_mut_01(&pre_hash_بفر),
      randomness);
}

/**
 Verify an ML-DSA-44 Signature

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
ساكن مضمن core_نتیجہ_نتیجہ_41
libcrux_ml_dsa_ml_dsa_44_portable_verify(
  ثابت Eurydice_arr_02 *verification_کلید,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_borrow_ٹکڑا_u8 context,
  ثابت Eurydice_arr_85 *signature
)
{
  أرجع
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_44_verify(libcrux_ml_dsa_types_as_ref_7f_7d(verification_کلید),
      سنیہا,
      context,
      libcrux_ml_dsa_types_as_ref_c5_37(signature));
}

/**
 Verify a HashML-DSA-44 Signature, with a SHAKE128 pre-hashing

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
ساكن مضمن core_نتیجہ_نتیجہ_41
libcrux_ml_dsa_ml_dsa_44_portable_verify_pre_hashed_shake128(
  ثابت Eurydice_arr_02 *verification_کلید,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_borrow_ٹکڑا_u8 context,
  ثابت Eurydice_arr_85 *signature
)
{
  Eurydice_arr_ec pre_hash_بفر = { .انکڑے = { 0U } };
  ثابت Eurydice_arr_02 *uu____0 = libcrux_ml_dsa_types_as_ref_7f_7d(verification_کلید);
  Eurydice_borrow_ٹکڑا_u8 uu____1 = سنیہا;
  Eurydice_borrow_ٹکڑا_u8 uu____2 = context;
  Eurydice_mut_borrow_ٹکڑا_u8 uu____3 = Eurydice_array_منزل_ٹکڑا_mut_01(&pre_hash_بفر);
  أرجع
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_44_verify_pre_hashed_shake128(uu____0,
      uu____1,
      uu____2,
      uu____3,
      libcrux_ml_dsa_types_as_ref_c5_37(signature));
}

#إذا defined(__cplusplus)
}
#جے_انت

#تعریف_کرو libcrux_mldsa44_portable_H_DEFINED
#جے_انت /* libcrux_mldsa44_portable_H */

/* from libcrux/combined_extraction/generated/libcrux_mldsa65_portable.h */
/*
 * SPDX-FileCopyrightText: 2025 Cryspen Sarl <info@cryspen.com>
 *
 * SPDX-License-Identifier: MIT or Apache-2.0
 *
 * This code was generated with the following revisions:
 * Charon: e656e17bff6ca5efac8ab6919b9b74cb9a8dd8ad
 * Eurydice: aaa9fa657fb6f09802edb890252040d94cd93982
 * Karamel: 8c19d41458ce5cbfea029ebc03334ba96d149039
 * F*: unset
 * Libcrux: c4e5e5e511bbc4c53f826163f57bfd10e9228911
 */


#جے_بنا_تعریف libcrux_mldsa65_portable_H
#تعریف_کرو libcrux_mldsa65_portable_H



#إذا defined(__cplusplus)
خارجي "C" {
#جے_انت


/**
 Generate an ML-DSA-65 Key Pair
*/
ساكن مضمن libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_MLDSA65_کلید_Pair
libcrux_ml_dsa_ml_dsa_65_portable_generate_کلید_pair(Eurydice_arr_ec randomness)
{
  Eurydice_arr_24 signing_کلید = { .انکڑے = { 0U } };
  Eurydice_arr_29 verification_کلید = { .انکڑے = { 0U } };
  libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_generate_کلید_pair(randomness,
    &signing_کلید,
    &verification_کلید);
  أرجع
    (
      KRML_CLITERAL(libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_MLDSA65_کلید_Pair){
        .signing_کلید = libcrux_ml_dsa_types_new_9b_e5(signing_کلید),
        .verification_کلید = libcrux_ml_dsa_types_new_7f_a2(verification_کلید)
      }
    );
}

/**
 Generate an ML-DSA-65 Key Pair
*/
ساكن مضمن فراغ
libcrux_ml_dsa_ml_dsa_65_portable_generate_کلید_pair_mut(
  Eurydice_arr_ec randomness,
  Eurydice_arr_24 *signing_کلید,
  Eurydice_arr_29 *verification_کلید
)
{
  libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_generate_کلید_pair(randomness,
    signing_کلید,
    verification_کلید);
}

/**
 Generate an ML-DSA-65 Signature

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
ساكن مضمن core_نتیجہ_نتیجہ_8c
libcrux_ml_dsa_ml_dsa_65_portable_sign(
  ثابت Eurydice_arr_24 *signing_کلید,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_borrow_ٹکڑا_u8 context,
  Eurydice_arr_ec randomness
)
{
  أرجع
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_sign(libcrux_ml_dsa_types_as_ref_9b_e5(signing_کلید),
      سنیہا,
      context,
      randomness);
}

/**
 Generate an ML-DSA-65 Signature

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
ساكن مضمن core_نتیجہ_نتیجہ_53
libcrux_ml_dsa_ml_dsa_65_portable_sign_mut(
  ثابت Eurydice_arr_24 *signing_کلید,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_borrow_ٹکڑا_u8 context,
  Eurydice_arr_ec randomness,
  Eurydice_arr_0c *signature
)
{
  أرجع
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_sign_mut(signing_کلید,
      سنیہا,
      context,
      randomness,
      signature);
}

/**
 Generate a HashML-DSA-65 Signature, with a SHAKE128 pre-hashing

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
ساكن مضمن core_نتیجہ_نتیجہ_8c
libcrux_ml_dsa_ml_dsa_65_portable_sign_pre_hashed_shake128(
  ثابت Eurydice_arr_24 *signing_کلید,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_borrow_ٹکڑا_u8 context,
  Eurydice_arr_ec randomness
)
{
  Eurydice_arr_ec pre_hash_بفر = { .انکڑے = { 0U } };
  ثابت Eurydice_arr_24 *uu____0 = libcrux_ml_dsa_types_as_ref_9b_e5(signing_کلید);
  أرجع
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_sign_pre_hashed_shake128(uu____0,
      سنیہا,
      context,
      Eurydice_array_منزل_ٹکڑا_mut_01(&pre_hash_بفر),
      randomness);
}

/**
 Verify an ML-DSA-65 Signature

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
ساكن مضمن core_نتیجہ_نتیجہ_41
libcrux_ml_dsa_ml_dsa_65_portable_verify(
  ثابت Eurydice_arr_29 *verification_کلید,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_borrow_ٹکڑا_u8 context,
  ثابت Eurydice_arr_0c *signature
)
{
  أرجع
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_verify(libcrux_ml_dsa_types_as_ref_7f_a2(verification_کلید),
      سنیہا,
      context,
      libcrux_ml_dsa_types_as_ref_c5_5c(signature));
}

/**
 Verify a HashML-DSA-65 Signature, with a SHAKE128 pre-hashing

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
ساكن مضمن core_نتیجہ_نتیجہ_41
libcrux_ml_dsa_ml_dsa_65_portable_verify_pre_hashed_shake128(
  ثابت Eurydice_arr_29 *verification_کلید,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_borrow_ٹکڑا_u8 context,
  ثابت Eurydice_arr_0c *signature
)
{
  Eurydice_arr_ec pre_hash_بفر = { .انکڑے = { 0U } };
  ثابت Eurydice_arr_29 *uu____0 = libcrux_ml_dsa_types_as_ref_7f_a2(verification_کلید);
  Eurydice_borrow_ٹکڑا_u8 uu____1 = سنیہا;
  Eurydice_borrow_ٹکڑا_u8 uu____2 = context;
  Eurydice_mut_borrow_ٹکڑا_u8 uu____3 = Eurydice_array_منزل_ٹکڑا_mut_01(&pre_hash_بفر);
  أرجع
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_verify_pre_hashed_shake128(uu____0,
      uu____1,
      uu____2,
      uu____3,
      libcrux_ml_dsa_types_as_ref_c5_5c(signature));
}

#إذا defined(__cplusplus)
}
#جے_انت

#تعریف_کرو libcrux_mldsa65_portable_H_DEFINED
#جے_انت /* libcrux_mldsa65_portable_H */

/* from libcrux/combined_extraction/generated/libcrux_mldsa87_portable.h */
/*
 * SPDX-FileCopyrightText: 2025 Cryspen Sarl <info@cryspen.com>
 *
 * SPDX-License-Identifier: MIT or Apache-2.0
 *
 * This code was generated with the following revisions:
 * Charon: e656e17bff6ca5efac8ab6919b9b74cb9a8dd8ad
 * Eurydice: aaa9fa657fb6f09802edb890252040d94cd93982
 * Karamel: 8c19d41458ce5cbfea029ebc03334ba96d149039
 * F*: unset
 * Libcrux: c4e5e5e511bbc4c53f826163f57bfd10e9228911
 */


#جے_بنا_تعریف libcrux_mldsa87_portable_H
#تعریف_کرو libcrux_mldsa87_portable_H



#إذا defined(__cplusplus)
خارجي "C" {
#جے_انت


/**
 Generate an ML-DSA-87 Key Pair
*/
ساكن مضمن libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_MLDSA87_کلید_Pair
libcrux_ml_dsa_ml_dsa_87_portable_generate_کلید_pair(Eurydice_arr_ec randomness)
{
  Eurydice_arr_e2 signing_کلید = { .انکڑے = { 0U } };
  Eurydice_arr_43 verification_کلید = { .انکڑے = { 0U } };
  libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_87_generate_کلید_pair(randomness,
    &signing_کلید,
    &verification_کلید);
  أرجع
    (
      KRML_CLITERAL(libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_MLDSA87_کلید_Pair){
        .signing_کلید = libcrux_ml_dsa_types_new_9b_72(signing_کلید),
        .verification_کلید = libcrux_ml_dsa_types_new_7f_c6(verification_کلید)
      }
    );
}

/**
 Generate an ML-DSA-87 Signature

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
ساكن مضمن core_نتیجہ_نتیجہ_8b
libcrux_ml_dsa_ml_dsa_87_portable_sign(
  ثابت Eurydice_arr_e2 *signing_کلید,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_borrow_ٹکڑا_u8 context,
  Eurydice_arr_ec randomness
)
{
  أرجع
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_87_sign(libcrux_ml_dsa_types_as_ref_9b_72(signing_کلید),
      سنیہا,
      context,
      randomness);
}

/**
 Generate an ML-DSA-87 Signature

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
ساكن مضمن core_نتیجہ_نتیجہ_53
libcrux_ml_dsa_ml_dsa_87_portable_sign_mut(
  ثابت Eurydice_arr_e2 *signing_کلید,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_borrow_ٹکڑا_u8 context,
  Eurydice_arr_ec randomness,
  Eurydice_arr_93 *signature
)
{
  أرجع
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_87_sign_mut(libcrux_ml_dsa_types_as_ref_9b_72(signing_کلید),
      سنیہا,
      context,
      randomness,
      signature);
}

/**
 Generate a HashML-DSA-87 Signature, with a SHAKE128 pre-hashing

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
ساكن مضمن core_نتیجہ_نتیجہ_8b
libcrux_ml_dsa_ml_dsa_87_portable_sign_pre_hashed_shake128(
  ثابت Eurydice_arr_e2 *signing_کلید,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_borrow_ٹکڑا_u8 context,
  Eurydice_arr_ec randomness
)
{
  Eurydice_arr_ec pre_hash_بفر = { .انکڑے = { 0U } };
  ثابت Eurydice_arr_e2 *uu____0 = libcrux_ml_dsa_types_as_ref_9b_72(signing_کلید);
  أرجع
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_87_sign_pre_hashed_shake128(uu____0,
      سنیہا,
      context,
      Eurydice_array_منزل_ٹکڑا_mut_01(&pre_hash_بفر),
      randomness);
}

/**
 Verify an ML-DSA-87 Signature

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
ساكن مضمن core_نتیجہ_نتیجہ_41
libcrux_ml_dsa_ml_dsa_87_portable_verify(
  ثابت Eurydice_arr_43 *verification_کلید,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_borrow_ٹکڑا_u8 context,
  ثابت Eurydice_arr_93 *signature
)
{
  أرجع
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_87_verify(libcrux_ml_dsa_types_as_ref_7f_c6(verification_کلید),
      سنیہا,
      context,
      libcrux_ml_dsa_types_as_ref_c5_f1(signature));
}

/**
 Verify a HashML-DSA-87 Signature, with a SHAKE128 pre-hashing

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
ساكن مضمن core_نتیجہ_نتیجہ_41
libcrux_ml_dsa_ml_dsa_87_portable_verify_pre_hashed_shake128(
  ثابت Eurydice_arr_43 *verification_کلید,
  Eurydice_borrow_ٹکڑا_u8 سنیہا,
  Eurydice_borrow_ٹکڑا_u8 context,
  ثابت Eurydice_arr_93 *signature
)
{
  Eurydice_arr_ec pre_hash_بفر = { .انکڑے = { 0U } };
  ثابت Eurydice_arr_43 *uu____0 = libcrux_ml_dsa_types_as_ref_7f_c6(verification_کلید);
  Eurydice_borrow_ٹکڑا_u8 uu____1 = سنیہا;
  Eurydice_borrow_ٹکڑا_u8 uu____2 = context;
  Eurydice_mut_borrow_ٹکڑا_u8 uu____3 = Eurydice_array_منزل_ٹکڑا_mut_01(&pre_hash_بفر);
  أرجع
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_87_verify_pre_hashed_shake128(uu____0,
      uu____1,
      uu____2,
      uu____3,
      libcrux_ml_dsa_types_as_ref_c5_f1(signature));
}

#إذا defined(__cplusplus)
}
#جے_انت

#تعریف_کرو libcrux_mldsa87_portable_H_DEFINED
#جے_انت /* libcrux_mldsa87_portable_H */

/* from libcrux/combined_extraction/generated/libcrux_mlkem768_portable.h */
/*
 * SPDX-FileCopyrightText: 2025 Cryspen Sarl <info@cryspen.com>
 *
 * SPDX-License-Identifier: MIT or Apache-2.0
 *
 * This code was generated with the following revisions:
 * Charon: e656e17bff6ca5efac8ab6919b9b74cb9a8dd8ad
 * Eurydice: aaa9fa657fb6f09802edb890252040d94cd93982
 * Karamel: 8c19d41458ce5cbfea029ebc03334ba96d149039
 * F*: unset
 * Libcrux: c4e5e5e511bbc4c53f826163f57bfd10e9228911
 */


#جے_بنا_تعریف libcrux_mlkem768_portable_H
#تعریف_کرو libcrux_mlkem768_portable_H



#إذا defined(__cplusplus)
خارجي "C" {
#جے_انت


ساكن مضمن Eurydice_arr_c7
libcrux_ml_kem_hash_functions_portable_G(Eurydice_borrow_ٹکڑا_u8 داخلہ)
{
  Eurydice_arr_c7 digest = { .انکڑے = { 0U } };
  libcrux_sha3_portable_sha512(Eurydice_array_منزل_ٹکڑا_mut_17(&digest), داخلہ);
  أرجع digest;
}

ساكن مضمن Eurydice_arr_ec
libcrux_ml_kem_hash_functions_portable_H(Eurydice_borrow_ٹکڑا_u8 داخلہ)
{
  Eurydice_arr_ec digest = { .انکڑے = { 0U } };
  libcrux_sha3_portable_sha256(Eurydice_array_منزل_ٹکڑا_mut_01(&digest), داخلہ);
  أرجع digest;
}

#تعریف_کرو LIBCRUX_ML_KEM_POLYNOMIAL_ZETAS_TIMES_MONTGOMERY_R ((KRML_CLITERAL(Eurydice_arr_34){ .انکڑے = { -1044, -758, -359, -1517, 1493, 1422, 287, 202, -171, 622, 1577, 182, 962, -1202, -1474, 1468, 573, -1325, 264, 383, -829, 1458, -1602, -130, -681, 1017, 732, 608, -1542, 411, -205, -1571, 1223, 652, -552, 1015, -1293, 1491, -282, -1544, 516, -8, -320, -666, -1618, -1162, 126, 1469, -853, -90, -271, 830, 107, -1421, -247, -951, -398, 961, -1508, -725, 448, -1065, 677, -1275, -1103, 430, 555, 843, -1251, 871, 1550, 105, 422, 587, 177, -235, -291, -460, 1574, 1653, -246, 778, 1159, -147, -777, 1483, -602, 1119, -1590, 644, -872, 349, 418, 329, -156, -75, 817, 1097, 603, 610, 1322, -1285, -1465, 384, -1215, -136, 1218, -1335, -874, 220, -1187, -1659, -1185, -1530, -1278, 794, -1510, -854, -870, 478, -108, -308, 996, 991, 958, -1460, 1522, 1628 } }))

ساكن KRML_MUSTINLINE int16_t libcrux_ml_kem_polynomial_zeta(ناپ_t i)
{
  أرجع LIBCRUX_ML_KEM_POLYNOMIAL_ZETAS_TIMES_MONTGOMERY_R.انکڑے[i];
}

#تعریف_کرو LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_وچ_RING_ELEMENT ((ناپ_t)16U)

#تعریف_کرو LIBCRUX_ML_KEM_سمتیہ_TRAITS_میدان_ELEMENTS_وچ_سمتیہ ((ناپ_t)16U)

#تعریف_کرو LIBCRUX_ML_KEM_سمتیہ_TRAITS_MONTGOMERY_R_SQUARED_MOD_میدان_MODULUS (1353)

#تعریف_کرو LIBCRUX_ML_KEM_سمتیہ_TRAITS_میدان_MODULUS (3329)

#تعریف_کرو LIBCRUX_ML_KEM_سمتیہ_TRAITS_INVERSE_دا_MODULUS_MOD_MONTGOMERY_R (62209U)

ساكن KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_سمتیہ_type_from_i16_array(Eurydice_borrow_ٹکڑا_i16 array)
{
  Eurydice_arr_d6 arr;
  حافظہ_نقل(arr.انکڑے,
    Eurydice_ٹکڑا_subslice_shared_a6(array,
      (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = (ناپ_t)0U, .سرا = (ناپ_t)16U })).ptr,
    (ناپ_t)16U * حجم (int16_t));
  أرجع
    core_نتیجہ_unwrap_26_d3((
        KRML_CLITERAL(core_نتیجہ_نتیجہ_ec){ .ٹیگ = core_نتیجہ_Ok, .val = { .case_Ok = arr } }
      ));
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ساكن مضمن Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_from_i16_array_b8(Eurydice_borrow_ٹکڑا_i16 array)
{
  أرجع
    libcrux_ml_kem_سمتیہ_portable_سمتیہ_type_from_i16_array(libcrux_secrets_int_classify_عوامی_classify_ref_6d_39(array));
}

ساكن KRML_MUSTINLINE Eurydice_arr_d6 libcrux_ml_kem_سمتیہ_portable_سمتیہ_type_zero(فراغ)
{
  أرجع
    libcrux_secrets_int_عوامی_integers_classify_27_4b((
        KRML_CLITERAL(Eurydice_arr_d6){ .انکڑے = { 0U } }
      ));
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ساكن مضمن Eurydice_arr_d6 libcrux_ml_kem_سمتیہ_portable_ZERO_b8(فراغ)
{
  أرجع libcrux_ml_kem_سمتیہ_portable_سمتیہ_type_zero();
}

ساكن KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_arithmetic_جوڑو(Eurydice_arr_d6 lhs, ثابت Eurydice_arr_d6 *rhs)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < LIBCRUX_ML_KEM_سمتیہ_TRAITS_میدان_ELEMENTS_وچ_سمتیہ; i++)
  {
    ناپ_t i0 = i;
    ناپ_t uu____0 = i0;
    lhs.انکڑے[uu____0] += rhs->انکڑے[i0];
  }
  أرجع lhs;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ساكن مضمن Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_جوڑو_b8(Eurydice_arr_d6 lhs, ثابت Eurydice_arr_d6 *rhs)
{
  أرجع libcrux_ml_kem_سمتیہ_portable_arithmetic_جوڑو(lhs, rhs);
}

ساكن KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_arithmetic_sub(Eurydice_arr_d6 lhs, ثابت Eurydice_arr_d6 *rhs)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < LIBCRUX_ML_KEM_سمتیہ_TRAITS_میدان_ELEMENTS_وچ_سمتیہ; i++)
  {
    ناپ_t i0 = i;
    ناپ_t uu____0 = i0;
    lhs.انکڑے[uu____0] -= rhs->انکڑے[i0];
  }
  أرجع lhs;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ساكن مضمن Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_sub_b8(Eurydice_arr_d6 lhs, ثابت Eurydice_arr_d6 *rhs)
{
  أرجع libcrux_ml_kem_سمتیہ_portable_arithmetic_sub(lhs, rhs);
}

ساكن KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_arithmetic_multiply_by_constant(Eurydice_arr_d6 vec, int16_t c)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < LIBCRUX_ML_KEM_سمتیہ_TRAITS_میدان_ELEMENTS_وچ_سمتیہ; i++)
  {
    ناپ_t i0 = i;
    ناپ_t uu____0 = i0;
    vec.انکڑے[uu____0] *= c;
  }
  أرجع vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ساكن مضمن Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_multiply_by_constant_b8(Eurydice_arr_d6 vec, int16_t c)
{
  أرجع libcrux_ml_kem_سمتیہ_portable_arithmetic_multiply_by_constant(vec, c);
}

/**
 Note: This function is not secret independent
 Only use with public values.
*/
ساكن KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_arithmetic_cond_گھٹاؤ_3329(Eurydice_arr_d6 vec)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < LIBCRUX_ML_KEM_سمتیہ_TRAITS_میدان_ELEMENTS_وچ_سمتیہ; i++)
  {
    ناپ_t i0 = i;
    إذا (libcrux_secrets_int_عوامی_integers_declassify_d8_39(vec.انکڑے[i0]) >= 3329)
    {
      ناپ_t uu____0 = i0;
      vec.انکڑے[uu____0] -= 3329;
    }
  }
  أرجع vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ساكن مضمن Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_cond_گھٹاؤ_3329_b8(Eurydice_arr_d6 v)
{
  أرجع libcrux_ml_kem_سمتیہ_portable_arithmetic_cond_گھٹاؤ_3329(v);
}

#تعریف_کرو LIBCRUX_ML_KEM_سمتیہ_PORTABLE_ARITHMETIC_BARRETT_MULTIPLIER (20159)

#تعریف_کرو LIBCRUX_ML_KEM_سمتیہ_TRAITS_BARRETT_کھسکاؤ (26)

#تعریف_کرو LIBCRUX_ML_KEM_سمتیہ_TRAITS_BARRETT_R ((int32_t)((uint32_t)1 << (uint32_t)LIBCRUX_ML_KEM_سمتیہ_TRAITS_BARRETT_کھسکاؤ))

/**
 Signed Barrett Reduction

 Given an input `value`, `barrett_reduce` outputs a representative `result`
 such that:

 - result ≡ value (mod FIELD_MODULUS)
 - the absolute value of `result` is bound as follows:

 `|result| ≤ FIELD_MODULUS / 2 · (|value|/BARRETT_R + 1)

 Note: The input bound is 28296 to prevent overflow in the multiplication of quotient by FIELD_MODULUS

*/
ساكن مضمن int16_t
libcrux_ml_kem_سمتیہ_portable_arithmetic_barrett_reduce_element(int16_t قدر)
{
  int32_t
  t =
    libcrux_secrets_int_as_i32_f5(قدر) *
      LIBCRUX_ML_KEM_سمتیہ_PORTABLE_ARITHMETIC_BARRETT_MULTIPLIER
    + (LIBCRUX_ML_KEM_سمتیہ_TRAITS_BARRETT_R >> 1U);
  int16_t
  quotient =
    libcrux_secrets_int_as_i16_36(t >> (uint32_t)LIBCRUX_ML_KEM_سمتیہ_TRAITS_BARRETT_کھسکاؤ);
  أرجع قدر - quotient * LIBCRUX_ML_KEM_سمتیہ_TRAITS_میدان_MODULUS;
}

ساكن KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_arithmetic_barrett_reduce(Eurydice_arr_d6 vec)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < LIBCRUX_ML_KEM_سمتیہ_TRAITS_میدان_ELEMENTS_وچ_سمتیہ; i++)
  {
    ناپ_t i0 = i;
    int16_t vi = libcrux_ml_kem_سمتیہ_portable_arithmetic_barrett_reduce_element(vec.انکڑے[i0]);
    vec.انکڑے[i0] = vi;
  }
  أرجع vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ساكن مضمن Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_barrett_reduce_b8(Eurydice_arr_d6 سمتیہ)
{
  أرجع libcrux_ml_kem_سمتیہ_portable_arithmetic_barrett_reduce(سمتیہ);
}

#تعریف_کرو LIBCRUX_ML_KEM_سمتیہ_PORTABLE_ARITHMETIC_MONTGOMERY_کھسکاؤ (16U)

/**
 Signed Montgomery Reduction

 Given an input `value`, `montgomery_reduce` outputs a representative `o`
 such that:

 - o ≡ value · MONTGOMERY_R^(-1) (mod FIELD_MODULUS)
 - the absolute value of `o` is bound as follows:

 `|result| ≤ ceil(|value| / MONTGOMERY_R) + 1665

 In particular, if `|value| ≤ FIELD_MODULUS-1 * FIELD_MODULUS-1`, then `|o| <= FIELD_MODULUS-1`.
 And, if `|value| ≤ pow2 16 * FIELD_MODULUS-1`, then `|o| <= FIELD_MODULUS + 1664

*/
ساكن مضمن int16_t
libcrux_ml_kem_سمتیہ_portable_arithmetic_montgomery_reduce_element(int32_t قدر)
{
  int32_t
  k =
    libcrux_secrets_int_as_i32_f5(libcrux_secrets_int_as_i16_36(قدر)) *
      libcrux_secrets_int_as_i32_b8(libcrux_secrets_int_عوامی_integers_classify_27_df(LIBCRUX_ML_KEM_سمتیہ_TRAITS_INVERSE_دا_MODULUS_MOD_MONTGOMERY_R));
  int32_t
  k_times_modulus =
    libcrux_secrets_int_as_i32_f5(libcrux_secrets_int_as_i16_36(k)) *
      libcrux_secrets_int_as_i32_f5(libcrux_secrets_int_عوامی_integers_classify_27_39(LIBCRUX_ML_KEM_سمتیہ_TRAITS_میدان_MODULUS));
  int16_t
  c =
    libcrux_secrets_int_as_i16_36(k_times_modulus >>
        (uint32_t)LIBCRUX_ML_KEM_سمتیہ_PORTABLE_ARITHMETIC_MONTGOMERY_کھسکاؤ);
  int16_t
  قدر_بلند =
    libcrux_secrets_int_as_i16_36(قدر >>
        (uint32_t)LIBCRUX_ML_KEM_سمتیہ_PORTABLE_ARITHMETIC_MONTGOMERY_کھسکاؤ);
  أرجع قدر_بلند - c;
}

/**
 If `fe` is some field element 'x' of the Kyber field and `fer` is congruent to
 `y · MONTGOMERY_R`, this procedure outputs a value that is congruent to
 `x · y`, as follows:

    `fe · fer ≡ x · y · MONTGOMERY_R (mod FIELD_MODULUS)`

 `montgomery_reduce` takes the value `x · y · MONTGOMERY_R` and outputs a representative
 `x · y · MONTGOMERY_R * MONTGOMERY_R^{-1} ≡ x · y (mod FIELD_MODULUS)`.
*/
ساكن KRML_MUSTINLINE int16_t
libcrux_ml_kem_سمتیہ_portable_arithmetic_montgomery_multiply_fe_by_fer(
  int16_t fe,
  int16_t fer
)
{
  int32_t ضرب_حاصل = libcrux_secrets_int_as_i32_f5(fe) * libcrux_secrets_int_as_i32_f5(fer);
  أرجع libcrux_ml_kem_سمتیہ_portable_arithmetic_montgomery_reduce_element(ضرب_حاصل);
}

ساكن KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_arithmetic_montgomery_multiply_by_constant(
  Eurydice_arr_d6 vec,
  int16_t c
)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < LIBCRUX_ML_KEM_سمتیہ_TRAITS_میدان_ELEMENTS_وچ_سمتیہ; i++)
  {
    ناپ_t i0 = i;
    vec.انکڑے[i0] =
      libcrux_ml_kem_سمتیہ_portable_arithmetic_montgomery_multiply_fe_by_fer(vec.انکڑے[i0],
        c);
  }
  أرجع vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ساكن مضمن Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_montgomery_multiply_by_constant_b8(
  Eurydice_arr_d6 سمتیہ,
  int16_t constant
)
{
  أرجع
    libcrux_ml_kem_سمتیہ_portable_arithmetic_montgomery_multiply_by_constant(سمتیہ,
      libcrux_secrets_int_عوامی_integers_classify_27_39(constant));
}

ساكن KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_arithmetic_bitwise_and_with_constant(
  Eurydice_arr_d6 vec,
  int16_t c
)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < LIBCRUX_ML_KEM_سمتیہ_TRAITS_میدان_ELEMENTS_وچ_سمتیہ; i++)
  {
    ناپ_t i0 = i;
    ناپ_t uu____0 = i0;
    vec.انکڑے[uu____0] &= c;
  }
  أرجع vec;
}

/**
A monomorphic instance of libcrux_ml_kem.vector.portable.arithmetic.shift_right
with const generics
- SHIFT_BY= 15
*/
ساكن KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_arithmetic_کھسکاؤ_دایاں_ef(Eurydice_arr_d6 vec)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < LIBCRUX_ML_KEM_سمتیہ_TRAITS_میدان_ELEMENTS_وچ_سمتیہ; i++)
  {
    ناپ_t i0 = i;
    vec.انکڑے[i0] >>= (uint32_t)15;
  }
  أرجع vec;
}

ساكن KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_arithmetic_منزل_unsigned_representative(Eurydice_arr_d6 a)
{
  Eurydice_arr_d6 t = libcrux_ml_kem_سمتیہ_portable_arithmetic_کھسکاؤ_دایاں_ef(a);
  Eurydice_arr_d6
  fm =
    libcrux_ml_kem_سمتیہ_portable_arithmetic_bitwise_and_with_constant(t,
      LIBCRUX_ML_KEM_سمتیہ_TRAITS_میدان_MODULUS);
  أرجع libcrux_ml_kem_سمتیہ_portable_arithmetic_جوڑو(a, &fm);
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ساكن مضمن Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_منزل_unsigned_representative_b8(Eurydice_arr_d6 a)
{
  أرجع libcrux_ml_kem_سمتیہ_portable_arithmetic_منزل_unsigned_representative(a);
}

/**
 The `compress_*` functions implement the `Compress` function specified in the NIST FIPS
 203 standard (Page 18, Expression 4.5), which is defined as:

 ```plaintext
 Compress_d: ℤq -> ℤ_{2ᵈ}
 Compress_d(x) = ⌈(2ᵈ/q)·x⌋
 ```

 Since `⌈x⌋ = ⌊x + 1/2⌋` we have:

 ```plaintext
 Compress_d(x) = ⌊(2ᵈ/q)·x + 1/2⌋
               = ⌊(2^{d+1}·x + q) / 2q⌋
 ```

 For further information about the function implementations, consult the
 `implementation_notes.pdf` document in this directory.

 The NIST FIPS 203 standard can be found at
 <https://csrc.nist.gov/pubs/fips/203/ipd>.
*/
ساكن مضمن uint8_t
libcrux_ml_kem_سمتیہ_portable_compress_compress_سنیہا_coefficient(uint16_t fe)
{
  int16_t
  shifted =
    libcrux_secrets_int_عوامی_integers_classify_27_39(1664) - libcrux_secrets_int_as_i16_ca(fe);
  int16_t نقاب = shifted >> 15U;
  int16_t shifted_منزل_مثبت = نقاب ^ shifted;
  int16_t shifted_مثبت_وچ_range = shifted_منزل_مثبت - 832;
  int16_t r0 = shifted_مثبت_وچ_range >> 15U;
  int16_t r1 = r0 & 1;
  أرجع libcrux_secrets_int_as_u8_f5(r1);
}

ساكن KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_compress_compress_1(Eurydice_arr_d6 a)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < LIBCRUX_ML_KEM_سمتیہ_TRAITS_میدان_ELEMENTS_وچ_سمتیہ; i++)
  {
    ناپ_t i0 = i;
    a.انکڑے[i0] =
      libcrux_secrets_int_as_i16_59(libcrux_ml_kem_سمتیہ_portable_compress_compress_سنیہا_coefficient(libcrux_secrets_int_as_u16_f5(a.انکڑے[i0])));
  }
  أرجع a;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ساكن مضمن Eurydice_arr_d6 libcrux_ml_kem_سمتیہ_portable_compress_1_b8(Eurydice_arr_d6 a)
{
  أرجع libcrux_ml_kem_سمتیہ_portable_compress_compress_1(a);
}

ساكن KRML_MUSTINLINE uint32_t
libcrux_ml_kem_سمتیہ_portable_arithmetic_get_n_گھٹ_توں_گھٹ_significant_بٹ(
  uint8_t n,
  uint32_t قدر
)
{
  أرجع قدر & ((1U << (uint32_t)n) - 1U);
}

ساكن مضمن int16_t
libcrux_ml_kem_سمتیہ_portable_compress_compress_ciphertext_coefficient(
  uint8_t coefficient_بٹ,
  uint16_t fe
)
{
  uint64_t compressed = libcrux_secrets_int_as_u64_ca(fe) << (uint32_t)coefficient_بٹ;
  compressed += 1664ULL;
  compressed *= 10321340ULL;
  compressed >>= 35U;
  أرجع
    libcrux_secrets_int_as_i16_b8(libcrux_ml_kem_سمتیہ_portable_arithmetic_get_n_گھٹ_توں_گھٹ_significant_بٹ(coefficient_بٹ,
        libcrux_secrets_int_as_u32_a3(compressed)));
}

ساكن KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_compress_decompress_1(Eurydice_arr_d6 a)
{
  Eurydice_arr_d6 z = libcrux_ml_kem_سمتیہ_portable_سمتیہ_type_zero();
  Eurydice_arr_d6 s = libcrux_ml_kem_سمتیہ_portable_arithmetic_sub(z, &a);
  Eurydice_arr_d6
  res = libcrux_ml_kem_سمتیہ_portable_arithmetic_bitwise_and_with_constant(s, 1665);
  أرجع res;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ساكن مضمن Eurydice_arr_d6 libcrux_ml_kem_سمتیہ_portable_decompress_1_b8(Eurydice_arr_d6 a)
{
  أرجع libcrux_ml_kem_سمتیہ_portable_compress_decompress_1(a);
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_kem_سمتیہ_portable_ntt_ntt_قدم(
  Eurydice_arr_d6 *vec,
  int16_t zeta,
  ناپ_t i,
  ناپ_t j
)
{
  int16_t
  t =
    libcrux_ml_kem_سمتیہ_portable_arithmetic_montgomery_multiply_fe_by_fer(vec->انکڑے[j],
      libcrux_secrets_int_عوامی_integers_classify_27_39(zeta));
  int16_t a_minus_t = vec->انکڑے[i] - t;
  int16_t a_plus_t = vec->انکڑے[i] + t;
  vec->انکڑے[j] = a_minus_t;
  vec->انکڑے[i] = a_plus_t;
}

ساكن KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_ntt_ntt_layer_1_قدم(
  Eurydice_arr_d6 vec,
  int16_t zeta0,
  int16_t zeta1,
  int16_t zeta2,
  int16_t zeta3
)
{
  libcrux_ml_kem_سمتیہ_portable_ntt_ntt_قدم(&vec, zeta0, (ناپ_t)0U, (ناپ_t)2U);
  libcrux_ml_kem_سمتیہ_portable_ntt_ntt_قدم(&vec, zeta0, (ناپ_t)1U, (ناپ_t)3U);
  libcrux_ml_kem_سمتیہ_portable_ntt_ntt_قدم(&vec, zeta1, (ناپ_t)4U, (ناپ_t)6U);
  libcrux_ml_kem_سمتیہ_portable_ntt_ntt_قدم(&vec, zeta1, (ناپ_t)5U, (ناپ_t)7U);
  libcrux_ml_kem_سمتیہ_portable_ntt_ntt_قدم(&vec, zeta2, (ناپ_t)8U, (ناپ_t)10U);
  libcrux_ml_kem_سمتیہ_portable_ntt_ntt_قدم(&vec, zeta2, (ناپ_t)9U, (ناپ_t)11U);
  libcrux_ml_kem_سمتیہ_portable_ntt_ntt_قدم(&vec, zeta3, (ناپ_t)12U, (ناپ_t)14U);
  libcrux_ml_kem_سمتیہ_portable_ntt_ntt_قدم(&vec, zeta3, (ناپ_t)13U, (ناپ_t)15U);
  أرجع vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ساكن مضمن Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_ntt_layer_1_قدم_b8(
  Eurydice_arr_d6 a,
  int16_t zeta0,
  int16_t zeta1,
  int16_t zeta2,
  int16_t zeta3
)
{
  أرجع libcrux_ml_kem_سمتیہ_portable_ntt_ntt_layer_1_قدم(a, zeta0, zeta1, zeta2, zeta3);
}

ساكن KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_ntt_ntt_layer_2_قدم(
  Eurydice_arr_d6 vec,
  int16_t zeta0,
  int16_t zeta1
)
{
  libcrux_ml_kem_سمتیہ_portable_ntt_ntt_قدم(&vec, zeta0, (ناپ_t)0U, (ناپ_t)4U);
  libcrux_ml_kem_سمتیہ_portable_ntt_ntt_قدم(&vec, zeta0, (ناپ_t)1U, (ناپ_t)5U);
  libcrux_ml_kem_سمتیہ_portable_ntt_ntt_قدم(&vec, zeta0, (ناپ_t)2U, (ناپ_t)6U);
  libcrux_ml_kem_سمتیہ_portable_ntt_ntt_قدم(&vec, zeta0, (ناپ_t)3U, (ناپ_t)7U);
  libcrux_ml_kem_سمتیہ_portable_ntt_ntt_قدم(&vec, zeta1, (ناپ_t)8U, (ناپ_t)12U);
  libcrux_ml_kem_سمتیہ_portable_ntt_ntt_قدم(&vec, zeta1, (ناپ_t)9U, (ناپ_t)13U);
  libcrux_ml_kem_سمتیہ_portable_ntt_ntt_قدم(&vec, zeta1, (ناپ_t)10U, (ناپ_t)14U);
  libcrux_ml_kem_سمتیہ_portable_ntt_ntt_قدم(&vec, zeta1, (ناپ_t)11U, (ناپ_t)15U);
  أرجع vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ساكن مضمن Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_ntt_layer_2_قدم_b8(
  Eurydice_arr_d6 a,
  int16_t zeta0,
  int16_t zeta1
)
{
  أرجع libcrux_ml_kem_سمتیہ_portable_ntt_ntt_layer_2_قدم(a, zeta0, zeta1);
}

ساكن KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_ntt_ntt_layer_3_قدم(Eurydice_arr_d6 vec, int16_t zeta)
{
  libcrux_ml_kem_سمتیہ_portable_ntt_ntt_قدم(&vec, zeta, (ناپ_t)0U, (ناپ_t)8U);
  libcrux_ml_kem_سمتیہ_portable_ntt_ntt_قدم(&vec, zeta, (ناپ_t)1U, (ناپ_t)9U);
  libcrux_ml_kem_سمتیہ_portable_ntt_ntt_قدم(&vec, zeta, (ناپ_t)2U, (ناپ_t)10U);
  libcrux_ml_kem_سمتیہ_portable_ntt_ntt_قدم(&vec, zeta, (ناپ_t)3U, (ناپ_t)11U);
  libcrux_ml_kem_سمتیہ_portable_ntt_ntt_قدم(&vec, zeta, (ناپ_t)4U, (ناپ_t)12U);
  libcrux_ml_kem_سمتیہ_portable_ntt_ntt_قدم(&vec, zeta, (ناپ_t)5U, (ناپ_t)13U);
  libcrux_ml_kem_سمتیہ_portable_ntt_ntt_قدم(&vec, zeta, (ناپ_t)6U, (ناپ_t)14U);
  libcrux_ml_kem_سمتیہ_portable_ntt_ntt_قدم(&vec, zeta, (ناپ_t)7U, (ناپ_t)15U);
  أرجع vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ساكن مضمن Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_ntt_layer_3_قدم_b8(Eurydice_arr_d6 a, int16_t zeta)
{
  أرجع libcrux_ml_kem_سمتیہ_portable_ntt_ntt_layer_3_قدم(a, zeta);
}

ساكن KRML_MUSTINLINE فراغ
libcrux_ml_kem_سمتیہ_portable_ntt_inv_ntt_قدم(
  Eurydice_arr_d6 *vec,
  int16_t zeta,
  ناپ_t i,
  ناپ_t j
)
{
  int16_t a_minus_b = vec->انکڑے[j] - vec->انکڑے[i];
  int16_t a_plus_b = vec->انکڑے[j] + vec->انکڑے[i];
  int16_t o0 = libcrux_ml_kem_سمتیہ_portable_arithmetic_barrett_reduce_element(a_plus_b);
  int16_t
  o1 =
    libcrux_ml_kem_سمتیہ_portable_arithmetic_montgomery_multiply_fe_by_fer(a_minus_b,
      libcrux_secrets_int_عوامی_integers_classify_27_39(zeta));
  vec->انکڑے[i] = o0;
  vec->انکڑے[j] = o1;
}

ساكن KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_ntt_inv_ntt_layer_1_قدم(
  Eurydice_arr_d6 vec,
  int16_t zeta0,
  int16_t zeta1,
  int16_t zeta2,
  int16_t zeta3
)
{
  libcrux_ml_kem_سمتیہ_portable_ntt_inv_ntt_قدم(&vec, zeta0, (ناپ_t)0U, (ناپ_t)2U);
  libcrux_ml_kem_سمتیہ_portable_ntt_inv_ntt_قدم(&vec, zeta0, (ناپ_t)1U, (ناپ_t)3U);
  libcrux_ml_kem_سمتیہ_portable_ntt_inv_ntt_قدم(&vec, zeta1, (ناپ_t)4U, (ناپ_t)6U);
  libcrux_ml_kem_سمتیہ_portable_ntt_inv_ntt_قدم(&vec, zeta1, (ناپ_t)5U, (ناپ_t)7U);
  libcrux_ml_kem_سمتیہ_portable_ntt_inv_ntt_قدم(&vec, zeta2, (ناپ_t)8U, (ناپ_t)10U);
  libcrux_ml_kem_سمتیہ_portable_ntt_inv_ntt_قدم(&vec, zeta2, (ناپ_t)9U, (ناپ_t)11U);
  libcrux_ml_kem_سمتیہ_portable_ntt_inv_ntt_قدم(&vec, zeta3, (ناپ_t)12U, (ناپ_t)14U);
  libcrux_ml_kem_سمتیہ_portable_ntt_inv_ntt_قدم(&vec, zeta3, (ناپ_t)13U, (ناپ_t)15U);
  أرجع vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ساكن مضمن Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_inv_ntt_layer_1_قدم_b8(
  Eurydice_arr_d6 a,
  int16_t zeta0,
  int16_t zeta1,
  int16_t zeta2,
  int16_t zeta3
)
{
  أرجع libcrux_ml_kem_سمتیہ_portable_ntt_inv_ntt_layer_1_قدم(a, zeta0, zeta1, zeta2, zeta3);
}

ساكن KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_ntt_inv_ntt_layer_2_قدم(
  Eurydice_arr_d6 vec,
  int16_t zeta0,
  int16_t zeta1
)
{
  libcrux_ml_kem_سمتیہ_portable_ntt_inv_ntt_قدم(&vec, zeta0, (ناپ_t)0U, (ناپ_t)4U);
  libcrux_ml_kem_سمتیہ_portable_ntt_inv_ntt_قدم(&vec, zeta0, (ناپ_t)1U, (ناپ_t)5U);
  libcrux_ml_kem_سمتیہ_portable_ntt_inv_ntt_قدم(&vec, zeta0, (ناپ_t)2U, (ناپ_t)6U);
  libcrux_ml_kem_سمتیہ_portable_ntt_inv_ntt_قدم(&vec, zeta0, (ناپ_t)3U, (ناپ_t)7U);
  libcrux_ml_kem_سمتیہ_portable_ntt_inv_ntt_قدم(&vec, zeta1, (ناپ_t)8U, (ناپ_t)12U);
  libcrux_ml_kem_سمتیہ_portable_ntt_inv_ntt_قدم(&vec, zeta1, (ناپ_t)9U, (ناپ_t)13U);
  libcrux_ml_kem_سمتیہ_portable_ntt_inv_ntt_قدم(&vec, zeta1, (ناپ_t)10U, (ناپ_t)14U);
  libcrux_ml_kem_سمتیہ_portable_ntt_inv_ntt_قدم(&vec, zeta1, (ناپ_t)11U, (ناپ_t)15U);
  أرجع vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ساكن مضمن Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_inv_ntt_layer_2_قدم_b8(
  Eurydice_arr_d6 a,
  int16_t zeta0,
  int16_t zeta1
)
{
  أرجع libcrux_ml_kem_سمتیہ_portable_ntt_inv_ntt_layer_2_قدم(a, zeta0, zeta1);
}

ساكن KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_ntt_inv_ntt_layer_3_قدم(Eurydice_arr_d6 vec, int16_t zeta)
{
  libcrux_ml_kem_سمتیہ_portable_ntt_inv_ntt_قدم(&vec, zeta, (ناپ_t)0U, (ناپ_t)8U);
  libcrux_ml_kem_سمتیہ_portable_ntt_inv_ntt_قدم(&vec, zeta, (ناپ_t)1U, (ناپ_t)9U);
  libcrux_ml_kem_سمتیہ_portable_ntt_inv_ntt_قدم(&vec, zeta, (ناپ_t)2U, (ناپ_t)10U);
  libcrux_ml_kem_سمتیہ_portable_ntt_inv_ntt_قدم(&vec, zeta, (ناپ_t)3U, (ناپ_t)11U);
  libcrux_ml_kem_سمتیہ_portable_ntt_inv_ntt_قدم(&vec, zeta, (ناپ_t)4U, (ناپ_t)12U);
  libcrux_ml_kem_سمتیہ_portable_ntt_inv_ntt_قدم(&vec, zeta, (ناپ_t)5U, (ناپ_t)13U);
  libcrux_ml_kem_سمتیہ_portable_ntt_inv_ntt_قدم(&vec, zeta, (ناپ_t)6U, (ناپ_t)14U);
  libcrux_ml_kem_سمتیہ_portable_ntt_inv_ntt_قدم(&vec, zeta, (ناپ_t)7U, (ناپ_t)15U);
  أرجع vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ساكن مضمن Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_inv_ntt_layer_3_قدم_b8(Eurydice_arr_d6 a, int16_t zeta)
{
  أرجع libcrux_ml_kem_سمتیہ_portable_ntt_inv_ntt_layer_3_قدم(a, zeta);
}

/**
 Compute the product of two Kyber binomials with respect to the
 modulus `X² - zeta`.

 This function almost implements <strong>Algorithm 11</strong> of the
 NIST FIPS 203 standard, which is reproduced below:

 ```plaintext
 Input:  a₀, a₁, b₀, b₁ ∈ ℤq.
 Input: γ ∈ ℤq.
 Output: c₀, c₁ ∈ ℤq.

 c₀ ← a₀·b₀ + a₁·b₁·γ
 c₁ ← a₀·b₁ + a₁·b₀
 return c₀, c₁
 ```
 We say "almost" because the coefficients output by this function are in
 the Montgomery domain (unlike in the specification).

 The NIST FIPS 203 standard can be found at
 <https://csrc.nist.gov/pubs/fips/203/ipd>.
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_kem_سمتیہ_portable_ntt_ntt_multiply_binomials(
  ثابت Eurydice_arr_d6 *a,
  ثابت Eurydice_arr_d6 *b,
  int16_t zeta,
  ناپ_t i,
  Eurydice_arr_d6 *باہرلا
)
{
  int16_t ai = a->انکڑے[(ناپ_t)2U * i];
  int16_t bi = b->انکڑے[(ناپ_t)2U * i];
  int16_t aj = a->انکڑے[(ناپ_t)2U * i + (ناپ_t)1U];
  int16_t bj = b->انکڑے[(ناپ_t)2U * i + (ناپ_t)1U];
  int32_t ai_bi = libcrux_secrets_int_as_i32_f5(ai) * libcrux_secrets_int_as_i32_f5(bi);
  int32_t aj_bj_ = libcrux_secrets_int_as_i32_f5(aj) * libcrux_secrets_int_as_i32_f5(bj);
  int16_t aj_bj = libcrux_ml_kem_سمتیہ_portable_arithmetic_montgomery_reduce_element(aj_bj_);
  int32_t
  aj_bj_zeta = libcrux_secrets_int_as_i32_f5(aj_bj) * libcrux_secrets_int_as_i32_f5(zeta);
  int32_t ai_bi_aj_bj = ai_bi + aj_bj_zeta;
  int16_t o0 = libcrux_ml_kem_سمتیہ_portable_arithmetic_montgomery_reduce_element(ai_bi_aj_bj);
  int32_t ai_bj = libcrux_secrets_int_as_i32_f5(ai) * libcrux_secrets_int_as_i32_f5(bj);
  int32_t aj_bi = libcrux_secrets_int_as_i32_f5(aj) * libcrux_secrets_int_as_i32_f5(bi);
  int32_t ai_bj_aj_bi = ai_bj + aj_bi;
  int16_t o1 = libcrux_ml_kem_سمتیہ_portable_arithmetic_montgomery_reduce_element(ai_bj_aj_bi);
  باہرلا->انکڑے[(ناپ_t)2U * i] = o0;
  باہرلا->انکڑے[(ناپ_t)2U * i + (ناپ_t)1U] = o1;
}

ساكن KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_ntt_ntt_multiply(
  ثابت Eurydice_arr_d6 *lhs,
  ثابت Eurydice_arr_d6 *rhs,
  int16_t zeta0,
  int16_t zeta1,
  int16_t zeta2,
  int16_t zeta3
)
{
  int16_t nzeta0 = -zeta0;
  int16_t nzeta1 = -zeta1;
  int16_t nzeta2 = -zeta2;
  int16_t nzeta3 = -zeta3;
  Eurydice_arr_d6 باہرلا = libcrux_ml_kem_سمتیہ_portable_سمتیہ_type_zero();
  libcrux_ml_kem_سمتیہ_portable_ntt_ntt_multiply_binomials(lhs,
    rhs,
    libcrux_secrets_int_عوامی_integers_classify_27_39(zeta0),
    (ناپ_t)0U,
    &باہرلا);
  libcrux_ml_kem_سمتیہ_portable_ntt_ntt_multiply_binomials(lhs,
    rhs,
    libcrux_secrets_int_عوامی_integers_classify_27_39(nzeta0),
    (ناپ_t)1U,
    &باہرلا);
  libcrux_ml_kem_سمتیہ_portable_ntt_ntt_multiply_binomials(lhs,
    rhs,
    libcrux_secrets_int_عوامی_integers_classify_27_39(zeta1),
    (ناپ_t)2U,
    &باہرلا);
  libcrux_ml_kem_سمتیہ_portable_ntt_ntt_multiply_binomials(lhs,
    rhs,
    libcrux_secrets_int_عوامی_integers_classify_27_39(nzeta1),
    (ناپ_t)3U,
    &باہرلا);
  libcrux_ml_kem_سمتیہ_portable_ntt_ntt_multiply_binomials(lhs,
    rhs,
    libcrux_secrets_int_عوامی_integers_classify_27_39(zeta2),
    (ناپ_t)4U,
    &باہرلا);
  libcrux_ml_kem_سمتیہ_portable_ntt_ntt_multiply_binomials(lhs,
    rhs,
    libcrux_secrets_int_عوامی_integers_classify_27_39(nzeta2),
    (ناپ_t)5U,
    &باہرلا);
  libcrux_ml_kem_سمتیہ_portable_ntt_ntt_multiply_binomials(lhs,
    rhs,
    libcrux_secrets_int_عوامی_integers_classify_27_39(zeta3),
    (ناپ_t)6U,
    &باہرلا);
  libcrux_ml_kem_سمتیہ_portable_ntt_ntt_multiply_binomials(lhs,
    rhs,
    libcrux_secrets_int_عوامی_integers_classify_27_39(nzeta3),
    (ناپ_t)7U,
    &باہرلا);
  أرجع باہرلا;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ساكن مضمن Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_ntt_multiply_b8(
  ثابت Eurydice_arr_d6 *lhs,
  ثابت Eurydice_arr_d6 *rhs,
  int16_t zeta0,
  int16_t zeta1,
  int16_t zeta2,
  int16_t zeta3
)
{
  أرجع libcrux_ml_kem_سمتیہ_portable_ntt_ntt_multiply(lhs, rhs, zeta0, zeta1, zeta2, zeta3);
}

ساكن KRML_MUSTINLINE Eurydice_array_u8x2
libcrux_ml_kem_سمتیہ_portable_serialize_serialize_1(Eurydice_arr_d6 v)
{
  uint8_t
  result0 =
    (((((((uint32_t)libcrux_secrets_int_as_u8_f5(v.انکڑے[0U]) |
      (uint32_t)libcrux_secrets_int_as_u8_f5(v.انکڑے[1U]) << 1U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.انکڑے[2U]) << 2U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.انکڑے[3U]) << 3U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.انکڑے[4U]) << 4U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.انکڑے[5U]) << 5U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.انکڑے[6U]) << 6U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.انکڑے[7U]) << 7U;
  uint8_t
  result1 =
    (((((((uint32_t)libcrux_secrets_int_as_u8_f5(v.انکڑے[8U]) |
      (uint32_t)libcrux_secrets_int_as_u8_f5(v.انکڑے[9U]) << 1U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.انکڑے[10U]) << 2U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.انکڑے[11U]) << 3U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.انکڑے[12U]) << 4U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.انکڑے[13U]) << 5U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.انکڑے[14U]) << 6U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.انکڑے[15U]) << 7U;
  أرجع (KRML_CLITERAL(Eurydice_array_u8x2){ .انکڑے = { result0, result1 } });
}

ساكن مضمن Eurydice_array_u8x2 libcrux_ml_kem_سمتیہ_portable_serialize_1(Eurydice_arr_d6 a)
{
  أرجع
    libcrux_secrets_int_عوامی_integers_declassify_d8_75(libcrux_ml_kem_سمتیہ_portable_serialize_serialize_1(a));
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ساكن مضمن Eurydice_array_u8x2
libcrux_ml_kem_سمتیہ_portable_serialize_1_b8(Eurydice_arr_d6 a)
{
  أرجع libcrux_ml_kem_سمتیہ_portable_serialize_1(a);
}

ساكن KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_serialize_deserialize_1(Eurydice_borrow_ٹکڑا_u8 v)
{
  int16_t result0 = libcrux_secrets_int_as_i16_59((uint32_t)v.ptr[0U] & 1U);
  int16_t result1 = libcrux_secrets_int_as_i16_59((uint32_t)v.ptr[0U] >> 1U & 1U);
  int16_t result2 = libcrux_secrets_int_as_i16_59((uint32_t)v.ptr[0U] >> 2U & 1U);
  int16_t result3 = libcrux_secrets_int_as_i16_59((uint32_t)v.ptr[0U] >> 3U & 1U);
  int16_t result4 = libcrux_secrets_int_as_i16_59((uint32_t)v.ptr[0U] >> 4U & 1U);
  int16_t result5 = libcrux_secrets_int_as_i16_59((uint32_t)v.ptr[0U] >> 5U & 1U);
  int16_t result6 = libcrux_secrets_int_as_i16_59((uint32_t)v.ptr[0U] >> 6U & 1U);
  int16_t result7 = libcrux_secrets_int_as_i16_59((uint32_t)v.ptr[0U] >> 7U & 1U);
  int16_t result8 = libcrux_secrets_int_as_i16_59((uint32_t)v.ptr[1U] & 1U);
  int16_t result9 = libcrux_secrets_int_as_i16_59((uint32_t)v.ptr[1U] >> 1U & 1U);
  int16_t result10 = libcrux_secrets_int_as_i16_59((uint32_t)v.ptr[1U] >> 2U & 1U);
  int16_t result11 = libcrux_secrets_int_as_i16_59((uint32_t)v.ptr[1U] >> 3U & 1U);
  int16_t result12 = libcrux_secrets_int_as_i16_59((uint32_t)v.ptr[1U] >> 4U & 1U);
  int16_t result13 = libcrux_secrets_int_as_i16_59((uint32_t)v.ptr[1U] >> 5U & 1U);
  int16_t result14 = libcrux_secrets_int_as_i16_59((uint32_t)v.ptr[1U] >> 6U & 1U);
  int16_t result15 = libcrux_secrets_int_as_i16_59((uint32_t)v.ptr[1U] >> 7U & 1U);
  أرجع
    (
      KRML_CLITERAL(Eurydice_arr_d6){
        .انکڑے = {
          result0, result1, result2, result3, result4, result5, result6, result7, result8, result9,
          result10, result11, result12, result13, result14, result15
        }
      }
    );
}

ساكن مضمن Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_deserialize_1(Eurydice_borrow_ٹکڑا_u8 a)
{
  أرجع
    libcrux_ml_kem_سمتیہ_portable_serialize_deserialize_1(libcrux_secrets_int_classify_عوامی_classify_ref_6d_90(a));
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ساكن مضمن Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_deserialize_1_b8(Eurydice_borrow_ٹکڑا_u8 a)
{
  أرجع libcrux_ml_kem_سمتیہ_portable_deserialize_1(a);
}

ساكن KRML_MUSTINLINE uint8_t_x4
libcrux_ml_kem_سمتیہ_portable_serialize_serialize_4_int(Eurydice_borrow_ٹکڑا_i16 v)
{
  uint8_t
  result0 =
    (uint32_t)libcrux_secrets_int_as_u8_f5(v.ptr[1U]) << 4U |
      (uint32_t)libcrux_secrets_int_as_u8_f5(v.ptr[0U]);
  uint8_t
  result1 =
    (uint32_t)libcrux_secrets_int_as_u8_f5(v.ptr[3U]) << 4U |
      (uint32_t)libcrux_secrets_int_as_u8_f5(v.ptr[2U]);
  uint8_t
  result2 =
    (uint32_t)libcrux_secrets_int_as_u8_f5(v.ptr[5U]) << 4U |
      (uint32_t)libcrux_secrets_int_as_u8_f5(v.ptr[4U]);
  uint8_t
  result3 =
    (uint32_t)libcrux_secrets_int_as_u8_f5(v.ptr[7U]) << 4U |
      (uint32_t)libcrux_secrets_int_as_u8_f5(v.ptr[6U]);
  أرجع
    (KRML_CLITERAL(uint8_t_x4){ .fst = result0, .snd = result1, .thd = result2, .f3 = result3 });
}

ساكن KRML_MUSTINLINE Eurydice_array_u8x8
libcrux_ml_kem_سمتیہ_portable_serialize_serialize_4(Eurydice_arr_d6 v)
{
  uint8_t_x4
  result0_3 =
    libcrux_ml_kem_سمتیہ_portable_serialize_serialize_4_int(Eurydice_array_منزل_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = (ناپ_t)0U, .سرا = (ناپ_t)8U })));
  uint8_t_x4
  result4_7 =
    libcrux_ml_kem_سمتیہ_portable_serialize_serialize_4_int(Eurydice_array_منزل_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = (ناپ_t)8U, .سرا = (ناپ_t)16U })));
  أرجع
    (
      KRML_CLITERAL(Eurydice_array_u8x8){
        .انکڑے = {
          result0_3.fst, result0_3.snd, result0_3.thd, result0_3.f3, result4_7.fst, result4_7.snd,
          result4_7.thd, result4_7.f3
        }
      }
    );
}

ساكن مضمن Eurydice_array_u8x8 libcrux_ml_kem_سمتیہ_portable_serialize_4(Eurydice_arr_d6 a)
{
  أرجع
    libcrux_secrets_int_عوامی_integers_declassify_d8_52(libcrux_ml_kem_سمتیہ_portable_serialize_serialize_4(a));
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ساكن مضمن Eurydice_array_u8x8
libcrux_ml_kem_سمتیہ_portable_serialize_4_b8(Eurydice_arr_d6 a)
{
  أرجع libcrux_ml_kem_سمتیہ_portable_serialize_4(a);
}

ساكن KRML_MUSTINLINE int16_t_x8
libcrux_ml_kem_سمتیہ_portable_serialize_deserialize_4_int(Eurydice_borrow_ٹکڑا_u8 بائٹاں)
{
  int16_t v0 = libcrux_secrets_int_as_i16_59((uint32_t)بائٹاں.ptr[0U] & 15U);
  int16_t v1 = libcrux_secrets_int_as_i16_59((uint32_t)بائٹاں.ptr[0U] >> 4U & 15U);
  int16_t v2 = libcrux_secrets_int_as_i16_59((uint32_t)بائٹاں.ptr[1U] & 15U);
  int16_t v3 = libcrux_secrets_int_as_i16_59((uint32_t)بائٹاں.ptr[1U] >> 4U & 15U);
  int16_t v4 = libcrux_secrets_int_as_i16_59((uint32_t)بائٹاں.ptr[2U] & 15U);
  int16_t v5 = libcrux_secrets_int_as_i16_59((uint32_t)بائٹاں.ptr[2U] >> 4U & 15U);
  int16_t v6 = libcrux_secrets_int_as_i16_59((uint32_t)بائٹاں.ptr[3U] & 15U);
  int16_t v7 = libcrux_secrets_int_as_i16_59((uint32_t)بائٹاں.ptr[3U] >> 4U & 15U);
  أرجع
    (
      KRML_CLITERAL(int16_t_x8){
        .fst = v0,
        .snd = v1,
        .thd = v2,
        .f3 = v3,
        .f4 = v4,
        .f5 = v5,
        .f6 = v6,
        .f7 = v7
      }
    );
}

ساكن KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_serialize_deserialize_4(Eurydice_borrow_ٹکڑا_u8 بائٹاں)
{
  int16_t_x8
  v0_7 =
    libcrux_ml_kem_سمتیہ_portable_serialize_deserialize_4_int(Eurydice_ٹکڑا_subslice_shared_c8(بائٹاں,
        (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = (ناپ_t)0U, .سرا = (ناپ_t)4U })));
  int16_t_x8
  v8_15 =
    libcrux_ml_kem_سمتیہ_portable_serialize_deserialize_4_int(Eurydice_ٹکڑا_subslice_shared_c8(بائٹاں,
        (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = (ناپ_t)4U, .سرا = (ناپ_t)8U })));
  أرجع
    (
      KRML_CLITERAL(Eurydice_arr_d6){
        .انکڑے = {
          v0_7.fst, v0_7.snd, v0_7.thd, v0_7.f3, v0_7.f4, v0_7.f5, v0_7.f6, v0_7.f7, v8_15.fst,
          v8_15.snd, v8_15.thd, v8_15.f3, v8_15.f4, v8_15.f5, v8_15.f6, v8_15.f7
        }
      }
    );
}

ساكن مضمن Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_deserialize_4(Eurydice_borrow_ٹکڑا_u8 a)
{
  أرجع
    libcrux_ml_kem_سمتیہ_portable_serialize_deserialize_4(libcrux_secrets_int_classify_عوامی_classify_ref_6d_90(a));
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ساكن مضمن Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_deserialize_4_b8(Eurydice_borrow_ٹکڑا_u8 a)
{
  أرجع libcrux_ml_kem_سمتیہ_portable_deserialize_4(a);
}

ساكن KRML_MUSTINLINE uint8_t_x5
libcrux_ml_kem_سمتیہ_portable_serialize_serialize_10_int(Eurydice_borrow_ٹکڑا_i16 v)
{
  uint8_t r0 = libcrux_secrets_int_as_u8_f5(v.ptr[0U] & 255);
  uint8_t
  r1 =
    (uint32_t)libcrux_secrets_int_as_u8_f5(v.ptr[1U] & 63) << 2U |
      (uint32_t)libcrux_secrets_int_as_u8_f5(v.ptr[0U] >> 8U & 3);
  uint8_t
  r2 =
    (uint32_t)libcrux_secrets_int_as_u8_f5(v.ptr[2U] & 15) << 4U |
      (uint32_t)libcrux_secrets_int_as_u8_f5(v.ptr[1U] >> 6U & 15);
  uint8_t
  r3 =
    (uint32_t)libcrux_secrets_int_as_u8_f5(v.ptr[3U] & 3) << 6U |
      (uint32_t)libcrux_secrets_int_as_u8_f5(v.ptr[2U] >> 4U & 63);
  uint8_t r4 = libcrux_secrets_int_as_u8_f5(v.ptr[3U] >> 2U & 255);
  أرجع (KRML_CLITERAL(uint8_t_x5){ .fst = r0, .snd = r1, .thd = r2, .f3 = r3, .f4 = r4 });
}

ساكن KRML_MUSTINLINE Eurydice_arr_fc
libcrux_ml_kem_سمتیہ_portable_serialize_serialize_10(Eurydice_arr_d6 v)
{
  uint8_t_x5
  r0_4 =
    libcrux_ml_kem_سمتیہ_portable_serialize_serialize_10_int(Eurydice_array_منزل_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = (ناپ_t)0U, .سرا = (ناپ_t)4U })));
  uint8_t_x5
  r5_9 =
    libcrux_ml_kem_سمتیہ_portable_serialize_serialize_10_int(Eurydice_array_منزل_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = (ناپ_t)4U, .سرا = (ناپ_t)8U })));
  uint8_t_x5
  r10_14 =
    libcrux_ml_kem_سمتیہ_portable_serialize_serialize_10_int(Eurydice_array_منزل_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = (ناپ_t)8U, .سرا = (ناپ_t)12U })));
  uint8_t_x5
  r15_19 =
    libcrux_ml_kem_سمتیہ_portable_serialize_serialize_10_int(Eurydice_array_منزل_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = (ناپ_t)12U, .سرا = (ناپ_t)16U })));
  أرجع
    (
      KRML_CLITERAL(Eurydice_arr_fc){
        .انکڑے = {
          r0_4.fst, r0_4.snd, r0_4.thd, r0_4.f3, r0_4.f4, r5_9.fst, r5_9.snd, r5_9.thd, r5_9.f3,
          r5_9.f4, r10_14.fst, r10_14.snd, r10_14.thd, r10_14.f3, r10_14.f4, r15_19.fst, r15_19.snd,
          r15_19.thd, r15_19.f3, r15_19.f4
        }
      }
    );
}

ساكن مضمن Eurydice_arr_fc libcrux_ml_kem_سمتیہ_portable_serialize_10(Eurydice_arr_d6 a)
{
  أرجع
    libcrux_secrets_int_عوامی_integers_declassify_d8_2b(libcrux_ml_kem_سمتیہ_portable_serialize_serialize_10(a));
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ساكن مضمن Eurydice_arr_fc libcrux_ml_kem_سمتیہ_portable_serialize_10_b8(Eurydice_arr_d6 a)
{
  أرجع libcrux_ml_kem_سمتیہ_portable_serialize_10(a);
}

ساكن KRML_MUSTINLINE int16_t_x8
libcrux_ml_kem_سمتیہ_portable_serialize_deserialize_10_int(Eurydice_borrow_ٹکڑا_u8 بائٹاں)
{
  int16_t
  r0 =
    libcrux_secrets_int_as_i16_f5((int16_t)((uint32_t)(libcrux_secrets_int_as_i16_59(بائٹاں.ptr[1U])
      & 3)
      << 8U)
      | (libcrux_secrets_int_as_i16_59(بائٹاں.ptr[0U]) & 255));
  int16_t
  r1 =
    libcrux_secrets_int_as_i16_f5((int16_t)((uint32_t)(libcrux_secrets_int_as_i16_59(بائٹاں.ptr[2U])
      & 15)
      << 6U)
      | libcrux_secrets_int_as_i16_59(بائٹاں.ptr[1U]) >> 2U);
  int16_t
  r2 =
    libcrux_secrets_int_as_i16_f5((int16_t)((uint32_t)(libcrux_secrets_int_as_i16_59(بائٹاں.ptr[3U])
      & 63)
      << 4U)
      | libcrux_secrets_int_as_i16_59(بائٹاں.ptr[2U]) >> 4U);
  int16_t
  r3 =
    libcrux_secrets_int_as_i16_f5((int16_t)((uint32_t)libcrux_secrets_int_as_i16_59(بائٹاں.ptr[4U])
      << 2U)
      | libcrux_secrets_int_as_i16_59(بائٹاں.ptr[3U]) >> 6U);
  int16_t
  r4 =
    libcrux_secrets_int_as_i16_f5((int16_t)((uint32_t)(libcrux_secrets_int_as_i16_59(بائٹاں.ptr[6U])
      & 3)
      << 8U)
      | (libcrux_secrets_int_as_i16_59(بائٹاں.ptr[5U]) & 255));
  int16_t
  r5 =
    libcrux_secrets_int_as_i16_f5((int16_t)((uint32_t)(libcrux_secrets_int_as_i16_59(بائٹاں.ptr[7U])
      & 15)
      << 6U)
      | libcrux_secrets_int_as_i16_59(بائٹاں.ptr[6U]) >> 2U);
  int16_t
  r6 =
    libcrux_secrets_int_as_i16_f5((int16_t)((uint32_t)(libcrux_secrets_int_as_i16_59(بائٹاں.ptr[8U])
      & 63)
      << 4U)
      | libcrux_secrets_int_as_i16_59(بائٹاں.ptr[7U]) >> 4U);
  int16_t
  r7 =
    libcrux_secrets_int_as_i16_f5((int16_t)((uint32_t)libcrux_secrets_int_as_i16_59(بائٹاں.ptr[9U])
      << 2U)
      | libcrux_secrets_int_as_i16_59(بائٹاں.ptr[8U]) >> 6U);
  أرجع
    (
      KRML_CLITERAL(int16_t_x8){
        .fst = r0,
        .snd = r1,
        .thd = r2,
        .f3 = r3,
        .f4 = r4,
        .f5 = r5,
        .f6 = r6,
        .f7 = r7
      }
    );
}

ساكن KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_serialize_deserialize_10(Eurydice_borrow_ٹکڑا_u8 بائٹاں)
{
  int16_t_x8
  v0_7 =
    libcrux_ml_kem_سمتیہ_portable_serialize_deserialize_10_int(Eurydice_ٹکڑا_subslice_shared_c8(بائٹاں,
        (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = (ناپ_t)0U, .سرا = (ناپ_t)10U })));
  int16_t_x8
  v8_15 =
    libcrux_ml_kem_سمتیہ_portable_serialize_deserialize_10_int(Eurydice_ٹکڑا_subslice_shared_c8(بائٹاں,
        (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = (ناپ_t)10U, .سرا = (ناپ_t)20U })));
  أرجع
    (
      KRML_CLITERAL(Eurydice_arr_d6){
        .انکڑے = {
          v0_7.fst, v0_7.snd, v0_7.thd, v0_7.f3, v0_7.f4, v0_7.f5, v0_7.f6, v0_7.f7, v8_15.fst,
          v8_15.snd, v8_15.thd, v8_15.f3, v8_15.f4, v8_15.f5, v8_15.f6, v8_15.f7
        }
      }
    );
}

ساكن مضمن Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_deserialize_10(Eurydice_borrow_ٹکڑا_u8 a)
{
  أرجع
    libcrux_ml_kem_سمتیہ_portable_serialize_deserialize_10(libcrux_secrets_int_classify_عوامی_classify_ref_6d_90(a));
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ساكن مضمن Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_deserialize_10_b8(Eurydice_borrow_ٹکڑا_u8 a)
{
  أرجع libcrux_ml_kem_سمتیہ_portable_deserialize_10(a);
}

ساكن KRML_MUSTINLINE uint8_t_x3
libcrux_ml_kem_سمتیہ_portable_serialize_serialize_12_int(Eurydice_borrow_ٹکڑا_i16 v)
{
  uint8_t r0 = libcrux_secrets_int_as_u8_f5(v.ptr[0U] & 255);
  uint8_t
  r1 =
    libcrux_secrets_int_as_u8_f5(v.ptr[0U] >> 8U | (int16_t)((uint32_t)(v.ptr[1U] & 15) << 4U));
  uint8_t r2 = libcrux_secrets_int_as_u8_f5(v.ptr[1U] >> 4U & 255);
  أرجع (KRML_CLITERAL(uint8_t_x3){ .fst = r0, .snd = r1, .thd = r2 });
}

ساكن KRML_MUSTINLINE Eurydice_arr_94
libcrux_ml_kem_سمتیہ_portable_serialize_serialize_12(Eurydice_arr_d6 v)
{
  uint8_t_x3
  r0_2 =
    libcrux_ml_kem_سمتیہ_portable_serialize_serialize_12_int(Eurydice_array_منزل_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = (ناپ_t)0U, .سرا = (ناپ_t)2U })));
  uint8_t_x3
  r3_5 =
    libcrux_ml_kem_سمتیہ_portable_serialize_serialize_12_int(Eurydice_array_منزل_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = (ناپ_t)2U, .سرا = (ناپ_t)4U })));
  uint8_t_x3
  r6_8 =
    libcrux_ml_kem_سمتیہ_portable_serialize_serialize_12_int(Eurydice_array_منزل_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = (ناپ_t)4U, .سرا = (ناپ_t)6U })));
  uint8_t_x3
  r9_11 =
    libcrux_ml_kem_سمتیہ_portable_serialize_serialize_12_int(Eurydice_array_منزل_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = (ناپ_t)6U, .سرا = (ناپ_t)8U })));
  uint8_t_x3
  r12_14 =
    libcrux_ml_kem_سمتیہ_portable_serialize_serialize_12_int(Eurydice_array_منزل_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = (ناپ_t)8U, .سرا = (ناپ_t)10U })));
  uint8_t_x3
  r15_17 =
    libcrux_ml_kem_سمتیہ_portable_serialize_serialize_12_int(Eurydice_array_منزل_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = (ناپ_t)10U, .سرا = (ناپ_t)12U })));
  uint8_t_x3
  r18_20 =
    libcrux_ml_kem_سمتیہ_portable_serialize_serialize_12_int(Eurydice_array_منزل_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = (ناپ_t)12U, .سرا = (ناپ_t)14U })));
  uint8_t_x3
  r21_23 =
    libcrux_ml_kem_سمتیہ_portable_serialize_serialize_12_int(Eurydice_array_منزل_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = (ناپ_t)14U, .سرا = (ناپ_t)16U })));
  أرجع
    (
      KRML_CLITERAL(Eurydice_arr_94){
        .انکڑے = {
          r0_2.fst, r0_2.snd, r0_2.thd, r3_5.fst, r3_5.snd, r3_5.thd, r6_8.fst, r6_8.snd, r6_8.thd,
          r9_11.fst, r9_11.snd, r9_11.thd, r12_14.fst, r12_14.snd, r12_14.thd, r15_17.fst,
          r15_17.snd, r15_17.thd, r18_20.fst, r18_20.snd, r18_20.thd, r21_23.fst, r21_23.snd,
          r21_23.thd
        }
      }
    );
}

ساكن مضمن Eurydice_arr_94 libcrux_ml_kem_سمتیہ_portable_serialize_12(Eurydice_arr_d6 a)
{
  أرجع
    libcrux_secrets_int_عوامی_integers_declassify_d8_40(libcrux_ml_kem_سمتیہ_portable_serialize_serialize_12(a));
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ساكن مضمن Eurydice_arr_94 libcrux_ml_kem_سمتیہ_portable_serialize_12_b8(Eurydice_arr_d6 a)
{
  أرجع libcrux_ml_kem_سمتیہ_portable_serialize_12(a);
}

ساكن KRML_MUSTINLINE int16_t_x2
libcrux_ml_kem_سمتیہ_portable_serialize_deserialize_12_int(Eurydice_borrow_ٹکڑا_u8 بائٹاں)
{
  int16_t byte0 = libcrux_secrets_int_as_i16_59(بائٹاں.ptr[0U]);
  int16_t byte1 = libcrux_secrets_int_as_i16_59(بائٹاں.ptr[1U]);
  int16_t byte2 = libcrux_secrets_int_as_i16_59(بائٹاں.ptr[2U]);
  int16_t r0 = (int16_t)((uint32_t)(byte1 & 15) << 8U) | (byte0 & 255);
  int16_t r1 = (int16_t)((uint32_t)byte2 << 4U) | (byte1 >> 4U & 15);
  أرجع (KRML_CLITERAL(int16_t_x2){ .fst = r0, .snd = r1 });
}

ساكن KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_serialize_deserialize_12(Eurydice_borrow_ٹکڑا_u8 بائٹاں)
{
  int16_t_x2
  v0_1 =
    libcrux_ml_kem_سمتیہ_portable_serialize_deserialize_12_int(Eurydice_ٹکڑا_subslice_shared_c8(بائٹاں,
        (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = (ناپ_t)0U, .سرا = (ناپ_t)3U })));
  int16_t_x2
  v2_3 =
    libcrux_ml_kem_سمتیہ_portable_serialize_deserialize_12_int(Eurydice_ٹکڑا_subslice_shared_c8(بائٹاں,
        (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = (ناپ_t)3U, .سرا = (ناپ_t)6U })));
  int16_t_x2
  v4_5 =
    libcrux_ml_kem_سمتیہ_portable_serialize_deserialize_12_int(Eurydice_ٹکڑا_subslice_shared_c8(بائٹاں,
        (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = (ناپ_t)6U, .سرا = (ناپ_t)9U })));
  int16_t_x2
  v6_7 =
    libcrux_ml_kem_سمتیہ_portable_serialize_deserialize_12_int(Eurydice_ٹکڑا_subslice_shared_c8(بائٹاں,
        (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = (ناپ_t)9U, .سرا = (ناپ_t)12U })));
  int16_t_x2
  v8_9 =
    libcrux_ml_kem_سمتیہ_portable_serialize_deserialize_12_int(Eurydice_ٹکڑا_subslice_shared_c8(بائٹاں,
        (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = (ناپ_t)12U, .سرا = (ناپ_t)15U })));
  int16_t_x2
  v10_11 =
    libcrux_ml_kem_سمتیہ_portable_serialize_deserialize_12_int(Eurydice_ٹکڑا_subslice_shared_c8(بائٹاں,
        (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = (ناپ_t)15U, .سرا = (ناپ_t)18U })));
  int16_t_x2
  v12_13 =
    libcrux_ml_kem_سمتیہ_portable_serialize_deserialize_12_int(Eurydice_ٹکڑا_subslice_shared_c8(بائٹاں,
        (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = (ناپ_t)18U, .سرا = (ناپ_t)21U })));
  int16_t_x2
  v14_15 =
    libcrux_ml_kem_سمتیہ_portable_serialize_deserialize_12_int(Eurydice_ٹکڑا_subslice_shared_c8(بائٹاں,
        (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = (ناپ_t)21U, .سرا = (ناپ_t)24U })));
  أرجع
    (
      KRML_CLITERAL(Eurydice_arr_d6){
        .انکڑے = {
          v0_1.fst, v0_1.snd, v2_3.fst, v2_3.snd, v4_5.fst, v4_5.snd, v6_7.fst, v6_7.snd, v8_9.fst,
          v8_9.snd, v10_11.fst, v10_11.snd, v12_13.fst, v12_13.snd, v14_15.fst, v14_15.snd
        }
      }
    );
}

ساكن مضمن Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_deserialize_12(Eurydice_borrow_ٹکڑا_u8 a)
{
  أرجع
    libcrux_ml_kem_سمتیہ_portable_serialize_deserialize_12(libcrux_secrets_int_classify_عوامی_classify_ref_6d_90(a));
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ساكن مضمن Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_deserialize_12_b8(Eurydice_borrow_ٹکڑا_u8 a)
{
  أرجع libcrux_ml_kem_سمتیہ_portable_deserialize_12(a);
}

ساكن KRML_MUSTINLINE ناپ_t
libcrux_ml_kem_سمتیہ_portable_sampling_rej_sample(
  Eurydice_borrow_ٹکڑا_u8 a,
  Eurydice_mut_borrow_ٹکڑا_i16 نتیجہ
)
{
  ناپ_t sampled = (ناپ_t)0U;
  لكل (ناپ_t i = (ناپ_t)0U; i < a.meta / (ناپ_t)3U; i++)
  {
    ناپ_t i0 = i;
    int16_t b1 = (int16_t)(uint32_t)a.ptr[i0 * (ناپ_t)3U + (ناپ_t)0U];
    int16_t b2 = (int16_t)(uint32_t)a.ptr[i0 * (ناپ_t)3U + (ناپ_t)1U];
    int16_t b3 = (int16_t)(uint32_t)a.ptr[i0 * (ناپ_t)3U + (ناپ_t)2U];
    int16_t d1 = (int16_t)((uint32_t)(b2 & 15) << 8U) | b1;
    int16_t d2 = (int16_t)((uint32_t)b3 << 4U) | b2 >> 4U;
    إذا (d1 < LIBCRUX_ML_KEM_سمتیہ_TRAITS_میدان_MODULUS)
    {
      إذا (sampled < (ناپ_t)16U)
      {
        نتیجہ.ptr[sampled] = d1;
        sampled++;
      }
    }
    إذا (d2 < LIBCRUX_ML_KEM_سمتیہ_TRAITS_میدان_MODULUS)
    {
      إذا (sampled < (ناپ_t)16U)
      {
        نتیجہ.ptr[sampled] = d2;
        sampled++;
      }
    }
  }
  أرجع sampled;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ساكن مضمن ناپ_t
libcrux_ml_kem_سمتیہ_portable_rej_sample_b8(
  Eurydice_borrow_ٹکڑا_u8 a,
  Eurydice_mut_borrow_ٹکڑا_i16 باہرلا
)
{
  أرجع libcrux_ml_kem_سمتیہ_portable_sampling_rej_sample(a, باہرلا);
}

#تعریف_کرو LIBCRUX_ML_KEM_MLKEM768_سمتیہ_U_COMPRESSION_ضارب ((ناپ_t)10U)

#تعریف_کرو LIBCRUX_ML_KEM_MLKEM768_C1_بلاک_ناپ (LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_وچ_RING_ELEMENT * LIBCRUX_ML_KEM_MLKEM768_سمتیہ_U_COMPRESSION_ضارب / (ناپ_t)8U)

#تعریف_کرو LIBCRUX_ML_KEM_MLKEM768_RANK ((ناپ_t)3U)

#تعریف_کرو LIBCRUX_ML_KEM_MLKEM768_C1_ناپ (LIBCRUX_ML_KEM_MLKEM768_C1_بلاک_ناپ * LIBCRUX_ML_KEM_MLKEM768_RANK)

#تعریف_کرو LIBCRUX_ML_KEM_MLKEM768_سمتیہ_V_COMPRESSION_ضارب ((ناپ_t)4U)

#تعریف_کرو LIBCRUX_ML_KEM_MLKEM768_C2_ناپ (LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_وچ_RING_ELEMENT * LIBCRUX_ML_KEM_MLKEM768_سمتیہ_V_COMPRESSION_ضارب / (ناپ_t)8U)

#تعریف_کرو LIBCRUX_ML_KEM_MLKEM768_CPA_PKE_CIPHERTEXT_ناپ (LIBCRUX_ML_KEM_MLKEM768_C1_ناپ + LIBCRUX_ML_KEM_MLKEM768_C2_ناپ)

#تعریف_کرو LIBCRUX_ML_KEM_MLKEM768_T_AS_NTT_ENCODED_ناپ (LIBCRUX_ML_KEM_MLKEM768_RANK * LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_وچ_RING_ELEMENT * LIBCRUX_ML_KEM_CONSTANTS_بٹ_فی_COEFFICIENT / (ناپ_t)8U)

#تعریف_کرو LIBCRUX_ML_KEM_MLKEM768_CPA_PKE_عوامی_کلید_ناپ (LIBCRUX_ML_KEM_MLKEM768_T_AS_NTT_ENCODED_ناپ + (ناپ_t)32U)

#تعریف_کرو LIBCRUX_ML_KEM_MLKEM768_CPA_PKE_SECRET_کلید_ناپ (LIBCRUX_ML_KEM_MLKEM768_RANK * LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_وچ_RING_ELEMENT * LIBCRUX_ML_KEM_CONSTANTS_بٹ_فی_COEFFICIENT / (ناپ_t)8U)

#تعریف_کرو LIBCRUX_ML_KEM_MLKEM768_ETA1 ((ناپ_t)2U)

#تعریف_کرو LIBCRUX_ML_KEM_MLKEM768_ETA1_RANDOMNESS_ناپ (LIBCRUX_ML_KEM_MLKEM768_ETA1 * (ناپ_t)64U)

#تعریف_کرو LIBCRUX_ML_KEM_MLKEM768_ETA2 ((ناپ_t)2U)

#تعریف_کرو LIBCRUX_ML_KEM_MLKEM768_ETA2_RANDOMNESS_ناپ (LIBCRUX_ML_KEM_MLKEM768_ETA2 * (ناپ_t)64U)

#تعریف_کرو LIBCRUX_ML_KEM_MLKEM768_IMPLICIT_REJECTION_HASH_داخلہ_ناپ (LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_ناپ + LIBCRUX_ML_KEM_MLKEM768_CPA_PKE_CIPHERTEXT_ناپ)

تعريفنوع Eurydice_arr_7d libcrux_ml_kem_mlkem768_Ml_Kem768_نجی_کلید;

تعريفنوع Eurydice_arr_5f libcrux_ml_kem_mlkem768_Ml_Kem768_عوامی_کلید;

#تعریف_کرو LIBCRUX_ML_KEM_MLKEM768_RANKED_بائٹاں_فی_RING_ELEMENT (LIBCRUX_ML_KEM_MLKEM768_RANK * LIBCRUX_ML_KEM_CONSTANTS_بٹ_فی_RING_ELEMENT / (ناپ_t)8U)

#تعریف_کرو LIBCRUX_ML_KEM_MLKEM768_SECRET_کلید_ناپ (LIBCRUX_ML_KEM_MLKEM768_CPA_PKE_SECRET_کلید_ناپ + LIBCRUX_ML_KEM_MLKEM768_CPA_PKE_عوامی_کلید_ناپ + LIBCRUX_ML_KEM_CONSTANTS_H_DIGEST_ناپ + LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_ناپ)

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- $16size_t
*/
تعريفنوع بنية Eurydice_arr_9e_s { Eurydice_arr_d6 انکڑے[16U]; } Eurydice_arr_9e;

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_kem_polynomial_PolynomialRingElement_1d
with const generics
- $3size_t
*/
تعريفنوع بنية Eurydice_arr_bb0_s { Eurydice_arr_9e انکڑے[3U]; } Eurydice_arr_bb0;

/**
This function found in impl {libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.polynomial.ZERO_d6
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ساكن مضمن Eurydice_arr_9e libcrux_ml_kem_polynomial_ZERO_d6_ea(فراغ)
{
  Eurydice_arr_9e lit;
  Eurydice_arr_d6 repeat_عبارت[16U];
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)16U; i++)
  {
    repeat_عبارت[i] = libcrux_ml_kem_سمتیہ_portable_ZERO_b8();
  }
  حافظہ_نقل(lit.انکڑے, repeat_عبارت, (ناپ_t)16U * حجم (Eurydice_arr_d6));
  أرجع lit;
}

/**
This function found in impl {core::ops::function::FnMut<(usize), libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]> for libcrux_ml_kem::ind_cpa::decrypt::closure<Vector, K, CIPHERTEXT_SIZE, VECTOR_U_ENCODED_SIZE, U_COMPRESSION_FACTOR, V_COMPRESSION_FACTOR>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.decrypt.call_mut_0b
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- CIPHERTEXT_SIZE= 1088
- VECTOR_U_ENCODED_SIZE= 960
- U_COMPRESSION_FACTOR= 10
- V_COMPRESSION_FACTOR= 4
*/
ساكن مضمن Eurydice_arr_9e
libcrux_ml_kem_ind_cpa_decrypt_call_mut_0b_01(فراغ **_, ناپ_t tupled_دلیلاں)
{
  أرجع libcrux_ml_kem_polynomial_ZERO_d6_ea();
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.deserialize_to_uncompressed_ring_element
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ساكن KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_serialize_deserialize_منزل_uncompressed_ring_element_ea(
  Eurydice_borrow_ٹکڑا_u8 serialized
)
{
  Eurydice_arr_9e re = libcrux_ml_kem_polynomial_ZERO_d6_ea();
  لكل (ناپ_t i = (ناپ_t)0U; i < serialized.meta / (ناپ_t)24U; i++)
  {
    ناپ_t i0 = i;
    Eurydice_borrow_ٹکڑا_u8
    بائٹاں =
      Eurydice_ٹکڑا_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .شروع = i0 * (ناپ_t)24U,
            .سرا = i0 * (ناپ_t)24U + (ناپ_t)24U
          }
        ));
    Eurydice_arr_d6 uu____0 = libcrux_ml_kem_سمتیہ_portable_deserialize_12_b8(بائٹاں);
    re.انکڑے[i0] = uu____0;
  }
  أرجع re;
}

/**
 Call [`deserialize_to_uncompressed_ring_element`] for each ring element.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.deserialize_vector
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_kem_ind_cpa_deserialize_سمتیہ_68(
  Eurydice_borrow_ٹکڑا_u8 secret_کلید,
  Eurydice_arr_bb0 *secret_as_ntt
)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)3U; i++)
  {
    ناپ_t i0 = i;
    Eurydice_arr_9e
    uu____0 =
      libcrux_ml_kem_serialize_deserialize_منزل_uncompressed_ring_element_ea(Eurydice_ٹکڑا_subslice_shared_c8(secret_کلید,
          (
            KRML_CLITERAL(core_ops_range_Range_87){
              .شروع = i0 * LIBCRUX_ML_KEM_CONSTANTS_بائٹاں_فی_RING_ELEMENT,
              .سرا = (i0 + (ناپ_t)1U) * LIBCRUX_ML_KEM_CONSTANTS_بائٹاں_فی_RING_ELEMENT
            }
          )));
    secret_as_ntt->انکڑے[i0] = uu____0;
  }
}

/**
This function found in impl {core::ops::function::FnMut<(usize), libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]> for libcrux_ml_kem::ind_cpa::deserialize_then_decompress_u::closure<Vector, K, CIPHERTEXT_SIZE, U_COMPRESSION_FACTOR>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.deserialize_then_decompress_u.call_mut_35
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- CIPHERTEXT_SIZE= 1088
- U_COMPRESSION_FACTOR= 10
*/
ساكن مضمن Eurydice_arr_9e
libcrux_ml_kem_ind_cpa_deserialize_then_decompress_u_call_mut_35_30(
  فراغ **_,
  ناپ_t tupled_دلیلاں
)
{
  أرجع libcrux_ml_kem_polynomial_ZERO_d6_ea();
}

/**
A monomorphic instance of libcrux_ml_kem.vector.portable.compress.decompress_ciphertext_coefficient
with const generics
- COEFFICIENT_BITS= 10
*/
ساكن KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_compress_decompress_ciphertext_coefficient_ef(Eurydice_arr_d6 a)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < LIBCRUX_ML_KEM_سمتیہ_TRAITS_میدان_ELEMENTS_وچ_سمتیہ; i++)
  {
    ناپ_t i0 = i;
    int32_t
    decompressed =
      libcrux_secrets_int_as_i32_f5(a.انکڑے[i0]) *
        libcrux_secrets_int_as_i32_f5(libcrux_secrets_int_عوامی_integers_classify_27_39(LIBCRUX_ML_KEM_سمتیہ_TRAITS_میدان_MODULUS));
    decompressed = (int32_t)((uint32_t)decompressed << 1U) + (int32_t)((uint32_t)1 << (uint32_t)10);
    decompressed >>= (uint32_t)(10 + 1);
    a.انکڑے[i0] = libcrux_secrets_int_as_i16_36(decompressed);
  }
  أرجع a;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
/**
A monomorphic instance of libcrux_ml_kem.vector.portable.decompress_ciphertext_coefficient_b8
with const generics
- COEFFICIENT_BITS= 10
*/
ساكن مضمن Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_decompress_ciphertext_coefficient_b8_ef(Eurydice_arr_d6 a)
{
  أرجع libcrux_ml_kem_سمتیہ_portable_compress_decompress_ciphertext_coefficient_ef(a);
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.deserialize_then_decompress_10
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ساكن KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_serialize_deserialize_then_decompress_10_ea(Eurydice_borrow_ٹکڑا_u8 serialized)
{
  Eurydice_arr_9e re = libcrux_ml_kem_polynomial_ZERO_d6_ea();
  لكل (ناپ_t i = (ناپ_t)0U; i < serialized.meta / (ناپ_t)20U; i++)
  {
    ناپ_t i0 = i;
    Eurydice_borrow_ٹکڑا_u8
    بائٹاں =
      Eurydice_ٹکڑا_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .شروع = i0 * (ناپ_t)20U,
            .سرا = i0 * (ناپ_t)20U + (ناپ_t)20U
          }
        ));
    Eurydice_arr_d6 coefficient = libcrux_ml_kem_سمتیہ_portable_deserialize_10_b8(بائٹاں);
    Eurydice_arr_d6
    uu____0 = libcrux_ml_kem_سمتیہ_portable_decompress_ciphertext_coefficient_b8_ef(coefficient);
    re.انکڑے[i0] = uu____0;
  }
  أرجع re;
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.deserialize_then_decompress_ring_element_u
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- COMPRESSION_FACTOR= 10
*/
ساكن KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_serialize_deserialize_then_decompress_ring_element_u_f7(
  Eurydice_borrow_ٹکڑا_u8 serialized
)
{
  أرجع libcrux_ml_kem_serialize_deserialize_then_decompress_10_ea(serialized);
}

تعريفنوع بنية libcrux_ml_kem_سمتیہ_portable_سمتیہ_type_Portable_سمتیہ_x2_s
{
  Eurydice_arr_d6 fst;
  Eurydice_arr_d6 snd;
}
libcrux_ml_kem_سمتیہ_portable_سمتیہ_type_Portable_سمتیہ_x2;

/**
A monomorphic instance of libcrux_ml_kem.ntt.ntt_layer_int_vec_step
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ساكن KRML_MUSTINLINE libcrux_ml_kem_سمتیہ_portable_سمتیہ_type_Portable_سمتیہ_x2
libcrux_ml_kem_ntt_ntt_layer_int_vec_قدم_ea(
  Eurydice_arr_d6 a,
  Eurydice_arr_d6 b,
  int16_t zeta_r
)
{
  Eurydice_arr_d6
  t = libcrux_ml_kem_سمتیہ_portable_montgomery_multiply_by_constant_b8(b, zeta_r);
  b = libcrux_ml_kem_سمتیہ_portable_sub_b8(a, &t);
  a = libcrux_ml_kem_سمتیہ_portable_جوڑو_b8(a, &t);
  أرجع
    (
      KRML_CLITERAL(libcrux_ml_kem_سمتیہ_portable_سمتیہ_type_Portable_سمتیہ_x2){
        .fst = a,
        .snd = b
      }
    );
}

/**
A monomorphic instance of libcrux_ml_kem.ntt.ntt_at_layer_4_plus
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_kem_ntt_ntt_at_layer_4_plus_ea(
  ناپ_t *zeta_i,
  Eurydice_arr_9e *re,
  ناپ_t layer,
  ناپ_t _initial_coefficient_bound
)
{
  ناپ_t قدم = (ناپ_t)1U << (uint32_t)layer;
  لكل (ناپ_t i0 = (ناپ_t)0U; i0 < (ناپ_t)128U >> (uint32_t)layer; i0++)
  {
    ناپ_t گیڑا = i0;
    zeta_i[0U]++;
    ناپ_t وتھ = گیڑا * قدم * (ناپ_t)2U;
    ناپ_t وتھ_vec = وتھ / (ناپ_t)16U;
    ناپ_t قدم_vec = قدم / (ناپ_t)16U;
    لكل (ناپ_t i = وتھ_vec; i < وتھ_vec + قدم_vec; i++)
    {
      ناپ_t j = i;
      libcrux_ml_kem_سمتیہ_portable_سمتیہ_type_Portable_سمتیہ_x2
      uu____0 =
        libcrux_ml_kem_ntt_ntt_layer_int_vec_قدم_ea(re->انکڑے[j],
          re->انکڑے[j + قدم_vec],
          libcrux_ml_kem_polynomial_zeta(zeta_i[0U]));
      Eurydice_arr_d6 x = uu____0.fst;
      Eurydice_arr_d6 y = uu____0.snd;
      re->انکڑے[j] = x;
      re->انکڑے[j + قدم_vec] = y;
    }
  }
}

/**
A monomorphic instance of libcrux_ml_kem.ntt.ntt_at_layer_3
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_kem_ntt_ntt_at_layer_3_ea(
  ناپ_t *zeta_i,
  Eurydice_arr_9e *re,
  ناپ_t _initial_coefficient_bound
)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)16U; i++)
  {
    ناپ_t گیڑا = i;
    zeta_i[0U]++;
    Eurydice_arr_d6
    uu____0 =
      libcrux_ml_kem_سمتیہ_portable_ntt_layer_3_قدم_b8(re->انکڑے[گیڑا],
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U]));
    re->انکڑے[گیڑا] = uu____0;
  }
}

/**
A monomorphic instance of libcrux_ml_kem.ntt.ntt_at_layer_2
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_kem_ntt_ntt_at_layer_2_ea(
  ناپ_t *zeta_i,
  Eurydice_arr_9e *re,
  ناپ_t _initial_coefficient_bound
)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)16U; i++)
  {
    ناپ_t گیڑا = i;
    zeta_i[0U]++;
    re->انکڑے[گیڑا] =
      libcrux_ml_kem_سمتیہ_portable_ntt_layer_2_قدم_b8(re->انکڑے[گیڑا],
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U]),
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U] + (ناپ_t)1U));
    zeta_i[0U]++;
  }
}

/**
A monomorphic instance of libcrux_ml_kem.ntt.ntt_at_layer_1
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_kem_ntt_ntt_at_layer_1_ea(
  ناپ_t *zeta_i,
  Eurydice_arr_9e *re,
  ناپ_t _initial_coefficient_bound
)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)16U; i++)
  {
    ناپ_t گیڑا = i;
    zeta_i[0U]++;
    re->انکڑے[گیڑا] =
      libcrux_ml_kem_سمتیہ_portable_ntt_layer_1_قدم_b8(re->انکڑے[گیڑا],
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U]),
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U] + (ناپ_t)1U),
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U] + (ناپ_t)2U),
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U] + (ناپ_t)3U));
    zeta_i[0U] += (ناپ_t)3U;
  }
}

/**
A monomorphic instance of libcrux_ml_kem.polynomial.poly_barrett_reduce
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_kem_polynomial_poly_barrett_reduce_ea(Eurydice_arr_9e *myself)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_وچ_RING_ELEMENT; i++)
  {
    ناپ_t i0 = i;
    Eurydice_arr_d6 uu____0 = libcrux_ml_kem_سمتیہ_portable_barrett_reduce_b8(myself->انکڑے[i0]);
    myself->انکڑے[i0] = uu____0;
  }
}

/**
This function found in impl {libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.polynomial.poly_barrett_reduce_d6
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_kem_polynomial_poly_barrett_reduce_d6_ea(Eurydice_arr_9e *self)
{
  libcrux_ml_kem_polynomial_poly_barrett_reduce_ea(self);
}

/**
A monomorphic instance of libcrux_ml_kem.ntt.ntt_vector_u
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- VECTOR_U_COMPRESSION_FACTOR= 10
*/
ساكن KRML_MUSTINLINE فراغ libcrux_ml_kem_ntt_ntt_سمتیہ_u_f7(Eurydice_arr_9e *re)
{
  ناپ_t zeta_i = (ناپ_t)0U;
  libcrux_ml_kem_ntt_ntt_at_layer_4_plus_ea(&zeta_i, re, (ناپ_t)7U, (ناپ_t)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_4_plus_ea(&zeta_i, re, (ناپ_t)6U, (ناپ_t)2U * (ناپ_t)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_4_plus_ea(&zeta_i, re, (ناپ_t)5U, (ناپ_t)3U * (ناپ_t)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_4_plus_ea(&zeta_i, re, (ناپ_t)4U, (ناپ_t)4U * (ناپ_t)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_3_ea(&zeta_i, re, (ناپ_t)5U * (ناپ_t)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_2_ea(&zeta_i, re, (ناپ_t)6U * (ناپ_t)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_1_ea(&zeta_i, re, (ناپ_t)7U * (ناپ_t)3328U);
  libcrux_ml_kem_polynomial_poly_barrett_reduce_d6_ea(re);
}

/**
 Call [`deserialize_then_decompress_ring_element_u`] on each ring element
 in the `ciphertext`.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.deserialize_then_decompress_u
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- CIPHERTEXT_SIZE= 1088
- U_COMPRESSION_FACTOR= 10
*/
ساكن KRML_MUSTINLINE Eurydice_arr_bb0
libcrux_ml_kem_ind_cpa_deserialize_then_decompress_u_30(ثابت Eurydice_arr_2b *ciphertext)
{
  Eurydice_arr_bb0 arr_struct;
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    فراغ *lvalue = (فراغ *)0U;
    arr_struct.انکڑے[i] =
      libcrux_ml_kem_ind_cpa_deserialize_then_decompress_u_call_mut_35_30(&lvalue,
        i);
  }
  Eurydice_arr_bb0 u_as_ntt = arr_struct;
  لكل
  (ناپ_t
    i = (ناپ_t)0U;
    i <
      (ناپ_t)1088U /
        (LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_وچ_RING_ELEMENT * (ناپ_t)10U / (ناپ_t)8U);
    i++)
  {
    ناپ_t i0 = i;
    Eurydice_borrow_ٹکڑا_u8
    u_بائٹاں =
      Eurydice_array_منزل_subslice_shared_d44(ciphertext,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .شروع = i0 *
              (LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_وچ_RING_ELEMENT * (ناپ_t)10U / (ناپ_t)8U),
            .سرا = i0 *
              (LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_وچ_RING_ELEMENT * (ناپ_t)10U / (ناپ_t)8U)
            + LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_وچ_RING_ELEMENT * (ناپ_t)10U / (ناپ_t)8U
          }
        ));
    u_as_ntt.انکڑے[i0] =
      libcrux_ml_kem_serialize_deserialize_then_decompress_ring_element_u_f7(u_بائٹاں);
    libcrux_ml_kem_ntt_ntt_سمتیہ_u_f7(&u_as_ntt.انکڑے[i0]);
  }
  أرجع u_as_ntt;
}

/**
A monomorphic instance of libcrux_ml_kem.vector.portable.compress.decompress_ciphertext_coefficient
with const generics
- COEFFICIENT_BITS= 4
*/
ساكن KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_compress_decompress_ciphertext_coefficient_d1(Eurydice_arr_d6 a)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < LIBCRUX_ML_KEM_سمتیہ_TRAITS_میدان_ELEMENTS_وچ_سمتیہ; i++)
  {
    ناپ_t i0 = i;
    int32_t
    decompressed =
      libcrux_secrets_int_as_i32_f5(a.انکڑے[i0]) *
        libcrux_secrets_int_as_i32_f5(libcrux_secrets_int_عوامی_integers_classify_27_39(LIBCRUX_ML_KEM_سمتیہ_TRAITS_میدان_MODULUS));
    decompressed = (int32_t)((uint32_t)decompressed << 1U) + (int32_t)((uint32_t)1 << (uint32_t)4);
    decompressed >>= (uint32_t)(4 + 1);
    a.انکڑے[i0] = libcrux_secrets_int_as_i16_36(decompressed);
  }
  أرجع a;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
/**
A monomorphic instance of libcrux_ml_kem.vector.portable.decompress_ciphertext_coefficient_b8
with const generics
- COEFFICIENT_BITS= 4
*/
ساكن مضمن Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_decompress_ciphertext_coefficient_b8_d1(Eurydice_arr_d6 a)
{
  أرجع libcrux_ml_kem_سمتیہ_portable_compress_decompress_ciphertext_coefficient_d1(a);
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.deserialize_then_decompress_4
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ساكن KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_serialize_deserialize_then_decompress_4_ea(Eurydice_borrow_ٹکڑا_u8 serialized)
{
  Eurydice_arr_9e re = libcrux_ml_kem_polynomial_ZERO_d6_ea();
  لكل (ناپ_t i = (ناپ_t)0U; i < serialized.meta / (ناپ_t)8U; i++)
  {
    ناپ_t i0 = i;
    Eurydice_borrow_ٹکڑا_u8
    بائٹاں =
      Eurydice_ٹکڑا_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .شروع = i0 * (ناپ_t)8U,
            .سرا = i0 * (ناپ_t)8U + (ناپ_t)8U
          }
        ));
    Eurydice_arr_d6 coefficient = libcrux_ml_kem_سمتیہ_portable_deserialize_4_b8(بائٹاں);
    Eurydice_arr_d6
    uu____0 = libcrux_ml_kem_سمتیہ_portable_decompress_ciphertext_coefficient_b8_d1(coefficient);
    re.انکڑے[i0] = uu____0;
  }
  أرجع re;
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.deserialize_then_decompress_ring_element_v
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- COMPRESSION_FACTOR= 4
*/
ساكن KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_serialize_deserialize_then_decompress_ring_element_v_b6(
  Eurydice_borrow_ٹکڑا_u8 serialized
)
{
  أرجع libcrux_ml_kem_serialize_deserialize_then_decompress_4_ea(serialized);
}

/**
A monomorphic instance of libcrux_ml_kem.polynomial.ZERO
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ساكن مضمن Eurydice_arr_9e libcrux_ml_kem_polynomial_ZERO_ea(فراغ)
{
  Eurydice_arr_9e lit;
  Eurydice_arr_d6 repeat_عبارت[16U];
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)16U; i++)
  {
    repeat_عبارت[i] = libcrux_ml_kem_سمتیہ_portable_ZERO_b8();
  }
  حافظہ_نقل(lit.انکڑے, repeat_عبارت, (ناپ_t)16U * حجم (Eurydice_arr_d6));
  أرجع lit;
}

/**
 Given two `KyberPolynomialRingElement`s in their NTT representations,
 compute their product. Given two polynomials in the NTT domain `f^` and `ĵ`,
 the `iᵗʰ` coefficient of the product `k̂` is determined by the calculation:

 ```plaintext
 ĥ[2·i] + ĥ[2·i + 1]X = (f^[2·i] + f^[2·i + 1]X)·(ĝ[2·i] + ĝ[2·i + 1]X) mod (X² - ζ^(2·BitRev₇(i) + 1))
 ```

 This function almost implements <strong>Algorithm 10</strong> of the
 NIST FIPS 203 standard, which is reproduced below:

 ```plaintext
 Input: Two arrays fˆ ∈ ℤ₂₅₆ and ĝ ∈ ℤ₂₅₆.
 Output: An array ĥ ∈ ℤq.

 for(i ← 0; i < 128; i++)
     (ĥ[2i], ĥ[2i+1]) ← BaseCaseMultiply(fˆ[2i], fˆ[2i+1], ĝ[2i], ĝ[2i+1], ζ^(2·BitRev₇(i) + 1))
 end for
 return ĥ
 ```
 We say "almost" because the coefficients of the ring element output by
 this function are in the Montgomery domain.

 The NIST FIPS 203 standard can be found at
 <https://csrc.nist.gov/pubs/fips/203/ipd>.
*/
/**
A monomorphic instance of libcrux_ml_kem.polynomial.ntt_multiply
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ساكن KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_polynomial_ntt_multiply_ea(
  ثابت Eurydice_arr_9e *myself,
  ثابت Eurydice_arr_9e *rhs
)
{
  Eurydice_arr_9e باہرلا = libcrux_ml_kem_polynomial_ZERO_ea();
  لكل (ناپ_t i = (ناپ_t)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_وچ_RING_ELEMENT; i++)
  {
    ناپ_t i0 = i;
    Eurydice_arr_d6
    uu____0 =
      libcrux_ml_kem_سمتیہ_portable_ntt_multiply_b8(&myself->انکڑے[i0],
        &rhs->انکڑے[i0],
        libcrux_ml_kem_polynomial_zeta((ناپ_t)64U + (ناپ_t)4U * i0),
        libcrux_ml_kem_polynomial_zeta((ناپ_t)64U + (ناپ_t)4U * i0 + (ناپ_t)1U),
        libcrux_ml_kem_polynomial_zeta((ناپ_t)64U + (ناپ_t)4U * i0 + (ناپ_t)2U),
        libcrux_ml_kem_polynomial_zeta((ناپ_t)64U + (ناپ_t)4U * i0 + (ناپ_t)3U));
    باہرلا.انکڑے[i0] = uu____0;
  }
  أرجع باہرلا;
}

/**
This function found in impl {libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.polynomial.ntt_multiply_d6
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ساكن KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_polynomial_ntt_multiply_d6_ea(
  ثابت Eurydice_arr_9e *self,
  ثابت Eurydice_arr_9e *rhs
)
{
  أرجع libcrux_ml_kem_polynomial_ntt_multiply_ea(self, rhs);
}

/**
 Given two polynomial ring elements `lhs` and `rhs`, compute the pointwise
 sum of their constituent coefficients.
*/
/**
A monomorphic instance of libcrux_ml_kem.polynomial.add_to_ring_element
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_kem_polynomial_جوڑو_منزل_ring_element_68(
  Eurydice_arr_9e *myself,
  ثابت Eurydice_arr_9e *rhs
)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)16U; i++)
  {
    ناپ_t i0 = i;
    Eurydice_arr_d6
    uu____0 = libcrux_ml_kem_سمتیہ_portable_جوڑو_b8(myself->انکڑے[i0], &rhs->انکڑے[i0]);
    myself->انکڑے[i0] = uu____0;
  }
}

/**
 Given two polynomial ring elements `lhs` and `rhs`, compute the pointwise
 sum of their constituent coefficients.
*/
/**
This function found in impl {libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.polynomial.add_to_ring_element_d6
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_kem_polynomial_جوڑو_منزل_ring_element_d6_68(
  Eurydice_arr_9e *self,
  ثابت Eurydice_arr_9e *rhs
)
{
  libcrux_ml_kem_polynomial_جوڑو_منزل_ring_element_68(self, rhs);
}

/**
A monomorphic instance of libcrux_ml_kem.invert_ntt.invert_ntt_at_layer_1
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_1_ea(ناپ_t *zeta_i, Eurydice_arr_9e *re)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)16U; i++)
  {
    ناپ_t گیڑا = i;
    zeta_i[0U]--;
    re->انکڑے[گیڑا] =
      libcrux_ml_kem_سمتیہ_portable_inv_ntt_layer_1_قدم_b8(re->انکڑے[گیڑا],
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U]),
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U] - (ناپ_t)1U),
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U] - (ناپ_t)2U),
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U] - (ناپ_t)3U));
    zeta_i[0U] -= (ناپ_t)3U;
  }
}

/**
A monomorphic instance of libcrux_ml_kem.invert_ntt.invert_ntt_at_layer_2
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_2_ea(ناپ_t *zeta_i, Eurydice_arr_9e *re)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)16U; i++)
  {
    ناپ_t گیڑا = i;
    zeta_i[0U]--;
    re->انکڑے[گیڑا] =
      libcrux_ml_kem_سمتیہ_portable_inv_ntt_layer_2_قدم_b8(re->انکڑے[گیڑا],
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U]),
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U] - (ناپ_t)1U));
    zeta_i[0U]--;
  }
}

/**
A monomorphic instance of libcrux_ml_kem.invert_ntt.invert_ntt_at_layer_3
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_3_ea(ناپ_t *zeta_i, Eurydice_arr_9e *re)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)16U; i++)
  {
    ناپ_t گیڑا = i;
    zeta_i[0U]--;
    Eurydice_arr_d6
    uu____0 =
      libcrux_ml_kem_سمتیہ_portable_inv_ntt_layer_3_قدم_b8(re->انکڑے[گیڑا],
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U]));
    re->انکڑے[گیڑا] = uu____0;
  }
}

/**
A monomorphic instance of libcrux_ml_kem.invert_ntt.inv_ntt_layer_int_vec_step_reduce
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ساكن KRML_MUSTINLINE libcrux_ml_kem_سمتیہ_portable_سمتیہ_type_Portable_سمتیہ_x2
libcrux_ml_kem_invert_ntt_inv_ntt_layer_int_vec_قدم_reduce_ea(
  Eurydice_arr_d6 a,
  Eurydice_arr_d6 b,
  int16_t zeta_r
)
{
  Eurydice_arr_d6 a_minus_b = libcrux_ml_kem_سمتیہ_portable_sub_b8(b, &a);
  a =
    libcrux_ml_kem_سمتیہ_portable_barrett_reduce_b8(libcrux_ml_kem_سمتیہ_portable_جوڑو_b8(a, &b));
  b = libcrux_ml_kem_سمتیہ_portable_montgomery_multiply_by_constant_b8(a_minus_b, zeta_r);
  أرجع
    (
      KRML_CLITERAL(libcrux_ml_kem_سمتیہ_portable_سمتیہ_type_Portable_سمتیہ_x2){
        .fst = a,
        .snd = b
      }
    );
}

/**
A monomorphic instance of libcrux_ml_kem.invert_ntt.invert_ntt_at_layer_4_plus
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_4_plus_ea(
  ناپ_t *zeta_i,
  Eurydice_arr_9e *re,
  ناپ_t layer
)
{
  ناپ_t قدم = (ناپ_t)1U << (uint32_t)layer;
  لكل (ناپ_t i0 = (ناپ_t)0U; i0 < (ناپ_t)128U >> (uint32_t)layer; i0++)
  {
    ناپ_t گیڑا = i0;
    zeta_i[0U]--;
    ناپ_t وتھ = گیڑا * قدم * (ناپ_t)2U;
    ناپ_t وتھ_vec = وتھ / LIBCRUX_ML_KEM_سمتیہ_TRAITS_میدان_ELEMENTS_وچ_سمتیہ;
    ناپ_t قدم_vec = قدم / LIBCRUX_ML_KEM_سمتیہ_TRAITS_میدان_ELEMENTS_وچ_سمتیہ;
    لكل (ناپ_t i = وتھ_vec; i < وتھ_vec + قدم_vec; i++)
    {
      ناپ_t j = i;
      libcrux_ml_kem_سمتیہ_portable_سمتیہ_type_Portable_سمتیہ_x2
      uu____0 =
        libcrux_ml_kem_invert_ntt_inv_ntt_layer_int_vec_قدم_reduce_ea(re->انکڑے[j],
          re->انکڑے[j + قدم_vec],
          libcrux_ml_kem_polynomial_zeta(zeta_i[0U]));
      Eurydice_arr_d6 x = uu____0.fst;
      Eurydice_arr_d6 y = uu____0.snd;
      re->انکڑے[j] = x;
      re->انکڑے[j + قدم_vec] = y;
    }
  }
}

/**
A monomorphic instance of libcrux_ml_kem.invert_ntt.invert_ntt_montgomery
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_kem_invert_ntt_invert_ntt_montgomery_68(Eurydice_arr_9e *re)
{
  ناپ_t zeta_i = LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_وچ_RING_ELEMENT / (ناپ_t)2U;
  libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_1_ea(&zeta_i, re);
  libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_2_ea(&zeta_i, re);
  libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_3_ea(&zeta_i, re);
  libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_4_plus_ea(&zeta_i, re, (ناپ_t)4U);
  libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_4_plus_ea(&zeta_i, re, (ناپ_t)5U);
  libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_4_plus_ea(&zeta_i, re, (ناپ_t)6U);
  libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_4_plus_ea(&zeta_i, re, (ناپ_t)7U);
  libcrux_ml_kem_polynomial_poly_barrett_reduce_d6_ea(re);
}

/**
A monomorphic instance of libcrux_ml_kem.polynomial.subtract_reduce
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ساكن KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_polynomial_گھٹاؤ_reduce_ea(ثابت Eurydice_arr_9e *myself, Eurydice_arr_9e b)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_وچ_RING_ELEMENT; i++)
  {
    ناپ_t i0 = i;
    Eurydice_arr_d6
    coefficient_عام_form =
      libcrux_ml_kem_سمتیہ_portable_montgomery_multiply_by_constant_b8(b.انکڑے[i0],
        1441);
    Eurydice_arr_d6
    diff = libcrux_ml_kem_سمتیہ_portable_sub_b8(myself->انکڑے[i0], &coefficient_عام_form);
    Eurydice_arr_d6 red = libcrux_ml_kem_سمتیہ_portable_barrett_reduce_b8(diff);
    b.انکڑے[i0] = red;
  }
  أرجع b;
}

/**
This function found in impl {libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.polynomial.subtract_reduce_d6
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ساكن KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_polynomial_گھٹاؤ_reduce_d6_ea(ثابت Eurydice_arr_9e *self, Eurydice_arr_9e b)
{
  أرجع libcrux_ml_kem_polynomial_گھٹاؤ_reduce_ea(self, b);
}

/**
 The following functions compute various expressions involving
 vectors and matrices. The computation of these expressions has been
 abstracted away into these functions in order to save on loop iterations.
 Compute v − InverseNTT(sᵀ ◦ NTT(u))
*/
/**
A monomorphic instance of libcrux_ml_kem.matrix.compute_message
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
ساكن KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_میٹرکس_compute_سنیہا_68(
  ثابت Eurydice_arr_9e *v,
  ثابت Eurydice_arr_bb0 *secret_as_ntt,
  ثابت Eurydice_arr_bb0 *u_as_ntt
)
{
  Eurydice_arr_9e نتیجہ = libcrux_ml_kem_polynomial_ZERO_d6_ea();
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)3U; i++)
  {
    ناپ_t i0 = i;
    Eurydice_arr_9e
    ضرب_حاصل =
      libcrux_ml_kem_polynomial_ntt_multiply_d6_ea(&secret_as_ntt->انکڑے[i0],
        &u_as_ntt->انکڑے[i0]);
    libcrux_ml_kem_polynomial_جوڑو_منزل_ring_element_d6_68(&نتیجہ, &ضرب_حاصل);
  }
  libcrux_ml_kem_invert_ntt_invert_ntt_montgomery_68(&نتیجہ);
  أرجع libcrux_ml_kem_polynomial_گھٹاؤ_reduce_d6_ea(v, نتیجہ);
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.to_unsigned_field_modulus
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ساكن KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_serialize_منزل_unsigned_میدان_modulus_ea(Eurydice_arr_d6 a)
{
  أرجع libcrux_ml_kem_سمتیہ_portable_منزل_unsigned_representative_b8(a);
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.compress_then_serialize_message
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ساكن KRML_MUSTINLINE Eurydice_arr_ec
libcrux_ml_kem_serialize_compress_then_serialize_سنیہا_ea(Eurydice_arr_9e re)
{
  Eurydice_arr_ec serialized = { .انکڑے = { 0U } };
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)16U; i++)
  {
    ناپ_t i0 = i;
    Eurydice_arr_d6
    coefficient = libcrux_ml_kem_serialize_منزل_unsigned_میدان_modulus_ea(re.انکڑے[i0]);
    Eurydice_arr_d6
    coefficient_compressed = libcrux_ml_kem_سمتیہ_portable_compress_1_b8(coefficient);
    Eurydice_array_u8x2
    بائٹاں = libcrux_ml_kem_سمتیہ_portable_serialize_1_b8(coefficient_compressed);
    Eurydice_ٹکڑا_copy(Eurydice_array_منزل_subslice_mut_d46(&serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .شروع = (ناپ_t)2U * i0,
            .سرا = (ناپ_t)2U * i0 + (ناپ_t)2U
          }
        )),
      Eurydice_array_منزل_ٹکڑا_shared_82(&بائٹاں),
      uint8_t);
  }
  أرجع serialized;
}

/**
 This function implements <strong>Algorithm 14</strong> of the
 NIST FIPS 203 specification; this is the Kyber CPA-PKE decryption algorithm.

 Algorithm 14 is reproduced below:

 ```plaintext
 Input: decryption key dkₚₖₑ ∈ 𝔹^{384k}.
 Input: ciphertext c ∈ 𝔹^{32(dᵤk + dᵥ)}.
 Output: message m ∈ 𝔹^{32}.

 c₁ ← c[0 : 32dᵤk]
 c₂ ← c[32dᵤk : 32(dᵤk + dᵥ)]
 u ← Decompress_{dᵤ}(ByteDecode_{dᵤ}(c₁))
 v ← Decompress_{dᵥ}(ByteDecode_{dᵥ}(c₂))
 ŝ ← ByteDecode₁₂(dkₚₖₑ)
 w ← v - NTT-¹(ŝᵀ ◦ NTT(u))
 m ← ByteEncode₁(Compress₁(w))
 return m
 ```

 The NIST FIPS 203 standard can be found at
 <https://csrc.nist.gov/pubs/fips/203/ipd>.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.decrypt_unpacked
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- CIPHERTEXT_SIZE= 1088
- VECTOR_U_ENCODED_SIZE= 960
- U_COMPRESSION_FACTOR= 10
- V_COMPRESSION_FACTOR= 4
*/
ساكن KRML_MUSTINLINE Eurydice_arr_ec
libcrux_ml_kem_ind_cpa_decrypt_unpacked_01(
  ثابت Eurydice_arr_bb0 *secret_کلید,
  ثابت Eurydice_arr_2b *ciphertext
)
{
  Eurydice_arr_bb0
  u_as_ntt = libcrux_ml_kem_ind_cpa_deserialize_then_decompress_u_30(ciphertext);
  Eurydice_arr_9e
  v =
    libcrux_ml_kem_serialize_deserialize_then_decompress_ring_element_v_b6(Eurydice_array_منزل_subslice_from_shared_5f0(ciphertext,
        (ناپ_t)960U));
  Eurydice_arr_9e سنیہا = libcrux_ml_kem_میٹرکس_compute_سنیہا_68(&v, secret_کلید, &u_as_ntt);
  أرجع libcrux_ml_kem_serialize_compress_then_serialize_سنیہا_ea(سنیہا);
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.decrypt
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- CIPHERTEXT_SIZE= 1088
- VECTOR_U_ENCODED_SIZE= 960
- U_COMPRESSION_FACTOR= 10
- V_COMPRESSION_FACTOR= 4
*/
ساكن KRML_MUSTINLINE Eurydice_arr_ec
libcrux_ml_kem_ind_cpa_decrypt_01(
  Eurydice_borrow_ٹکڑا_u8 secret_کلید,
  ثابت Eurydice_arr_2b *ciphertext
)
{
  Eurydice_arr_bb0 arr_struct;
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    فراغ *lvalue = (فراغ *)0U;
    arr_struct.انکڑے[i] = libcrux_ml_kem_ind_cpa_decrypt_call_mut_0b_01(&lvalue, i);
  }
  Eurydice_arr_bb0 secret_کلید_unpacked = arr_struct;
  libcrux_ml_kem_ind_cpa_deserialize_سمتیہ_68(secret_کلید, &secret_کلید_unpacked);
  أرجع libcrux_ml_kem_ind_cpa_decrypt_unpacked_01(&secret_کلید_unpacked, ciphertext);
}

/**
This function found in impl {libcrux_ml_kem::hash_functions::Hash<K> for libcrux_ml_kem::hash_functions::portable::PortableHash<K>}
*/
/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.G_4a
with const generics
- K= 3
*/
ساكن مضمن Eurydice_arr_c7
libcrux_ml_kem_hash_functions_portable_G_4a_78(Eurydice_borrow_ٹکڑا_u8 داخلہ)
{
  أرجع libcrux_ml_kem_hash_functions_portable_G(داخلہ);
}

/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.PRF
with const generics
- LEN= 32
*/
ساكن مضمن Eurydice_arr_ec
libcrux_ml_kem_hash_functions_portable_PRF_ce(Eurydice_borrow_ٹکڑا_u8 داخلہ)
{
  Eurydice_arr_ec digest = { .انکڑے = { 0U } };
  libcrux_sha3_portable_shake256(Eurydice_array_منزل_ٹکڑا_mut_01(&digest), داخلہ);
  أرجع digest;
}

/**
This function found in impl {libcrux_ml_kem::hash_functions::Hash<K> for libcrux_ml_kem::hash_functions::portable::PortableHash<K>}
*/
/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.PRF_4a
with const generics
- K= 3
- LEN= 32
*/
ساكن مضمن Eurydice_arr_ec
libcrux_ml_kem_hash_functions_portable_PRF_4a_3b(Eurydice_borrow_ٹکڑا_u8 داخلہ)
{
  أرجع libcrux_ml_kem_hash_functions_portable_PRF_ce(داخلہ);
}

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_bb0
with const generics
- $3size_t
*/
تعريفنوع بنية Eurydice_arr_c10_s { Eurydice_arr_bb0 انکڑے[3U]; } Eurydice_arr_c10;

/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.unpacked.IndCpaPublicKeyUnpacked
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- $3size_t
*/
تعريفنوع بنية libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_عوامی_کلید_Unpacked_51_s
{
  Eurydice_arr_bb0 t_as_ntt;
  Eurydice_arr_ec بیج_for_A;
  Eurydice_arr_c10 A;
}
libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_عوامی_کلید_Unpacked_51;

/**
This function found in impl {core::default::Default for libcrux_ml_kem::ind_cpa::unpacked::IndCpaPublicKeyUnpacked<Vector, K>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.unpacked.default_8b
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
ساكن مضمن libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_عوامی_کلید_Unpacked_51
libcrux_ml_kem_ind_cpa_unpacked_default_8b_68(فراغ)
{
  Eurydice_arr_bb0 uu____0;
  Eurydice_arr_9e repeat_expression0[3U];
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)3U; i++)
  {
    repeat_expression0[i] = libcrux_ml_kem_polynomial_ZERO_d6_ea();
  }
  حافظہ_نقل(uu____0.انکڑے, repeat_expression0, (ناپ_t)3U * حجم (Eurydice_arr_9e));
  Eurydice_arr_ec uu____1 = { .انکڑے = { 0U } };
  libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_عوامی_کلید_Unpacked_51 lit0;
  lit0.t_as_ntt = uu____0;
  lit0.بیج_for_A = uu____1;
  Eurydice_arr_bb0 repeat_expression1[3U];
  لكل (ناپ_t i0 = (ناپ_t)0U; i0 < (ناپ_t)3U; i0++)
  {
    Eurydice_arr_bb0 lit;
    Eurydice_arr_9e repeat_عبارت[3U];
    لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)3U; i++)
    {
      repeat_عبارت[i] = libcrux_ml_kem_polynomial_ZERO_d6_ea();
    }
    حافظہ_نقل(lit.انکڑے, repeat_عبارت, (ناپ_t)3U * حجم (Eurydice_arr_9e));
    repeat_expression1[i0] = lit;
  }
  حافظہ_نقل(lit0.A.انکڑے, repeat_expression1, (ناپ_t)3U * حجم (Eurydice_arr_bb0));
  أرجع lit0;
}

/**
 Only use with public values.

 This MUST NOT be used with secret inputs, like its caller `deserialize_ring_elements_reduced`.
*/
/**
A monomorphic instance of libcrux_ml_kem.serialize.deserialize_to_reduced_ring_element
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ساكن KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_serialize_deserialize_منزل_reduced_ring_element_ea(
  Eurydice_borrow_ٹکڑا_u8 serialized
)
{
  Eurydice_arr_9e re = libcrux_ml_kem_polynomial_ZERO_d6_ea();
  لكل (ناپ_t i = (ناپ_t)0U; i < serialized.meta / (ناپ_t)24U; i++)
  {
    ناپ_t i0 = i;
    Eurydice_borrow_ٹکڑا_u8
    بائٹاں =
      Eurydice_ٹکڑا_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .شروع = i0 * (ناپ_t)24U,
            .سرا = i0 * (ناپ_t)24U + (ناپ_t)24U
          }
        ));
    Eurydice_arr_d6 coefficient = libcrux_ml_kem_سمتیہ_portable_deserialize_12_b8(بائٹاں);
    Eurydice_arr_d6 uu____0 = libcrux_ml_kem_سمتیہ_portable_cond_گھٹاؤ_3329_b8(coefficient);
    re.انکڑے[i0] = uu____0;
  }
  أرجع re;
}

/**
 See [deserialize_ring_elements_reduced_out].
*/
/**
A monomorphic instance of libcrux_ml_kem.serialize.deserialize_ring_elements_reduced
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_kem_serialize_deserialize_ring_elements_reduced_68(
  Eurydice_borrow_ٹکڑا_u8 عوامی_کلید,
  Eurydice_arr_bb0 *deserialized_pk
)
{
  لكل
  (ناپ_t
    i = (ناپ_t)0U;
    i < عوامی_کلید.meta / LIBCRUX_ML_KEM_CONSTANTS_بائٹاں_فی_RING_ELEMENT;
    i++)
  {
    ناپ_t i0 = i;
    Eurydice_borrow_ٹکڑا_u8
    ring_element =
      Eurydice_ٹکڑا_subslice_shared_c8(عوامی_کلید,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .شروع = i0 * LIBCRUX_ML_KEM_CONSTANTS_بائٹاں_فی_RING_ELEMENT,
            .سرا = i0 * LIBCRUX_ML_KEM_CONSTANTS_بائٹاں_فی_RING_ELEMENT +
              LIBCRUX_ML_KEM_CONSTANTS_بائٹاں_فی_RING_ELEMENT
          }
        ));
    Eurydice_arr_9e
    uu____0 = libcrux_ml_kem_serialize_deserialize_منزل_reduced_ring_element_ea(ring_element);
    deserialized_pk->انکڑے[i0] = uu____0;
  }
}

/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.shake128_init_absorb_final
with const generics
- K= 3
*/
ساكن مضمن Eurydice_arr_1b0
libcrux_ml_kem_hash_functions_portable_shake128_init_absorb_final_78(
  ثابت Eurydice_arr_810 *داخلہ
)
{
  Eurydice_arr_1b0 shake128_state;
  Eurydice_arr_7c repeat_عبارت[3U];
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)3U; i++)
  {
    repeat_عبارت[i] = libcrux_sha3_portable_incremental_shake128_init();
  }
  حافظہ_نقل(shake128_state.انکڑے, repeat_عبارت, (ناپ_t)3U * حجم (Eurydice_arr_7c));
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)3U; i++)
  {
    ناپ_t i0 = i;
    libcrux_sha3_portable_incremental_shake128_absorb_final(&shake128_state.انکڑے[i0],
      Eurydice_array_منزل_ٹکڑا_shared_e9(&داخلہ->انکڑے[i0]));
  }
  أرجع shake128_state;
}

/**
This function found in impl {libcrux_ml_kem::hash_functions::Hash<K> for libcrux_ml_kem::hash_functions::portable::PortableHash<K>}
*/
/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.shake128_init_absorb_final_4a
with const generics
- K= 3
*/
ساكن مضمن Eurydice_arr_1b0
libcrux_ml_kem_hash_functions_portable_shake128_init_absorb_final_4a_78(
  ثابت Eurydice_arr_810 *داخلہ
)
{
  أرجع libcrux_ml_kem_hash_functions_portable_shake128_init_absorb_final_78(داخلہ);
}

/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.shake128_squeeze_first_three_blocks
with const generics
- K= 3
*/
ساكن مضمن Eurydice_arr_7e
libcrux_ml_kem_hash_functions_portable_shake128_squeeze_پہلا_three_بلاکاں_78(
  Eurydice_arr_1b0 *st
)
{
  Eurydice_arr_7e
  باہرلا = { .انکڑے = { { .انکڑے = { 0U } }, { .انکڑے = { 0U } }, { .انکڑے = { 0U } } } };
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)3U; i++)
  {
    ناپ_t i0 = i;
    libcrux_sha3_portable_incremental_shake128_squeeze_پہلا_three_بلاکاں(&st->انکڑے[i0],
      Eurydice_array_منزل_ٹکڑا_mut_48(&باہرلا.انکڑے[i0]));
  }
  أرجع باہرلا;
}

/**
This function found in impl {libcrux_ml_kem::hash_functions::Hash<K> for libcrux_ml_kem::hash_functions::portable::PortableHash<K>}
*/
/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.shake128_squeeze_first_three_blocks_4a
with const generics
- K= 3
*/
ساكن مضمن Eurydice_arr_7e
libcrux_ml_kem_hash_functions_portable_shake128_squeeze_پہلا_three_بلاکاں_4a_78(
  Eurydice_arr_1b0 *self
)
{
  أرجع libcrux_ml_kem_hash_functions_portable_shake128_squeeze_پہلا_three_بلاکاں_78(self);
}

/**
 If `bytes` contains a set of uniformly random bytes, this function
 uniformly samples a ring element `â` that is treated as being the NTT representation
 of the corresponding polynomial `a`.

 Since rejection sampling is used, it is possible the supplied bytes are
 not enough to sample the element, in which case an `Err` is returned and the
 caller must try again with a fresh set of bytes.

 This function <strong>partially</strong> implements <strong>Algorithm 6</strong> of the NIST FIPS 203 standard,
 We say "partially" because this implementation only accepts a finite set of
 bytes as input and returns an error if the set is not enough; Algorithm 6 of
 the FIPS 203 standard on the other hand samples from an infinite stream of bytes
 until the ring element is filled. Algorithm 6 is reproduced below:

 ```plaintext
 Input: byte stream B ∈ 𝔹*.
 Output: array â ∈ ℤ₂₅₆.

 i ← 0
 j ← 0
 while j < 256 do
     d₁ ← B[i] + 256·(B[i+1] mod 16)
     d₂ ← ⌊B[i+1]/16⌋ + 16·B[i+2]
     if d₁ < q then
         â[j] ← d₁
         j ← j + 1
     end if
     if d₂ < q and j < 256 then
         â[j] ← d₂
         j ← j + 1
     end if
     i ← i + 3
 end while
 return â
 ```

 The NIST FIPS 203 standard can be found at
 <https://csrc.nist.gov/pubs/fips/203/ipd>.
*/
/**
A monomorphic instance of libcrux_ml_kem.sampling.sample_from_uniform_distribution_next
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- N= 504
*/
ساكن KRML_MUSTINLINE bool
libcrux_ml_kem_sampling_sample_from_اکسار_distribution_اگلا_b6(
  ثابت Eurydice_arr_7e *randomness,
  Eurydice_arr_eb *sampled_coefficients,
  Eurydice_arr_b1 *باہرلا
)
{
  لكل (ناپ_t i0 = (ناپ_t)0U; i0 < (ناپ_t)3U; i0++)
  {
    ناپ_t i1 = i0;
    لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)504U / (ناپ_t)24U; i++)
    {
      ناپ_t r = i;
      إذا (sampled_coefficients->انکڑے[i1] < LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_وچ_RING_ELEMENT)
      {
        ناپ_t
        sampled =
          libcrux_ml_kem_سمتیہ_portable_rej_sample_b8(Eurydice_array_منزل_subslice_shared_d45(&randomness->انکڑے[i1],
              (
                KRML_CLITERAL(core_ops_range_Range_87){
                  .شروع = r * (ناپ_t)24U,
                  .سرا = r * (ناپ_t)24U + (ناپ_t)24U
                }
              )),
            Eurydice_array_منزل_subslice_mut_e7(&باہرلا->انکڑے[i1],
              (
                KRML_CLITERAL(core_ops_range_Range_87){
                  .شروع = sampled_coefficients->انکڑے[i1],
                  .سرا = sampled_coefficients->انکڑے[i1] + (ناپ_t)16U
                }
              )));
        ناپ_t uu____0 = i1;
        sampled_coefficients->انکڑے[uu____0] += sampled;
      }
    }
  }
  bool پورا = true;
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)3U; i++)
  {
    ناپ_t i0 = i;
    إذا (sampled_coefficients->انکڑے[i0] >= LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_وچ_RING_ELEMENT)
    {
      sampled_coefficients->انکڑے[i0] = LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_وچ_RING_ELEMENT;
    }
    وإلا
    {
      پورا = false;
    }
  }
  أرجع پورا;
}

/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.shake128_squeeze_next_block
with const generics
- K= 3
*/
ساكن مضمن Eurydice_arr_2c
libcrux_ml_kem_hash_functions_portable_shake128_squeeze_اگلا_بلاک_78(Eurydice_arr_1b0 *st)
{
  Eurydice_arr_2c
  باہرلا = { .انکڑے = { { .انکڑے = { 0U } }, { .انکڑے = { 0U } }, { .انکڑے = { 0U } } } };
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)3U; i++)
  {
    ناپ_t i0 = i;
    libcrux_sha3_portable_incremental_shake128_squeeze_اگلا_بلاک(&st->انکڑے[i0],
      Eurydice_array_منزل_ٹکڑا_mut_2c(&باہرلا.انکڑے[i0]));
  }
  أرجع باہرلا;
}

/**
This function found in impl {libcrux_ml_kem::hash_functions::Hash<K> for libcrux_ml_kem::hash_functions::portable::PortableHash<K>}
*/
/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.shake128_squeeze_next_block_4a
with const generics
- K= 3
*/
ساكن مضمن Eurydice_arr_2c
libcrux_ml_kem_hash_functions_portable_shake128_squeeze_اگلا_بلاک_4a_78(
  Eurydice_arr_1b0 *self
)
{
  أرجع libcrux_ml_kem_hash_functions_portable_shake128_squeeze_اگلا_بلاک_78(self);
}

/**
 If `bytes` contains a set of uniformly random bytes, this function
 uniformly samples a ring element `â` that is treated as being the NTT representation
 of the corresponding polynomial `a`.

 Since rejection sampling is used, it is possible the supplied bytes are
 not enough to sample the element, in which case an `Err` is returned and the
 caller must try again with a fresh set of bytes.

 This function <strong>partially</strong> implements <strong>Algorithm 6</strong> of the NIST FIPS 203 standard,
 We say "partially" because this implementation only accepts a finite set of
 bytes as input and returns an error if the set is not enough; Algorithm 6 of
 the FIPS 203 standard on the other hand samples from an infinite stream of bytes
 until the ring element is filled. Algorithm 6 is reproduced below:

 ```plaintext
 Input: byte stream B ∈ 𝔹*.
 Output: array â ∈ ℤ₂₅₆.

 i ← 0
 j ← 0
 while j < 256 do
     d₁ ← B[i] + 256·(B[i+1] mod 16)
     d₂ ← ⌊B[i+1]/16⌋ + 16·B[i+2]
     if d₁ < q then
         â[j] ← d₁
         j ← j + 1
     end if
     if d₂ < q and j < 256 then
         â[j] ← d₂
         j ← j + 1
     end if
     i ← i + 3
 end while
 return â
 ```

 The NIST FIPS 203 standard can be found at
 <https://csrc.nist.gov/pubs/fips/203/ipd>.
*/
/**
A monomorphic instance of libcrux_ml_kem.sampling.sample_from_uniform_distribution_next
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- N= 168
*/
ساكن KRML_MUSTINLINE bool
libcrux_ml_kem_sampling_sample_from_اکسار_distribution_اگلا_b60(
  ثابت Eurydice_arr_2c *randomness,
  Eurydice_arr_eb *sampled_coefficients,
  Eurydice_arr_b1 *باہرلا
)
{
  لكل (ناپ_t i0 = (ناپ_t)0U; i0 < (ناپ_t)3U; i0++)
  {
    ناپ_t i1 = i0;
    لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)168U / (ناپ_t)24U; i++)
    {
      ناپ_t r = i;
      إذا (sampled_coefficients->انکڑے[i1] < LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_وچ_RING_ELEMENT)
      {
        ناپ_t
        sampled =
          libcrux_ml_kem_سمتیہ_portable_rej_sample_b8(Eurydice_array_منزل_subslice_shared_d46(&randomness->انکڑے[i1],
              (
                KRML_CLITERAL(core_ops_range_Range_87){
                  .شروع = r * (ناپ_t)24U,
                  .سرا = r * (ناپ_t)24U + (ناپ_t)24U
                }
              )),
            Eurydice_array_منزل_subslice_mut_e7(&باہرلا->انکڑے[i1],
              (
                KRML_CLITERAL(core_ops_range_Range_87){
                  .شروع = sampled_coefficients->انکڑے[i1],
                  .سرا = sampled_coefficients->انکڑے[i1] + (ناپ_t)16U
                }
              )));
        ناپ_t uu____0 = i1;
        sampled_coefficients->انکڑے[uu____0] += sampled;
      }
    }
  }
  bool پورا = true;
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)3U; i++)
  {
    ناپ_t i0 = i;
    إذا (sampled_coefficients->انکڑے[i0] >= LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_وچ_RING_ELEMENT)
    {
      sampled_coefficients->انکڑے[i0] = LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_وچ_RING_ELEMENT;
    }
    وإلا
    {
      پورا = false;
    }
  }
  أرجع پورا;
}

/**
A monomorphic instance of libcrux_ml_kem.polynomial.from_i16_array
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ساكن KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_polynomial_from_i16_array_ea(Eurydice_borrow_ٹکڑا_i16 a)
{
  Eurydice_arr_9e نتیجہ = libcrux_ml_kem_polynomial_ZERO_ea();
  لكل (ناپ_t i = (ناپ_t)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_وچ_RING_ELEMENT; i++)
  {
    ناپ_t i0 = i;
    Eurydice_arr_d6
    uu____0 =
      libcrux_ml_kem_سمتیہ_portable_from_i16_array_b8(Eurydice_ٹکڑا_subslice_shared_a6(a,
          (
            KRML_CLITERAL(core_ops_range_Range_87){
              .شروع = i0 * (ناپ_t)16U,
              .سرا = (i0 + (ناپ_t)1U) * (ناپ_t)16U
            }
          )));
    نتیجہ.انکڑے[i0] = uu____0;
  }
  أرجع نتیجہ;
}

/**
This function found in impl {libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.polynomial.from_i16_array_d6
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ساكن KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_polynomial_from_i16_array_d6_ea(Eurydice_borrow_ٹکڑا_i16 a)
{
  أرجع libcrux_ml_kem_polynomial_from_i16_array_ea(a);
}

/**
This function found in impl {core::ops::function::FnMut<([i16; 272usize]), libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@2]> for libcrux_ml_kem::sampling::sample_from_xof::closure<Vector, Hasher, K>[TraitClause@0, TraitClause@1, TraitClause@2, TraitClause@3]}
*/
/**
A monomorphic instance of libcrux_ml_kem.sampling.sample_from_xof.call_mut_0a
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
*/
ساكن مضمن Eurydice_arr_9e
libcrux_ml_kem_sampling_sample_from_xof_call_mut_0a_91(فراغ **_, Eurydice_arr_5b tupled_دلیلاں)
{
  Eurydice_arr_5b s = tupled_دلیلاں;
  أرجع
    libcrux_ml_kem_polynomial_from_i16_array_d6_ea(Eurydice_array_منزل_subslice_shared_e70(&s,
        (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = (ناپ_t)0U, .سرا = (ناپ_t)256U })));
}

/**
A monomorphic instance of libcrux_ml_kem.sampling.sample_from_xof
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
*/
ساكن KRML_MUSTINLINE Eurydice_arr_bb0
libcrux_ml_kem_sampling_sample_from_xof_91(ثابت Eurydice_arr_810 *seeds)
{
  Eurydice_arr_eb sampled_coefficients = { .انکڑے = { 0U } };
  Eurydice_arr_b1
  باہرلا = { .انکڑے = { { .انکڑے = { 0U } }, { .انکڑے = { 0U } }, { .انکڑے = { 0U } } } };
  Eurydice_arr_1b0
  xof_state = libcrux_ml_kem_hash_functions_portable_shake128_init_absorb_final_4a_78(seeds);
  Eurydice_arr_7e
  randomness0 =
    libcrux_ml_kem_hash_functions_portable_shake128_squeeze_پہلا_three_بلاکاں_4a_78(&xof_state);
  bool
  پورا =
    libcrux_ml_kem_sampling_sample_from_اکسار_distribution_اگلا_b6(&randomness0,
      &sampled_coefficients,
      &باہرلا);
  طالما (true)
  {
    إذا (پورا)
    {
      اكسر;
    }
    وإلا
    {
      Eurydice_arr_2c
      randomness =
        libcrux_ml_kem_hash_functions_portable_shake128_squeeze_اگلا_بلاک_4a_78(&xof_state);
      پورا =
        libcrux_ml_kem_sampling_sample_from_اکسار_distribution_اگلا_b60(&randomness,
          &sampled_coefficients,
          &باہرلا);
    }
  }
  Eurydice_arr_bb0 arr_mapped_str;
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    فراغ *lvalue = (فراغ *)0U;
    arr_mapped_str.انکڑے[i] =
      libcrux_ml_kem_sampling_sample_from_xof_call_mut_0a_91(&lvalue,
        باہرلا.انکڑے[i]);
  }
  أرجع arr_mapped_str;
}

/**
A monomorphic instance of libcrux_ml_kem.matrix.sample_matrix_A
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_kem_میٹرکس_sample_میٹرکس_A_91(
  Eurydice_arr_c10 *A_transpose,
  ثابت Eurydice_arr_31 *بیج,
  bool transpose
)
{
  لكل (ناپ_t i0 = (ناپ_t)0U; i0 < (ناپ_t)3U; i0++)
  {
    ناپ_t i1 = i0;
    Eurydice_arr_810 seeds;
    Eurydice_arr_31 repeat_عبارت[3U];
    لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)3U; i++)
    {
      repeat_عبارت[i] =
        core_array__core__clone__Clone_for__T__N___clone((ناپ_t)34U,
          بیج,
          uint8_t,
          Eurydice_arr_31);
    }
    حافظہ_نقل(seeds.انکڑے, repeat_عبارت, (ناپ_t)3U * حجم (Eurydice_arr_31));
    لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)3U; i++)
    {
      ناپ_t j = i;
      seeds.انکڑے[j].انکڑے[32U] = (uint8_t)i1;
      seeds.انکڑے[j].انکڑے[33U] = (uint8_t)j;
    }
    Eurydice_arr_bb0 sampled = libcrux_ml_kem_sampling_sample_from_xof_91(&seeds);
    لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)3U; i++)
    {
      ناپ_t j = i;
      Eurydice_arr_9e sample = sampled.انکڑے[j];
      إذا (transpose)
      {
        A_transpose->انکڑے[j].انکڑے[i1] = sample;
      }
      وإلا
      {
        A_transpose->انکڑے[i1].انکڑے[j] = sample;
      }
    }
  }
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.build_unpacked_public_key_mut
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- T_AS_NTT_ENCODED_SIZE= 1152
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_kem_ind_cpa_build_unpacked_عوامی_کلید_mut_05(
  Eurydice_borrow_ٹکڑا_u8 عوامی_کلید,
  libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_عوامی_کلید_Unpacked_51 *unpacked_عوامی_کلید
)
{
  libcrux_ml_kem_serialize_deserialize_ring_elements_reduced_68(Eurydice_ٹکڑا_subslice_منزل_shared_72(عوامی_کلید,
      (ناپ_t)1152U),
    &unpacked_عوامی_کلید->t_as_ntt);
  Eurydice_borrow_ٹکڑا_u8
  بیج = Eurydice_ٹکڑا_subslice_from_shared_6d(عوامی_کلید, (ناپ_t)1152U);
  Eurydice_arr_c10 *uu____0 = &unpacked_عوامی_کلید->A;
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_31 lvalue = libcrux_ml_kem_utils_into_padded_array_de(بیج);
  libcrux_ml_kem_میٹرکس_sample_میٹرکس_A_91(uu____0, &lvalue, false);
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.build_unpacked_public_key
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- T_AS_NTT_ENCODED_SIZE= 1152
*/
ساكن KRML_MUSTINLINE libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_عوامی_کلید_Unpacked_51
libcrux_ml_kem_ind_cpa_build_unpacked_عوامی_کلید_05(Eurydice_borrow_ٹکڑا_u8 عوامی_کلید)
{
  libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_عوامی_کلید_Unpacked_51
  unpacked_عوامی_کلید = libcrux_ml_kem_ind_cpa_unpacked_default_8b_68();
  libcrux_ml_kem_ind_cpa_build_unpacked_عوامی_کلید_mut_05(عوامی_کلید, &unpacked_عوامی_کلید);
  أرجع unpacked_عوامی_کلید;
}

/**
A monomorphic instance of n-tuple
with types Eurydice_arr_bb0, libcrux_ml_kem_polynomial_PolynomialRingElement_1d

*/
تعريفنوع بنية tuple_c6_s
{
  Eurydice_arr_bb0 fst;
  Eurydice_arr_9e snd;
}
tuple_c6;

/**
This function found in impl {core::ops::function::FnMut<(usize), libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@2]> for libcrux_ml_kem::ind_cpa::encrypt_c1::closure<Vector, Hasher, K, C1_LEN, U_COMPRESSION_FACTOR, BLOCK_LEN, ETA1, ETA1_RANDOMNESS_SIZE, ETA2, ETA2_RANDOMNESS_SIZE>[TraitClause@0, TraitClause@1, TraitClause@2, TraitClause@3]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.encrypt_c1.call_mut_f1
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- C1_LEN= 960
- U_COMPRESSION_FACTOR= 10
- BLOCK_LEN= 320
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
- ETA2= 2
- ETA2_RANDOMNESS_SIZE= 128
*/
ساكن مضمن Eurydice_arr_9e
libcrux_ml_kem_ind_cpa_encrypt_c1_call_mut_f1_87(فراغ **_, ناپ_t tupled_دلیلاں)
{
  أرجع libcrux_ml_kem_polynomial_ZERO_d6_ea();
}

/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.PRFxN
with const generics
- K= 3
- LEN= 128
*/
ساكن مضمن Eurydice_arr_58
libcrux_ml_kem_hash_functions_portable_PRFxN_3b(ثابت Eurydice_arr_fd *داخلہ)
{
  Eurydice_arr_58
  باہرلا = { .انکڑے = { { .انکڑے = { 0U } }, { .انکڑے = { 0U } }, { .انکڑے = { 0U } } } };
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)3U; i++)
  {
    ناپ_t i0 = i;
    libcrux_sha3_portable_shake256(Eurydice_array_منزل_ٹکڑا_mut_78(&باہرلا.انکڑے[i0]),
      Eurydice_array_منزل_ٹکڑا_shared_b5(&داخلہ->انکڑے[i0]));
  }
  أرجع باہرلا;
}

/**
This function found in impl {libcrux_ml_kem::hash_functions::Hash<K> for libcrux_ml_kem::hash_functions::portable::PortableHash<K>}
*/
/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.PRFxN_4a
with const generics
- K= 3
- LEN= 128
*/
ساكن مضمن Eurydice_arr_58
libcrux_ml_kem_hash_functions_portable_PRFxN_4a_3b(ثابت Eurydice_arr_fd *داخلہ)
{
  أرجع libcrux_ml_kem_hash_functions_portable_PRFxN_3b(داخلہ);
}

/**
 Given a series of uniformly random bytes in `randomness`, for some number `eta`,
 the `sample_from_binomial_distribution_{eta}` functions sample
 a ring element from a binomial distribution centered at 0 that uses two sets
 of `eta` coin flips. If, for example,
 `eta = ETA`, each ring coefficient is a value `v` such
 such that `v ∈ {-ETA, -ETA + 1, ..., 0, ..., ETA + 1, ETA}` and:

 ```plaintext
 - If v < 0, Pr[v] = Pr[-v]
 - If v >= 0, Pr[v] = BINOMIAL_COEFFICIENT(2 * ETA; ETA - v) / 2 ^ (2 * ETA)
 ```

 The values `v < 0` are mapped to the appropriate `KyberFieldElement`.

 The expected value is:

 ```plaintext
 E[X] = (-ETA)Pr[-ETA] + (-(ETA - 1))Pr[-(ETA - 1)] + ... + (ETA - 1)Pr[ETA - 1] + (ETA)Pr[ETA]
      = 0 since Pr[-v] = Pr[v] when v < 0.
 ```

 And the variance is:

 ```plaintext
 Var(X) = E[(X - E[X])^2]
        = E[X^2]
        = sum_(v=-ETA to ETA)v^2 * (BINOMIAL_COEFFICIENT(2 * ETA; ETA - v) / 2^(2 * ETA))
        = ETA / 2
 ```

 This function implements <strong>Algorithm 7</strong> of the NIST FIPS 203 standard, which is
 reproduced below:

 ```plaintext
 Input: byte array B ∈ 𝔹^{64η}.
 Output: array f ∈ ℤ₂₅₆.

 b ← BytesToBits(B)
 for (i ← 0; i < 256; i++)
     x ← ∑(j=0 to η - 1) b[2iη + j]
     y ← ∑(j=0 to η - 1) b[2iη + η + j]
     f[i] ← x−y mod q
 end for
 return f
 ```

 The NIST FIPS 203 standard can be found at
 <https://csrc.nist.gov/pubs/fips/203/ipd>.
*/
/**
A monomorphic instance of libcrux_ml_kem.sampling.sample_from_binomial_distribution_2
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ساكن KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_sampling_sample_from_دو_رکنی_distribution_2_ea(
  Eurydice_borrow_ٹکڑا_u8 randomness
)
{
  Eurydice_arr_04 sampled_i16s = { .انکڑے = { 0U } };
  لكل (ناپ_t i0 = (ناپ_t)0U; i0 < randomness.meta / (ناپ_t)4U; i0++)
  {
    ناپ_t chunk_نمبر = i0;
    Eurydice_borrow_ٹکڑا_u8
    byte_chunk =
      Eurydice_ٹکڑا_subslice_shared_c8(randomness,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .شروع = chunk_نمبر * (ناپ_t)4U,
            .سرا = chunk_نمبر * (ناپ_t)4U + (ناپ_t)4U
          }
        ));
    uint32_t
    random_بٹ_as_u32 =
      (((uint32_t)byte_chunk.ptr[0U] | (uint32_t)byte_chunk.ptr[1U] << 8U) |
        (uint32_t)byte_chunk.ptr[2U] << 16U)
      | (uint32_t)byte_chunk.ptr[3U] << 24U;
    uint32_t even_بٹ = random_بٹ_as_u32 & 1431655765U;
    uint32_t odd_بٹ = random_بٹ_as_u32 >> 1U & 1431655765U;
    uint32_t coin_toss_outcomes = even_بٹ + odd_بٹ;
    لكل (uint32_t i = 0U; i < 32U / 4U; i++)
    {
      uint32_t outcome_سیٹ = i;
      uint32_t outcome_set0 = outcome_سیٹ * 4U;
      int16_t outcome_1 = (int16_t)(coin_toss_outcomes >> (uint32_t)outcome_set0 & 3U);
      int16_t outcome_2 = (int16_t)(coin_toss_outcomes >> (uint32_t)(outcome_set0 + 2U) & 3U);
      ناپ_t وتھ = (ناپ_t)(outcome_set0 >> 2U);
      sampled_i16s.انکڑے[(ناپ_t)8U * chunk_نمبر + وتھ] = outcome_1 - outcome_2;
    }
  }
  أرجع
    libcrux_ml_kem_polynomial_from_i16_array_d6_ea(Eurydice_array_منزل_ٹکڑا_shared_99(&sampled_i16s));
}

/**
A monomorphic instance of libcrux_ml_kem.sampling.sample_from_binomial_distribution
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- ETA= 2
*/
ساكن KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_sampling_sample_from_دو_رکنی_distribution_66(
  Eurydice_borrow_ٹکڑا_u8 randomness
)
{
  أرجع libcrux_ml_kem_sampling_sample_from_دو_رکنی_distribution_2_ea(randomness);
}

/**
A monomorphic instance of libcrux_ml_kem.ntt.ntt_at_layer_7
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ساكن KRML_MUSTINLINE فراغ libcrux_ml_kem_ntt_ntt_at_layer_7_ea(Eurydice_arr_9e *re)
{
  ناپ_t قدم = LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_وچ_RING_ELEMENT / (ناپ_t)2U;
  لكل (ناپ_t i = (ناپ_t)0U; i < قدم; i++)
  {
    ناپ_t j = i;
    Eurydice_arr_d6
    t = libcrux_ml_kem_سمتیہ_portable_multiply_by_constant_b8(re->انکڑے[j + قدم], -1600);
    re->انکڑے[j + قدم] = libcrux_ml_kem_سمتیہ_portable_sub_b8(re->انکڑے[j], &t);
    Eurydice_arr_d6 uu____1 = libcrux_ml_kem_سمتیہ_portable_جوڑو_b8(re->انکڑے[j], &t);
    re->انکڑے[j] = uu____1;
  }
}

/**
A monomorphic instance of libcrux_ml_kem.ntt.ntt_binomially_sampled_ring_element
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_kem_ntt_ntt_binomially_sampled_ring_element_ea(Eurydice_arr_9e *re)
{
  libcrux_ml_kem_ntt_ntt_at_layer_7_ea(re);
  ناپ_t zeta_i = (ناپ_t)1U;
  libcrux_ml_kem_ntt_ntt_at_layer_4_plus_ea(&zeta_i, re, (ناپ_t)6U, (ناپ_t)11207U);
  libcrux_ml_kem_ntt_ntt_at_layer_4_plus_ea(&zeta_i,
    re,
    (ناپ_t)5U,
    (ناپ_t)11207U + (ناپ_t)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_4_plus_ea(&zeta_i,
    re,
    (ناپ_t)4U,
    (ناپ_t)11207U + (ناپ_t)2U * (ناپ_t)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_3_ea(&zeta_i, re, (ناپ_t)11207U + (ناپ_t)3U * (ناپ_t)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_2_ea(&zeta_i, re, (ناپ_t)11207U + (ناپ_t)4U * (ناپ_t)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_1_ea(&zeta_i, re, (ناپ_t)11207U + (ناپ_t)5U * (ناپ_t)3328U);
  libcrux_ml_kem_polynomial_poly_barrett_reduce_d6_ea(re);
}

/**
 Sample a vector of ring elements from a centered binomial distribution and
 convert them into their NTT representations.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.sample_vector_cbd_then_ntt
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- ETA= 2
- ETA_RANDOMNESS_SIZE= 128
*/
ساكن KRML_MUSTINLINE uint8_t
libcrux_ml_kem_ind_cpa_sample_سمتیہ_cbd_then_ntt_bf(
  Eurydice_arr_bb0 *re_as_ntt,
  ثابت Eurydice_arr_fa0 *prf_داخلہ,
  uint8_t domain_separator
)
{
  Eurydice_arr_fd prf_inputs;
  Eurydice_arr_fa0 repeat_عبارت[3U];
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)3U; i++)
  {
    repeat_عبارت[i] =
      core_array__core__clone__Clone_for__T__N___clone((ناپ_t)33U,
        prf_داخلہ,
        uint8_t,
        Eurydice_arr_fa0);
  }
  حافظہ_نقل(prf_inputs.انکڑے, repeat_عبارت, (ناپ_t)3U * حجم (Eurydice_arr_fa0));
  domain_separator = libcrux_ml_kem_utils_prf_داخلہ_inc_78(&prf_inputs, domain_separator);
  Eurydice_arr_58 prf_outputs = libcrux_ml_kem_hash_functions_portable_PRFxN_4a_3b(&prf_inputs);
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)3U; i++)
  {
    ناپ_t i0 = i;
    Eurydice_arr_9e
    uu____0 =
      libcrux_ml_kem_sampling_sample_from_دو_رکنی_distribution_66(Eurydice_array_منزل_ٹکڑا_shared_78(&prf_outputs.انکڑے[i0]));
    re_as_ntt->انکڑے[i0] = uu____0;
    libcrux_ml_kem_ntt_ntt_binomially_sampled_ring_element_ea(&re_as_ntt->انکڑے[i0]);
  }
  أرجع domain_separator;
}

/**
This function found in impl {core::ops::function::FnMut<(usize), libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@2]> for libcrux_ml_kem::ind_cpa::encrypt_c1::closure#1<Vector, Hasher, K, C1_LEN, U_COMPRESSION_FACTOR, BLOCK_LEN, ETA1, ETA1_RANDOMNESS_SIZE, ETA2, ETA2_RANDOMNESS_SIZE>[TraitClause@0, TraitClause@1, TraitClause@2, TraitClause@3]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.encrypt_c1.call_mut_dd
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- C1_LEN= 960
- U_COMPRESSION_FACTOR= 10
- BLOCK_LEN= 320
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
- ETA2= 2
- ETA2_RANDOMNESS_SIZE= 128
*/
ساكن مضمن Eurydice_arr_9e
libcrux_ml_kem_ind_cpa_encrypt_c1_call_mut_dd_87(فراغ **_, ناپ_t tupled_دلیلاں)
{
  أرجع libcrux_ml_kem_polynomial_ZERO_d6_ea();
}

/**
 Sample a vector of ring elements from a centered binomial distribution.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.sample_ring_element_cbd
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- ETA2_RANDOMNESS_SIZE= 128
- ETA2= 2
*/
ساكن KRML_MUSTINLINE uint8_t
libcrux_ml_kem_ind_cpa_sample_ring_element_cbd_bf(
  ثابت Eurydice_arr_fa0 *prf_داخلہ,
  uint8_t domain_separator,
  Eurydice_arr_bb0 *error_1
)
{
  Eurydice_arr_fd prf_inputs;
  Eurydice_arr_fa0 repeat_عبارت[3U];
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)3U; i++)
  {
    repeat_عبارت[i] =
      core_array__core__clone__Clone_for__T__N___clone((ناپ_t)33U,
        prf_داخلہ,
        uint8_t,
        Eurydice_arr_fa0);
  }
  حافظہ_نقل(prf_inputs.انکڑے, repeat_عبارت, (ناپ_t)3U * حجم (Eurydice_arr_fa0));
  domain_separator = libcrux_ml_kem_utils_prf_داخلہ_inc_78(&prf_inputs, domain_separator);
  Eurydice_arr_58 prf_outputs = libcrux_ml_kem_hash_functions_portable_PRFxN_4a_3b(&prf_inputs);
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)3U; i++)
  {
    ناپ_t i0 = i;
    Eurydice_arr_9e
    uu____0 =
      libcrux_ml_kem_sampling_sample_from_دو_رکنی_distribution_66(Eurydice_array_منزل_ٹکڑا_shared_78(&prf_outputs.انکڑے[i0]));
    error_1->انکڑے[i0] = uu____0;
  }
  أرجع domain_separator;
}

/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.PRF
with const generics
- LEN= 128
*/
ساكن مضمن Eurydice_arr_89
libcrux_ml_kem_hash_functions_portable_PRF_ec(Eurydice_borrow_ٹکڑا_u8 داخلہ)
{
  Eurydice_arr_89 digest = { .انکڑے = { 0U } };
  libcrux_sha3_portable_shake256(Eurydice_array_منزل_ٹکڑا_mut_78(&digest), داخلہ);
  أرجع digest;
}

/**
This function found in impl {libcrux_ml_kem::hash_functions::Hash<K> for libcrux_ml_kem::hash_functions::portable::PortableHash<K>}
*/
/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.PRF_4a
with const generics
- K= 3
- LEN= 128
*/
ساكن مضمن Eurydice_arr_89
libcrux_ml_kem_hash_functions_portable_PRF_4a_3b0(Eurydice_borrow_ٹکڑا_u8 داخلہ)
{
  أرجع libcrux_ml_kem_hash_functions_portable_PRF_ec(داخلہ);
}

/**
This function found in impl {core::ops::function::FnMut<(usize), libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]> for libcrux_ml_kem::matrix::compute_vector_u::closure<Vector, K>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.matrix.compute_vector_u.call_mut_a8
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
ساكن مضمن Eurydice_arr_9e
libcrux_ml_kem_میٹرکس_compute_سمتیہ_u_call_mut_a8_68(فراغ **_, ناپ_t tupled_دلیلاں)
{
  أرجع libcrux_ml_kem_polynomial_ZERO_d6_ea();
}

/**
A monomorphic instance of libcrux_ml_kem.polynomial.add_error_reduce
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_kem_polynomial_جوڑو_error_reduce_ea(
  Eurydice_arr_9e *myself,
  ثابت Eurydice_arr_9e *error
)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_وچ_RING_ELEMENT; i++)
  {
    ناپ_t j = i;
    Eurydice_arr_d6
    coefficient_عام_form =
      libcrux_ml_kem_سمتیہ_portable_montgomery_multiply_by_constant_b8(myself->انکڑے[j],
        1441);
    Eurydice_arr_d6
    جوڑ = libcrux_ml_kem_سمتیہ_portable_جوڑو_b8(coefficient_عام_form, &error->انکڑے[j]);
    Eurydice_arr_d6 red = libcrux_ml_kem_سمتیہ_portable_barrett_reduce_b8(جوڑ);
    myself->انکڑے[j] = red;
  }
}

/**
This function found in impl {libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.polynomial.add_error_reduce_d6
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_kem_polynomial_جوڑو_error_reduce_d6_ea(
  Eurydice_arr_9e *self,
  ثابت Eurydice_arr_9e *error
)
{
  libcrux_ml_kem_polynomial_جوڑو_error_reduce_ea(self, error);
}

/**
 Compute u := InvertNTT(Aᵀ ◦ r̂) + e₁
*/
/**
A monomorphic instance of libcrux_ml_kem.matrix.compute_vector_u
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
ساكن KRML_MUSTINLINE Eurydice_arr_bb0
libcrux_ml_kem_میٹرکس_compute_سمتیہ_u_68(
  ثابت Eurydice_arr_c10 *a_as_ntt,
  ثابت Eurydice_arr_bb0 *r_as_ntt,
  ثابت Eurydice_arr_bb0 *error_1
)
{
  Eurydice_arr_bb0 arr_struct;
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    فراغ *lvalue = (فراغ *)0U;
    arr_struct.انکڑے[i] = libcrux_ml_kem_میٹرکس_compute_سمتیہ_u_call_mut_a8_68(&lvalue, i);
  }
  Eurydice_arr_bb0 نتیجہ = arr_struct;
  لكل (ناپ_t i0 = (ناپ_t)0U; i0 < (ناپ_t)3U; i0++)
  {
    ناپ_t i1 = i0;
    ثابت Eurydice_arr_bb0 *صف = &a_as_ntt->انکڑے[i1];
    لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)3U; i++)
    {
      ناپ_t j = i;
      ثابت Eurydice_arr_9e *a_element = &صف->انکڑے[j];
      Eurydice_arr_9e
      ضرب_حاصل = libcrux_ml_kem_polynomial_ntt_multiply_d6_ea(a_element, &r_as_ntt->انکڑے[j]);
      libcrux_ml_kem_polynomial_جوڑو_منزل_ring_element_d6_68(&نتیجہ.انکڑے[i1], &ضرب_حاصل);
    }
    libcrux_ml_kem_invert_ntt_invert_ntt_montgomery_68(&نتیجہ.انکڑے[i1]);
    libcrux_ml_kem_polynomial_جوڑو_error_reduce_d6_ea(&نتیجہ.انکڑے[i1], &error_1->انکڑے[i1]);
  }
  أرجع نتیجہ;
}

/**
A monomorphic instance of libcrux_ml_kem.vector.portable.compress.compress
with const generics
- COEFFICIENT_BITS= 10
*/
ساكن KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_compress_compress_ef(Eurydice_arr_d6 a)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < LIBCRUX_ML_KEM_سمتیہ_TRAITS_میدان_ELEMENTS_وچ_سمتیہ; i++)
  {
    ناپ_t i0 = i;
    int16_t
    uu____0 =
      libcrux_secrets_int_as_i16_f5(libcrux_ml_kem_سمتیہ_portable_compress_compress_ciphertext_coefficient((uint8_t)10,
          libcrux_secrets_int_as_u16_f5(a.انکڑے[i0])));
    a.انکڑے[i0] = uu____0;
  }
  أرجع a;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
/**
A monomorphic instance of libcrux_ml_kem.vector.portable.compress_b8
with const generics
- COEFFICIENT_BITS= 10
*/
ساكن مضمن Eurydice_arr_d6 libcrux_ml_kem_سمتیہ_portable_compress_b8_ef(Eurydice_arr_d6 a)
{
  أرجع libcrux_ml_kem_سمتیہ_portable_compress_compress_ef(a);
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.compress_then_serialize_10
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- OUT_LEN= 320
*/
ساكن KRML_MUSTINLINE Eurydice_arr_b0
libcrux_ml_kem_serialize_compress_then_serialize_10_e1(ثابت Eurydice_arr_9e *re)
{
  Eurydice_arr_b0 serialized = { .انکڑے = { 0U } };
  لكل (ناپ_t i = (ناپ_t)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_وچ_RING_ELEMENT; i++)
  {
    ناپ_t i0 = i;
    Eurydice_arr_d6
    coefficient =
      libcrux_ml_kem_سمتیہ_portable_compress_b8_ef(libcrux_ml_kem_serialize_منزل_unsigned_میدان_modulus_ea(re->انکڑے[i0]));
    Eurydice_arr_fc بائٹاں = libcrux_ml_kem_سمتیہ_portable_serialize_10_b8(coefficient);
    Eurydice_ٹکڑا_copy(Eurydice_array_منزل_subslice_mut_d413(&serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .شروع = (ناپ_t)20U * i0,
            .سرا = (ناپ_t)20U * i0 + (ناپ_t)20U
          }
        )),
      Eurydice_array_منزل_ٹکڑا_shared_8f(&بائٹاں),
      uint8_t);
  }
  أرجع serialized;
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.compress_then_serialize_ring_element_u
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- COMPRESSION_FACTOR= 10
- OUT_LEN= 320
*/
ساكن KRML_MUSTINLINE Eurydice_arr_b0
libcrux_ml_kem_serialize_compress_then_serialize_ring_element_u_f7(ثابت Eurydice_arr_9e *re)
{
  أرجع libcrux_ml_kem_serialize_compress_then_serialize_10_e1(re);
}

/**
 Call [`compress_then_serialize_ring_element_u`] on each ring element.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.compress_then_serialize_u
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- OUT_LEN= 960
- COMPRESSION_FACTOR= 10
- BLOCK_LEN= 320
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_kem_ind_cpa_compress_then_serialize_u_21(
  Eurydice_arr_bb0 داخلہ,
  Eurydice_mut_borrow_ٹکڑا_u8 باہرلا
)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)3U; i++)
  {
    ناپ_t i0 = i;
    Eurydice_arr_9e re = داخلہ.انکڑے[i0];
    Eurydice_mut_borrow_ٹکڑا_u8
    uu____0 =
      Eurydice_ٹکڑا_subslice_mut_c8(باہرلا,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .شروع = i0 * ((ناپ_t)960U / (ناپ_t)3U),
            .سرا = (i0 + (ناپ_t)1U) * ((ناپ_t)960U / (ناپ_t)3U)
          }
        ));
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_b0
    lvalue = libcrux_ml_kem_serialize_compress_then_serialize_ring_element_u_f7(&re);
    Eurydice_ٹکڑا_copy(uu____0, Eurydice_array_منزل_ٹکڑا_shared_56(&lvalue), uint8_t);
  }
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.encrypt_c1
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- C1_LEN= 960
- U_COMPRESSION_FACTOR= 10
- BLOCK_LEN= 320
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
- ETA2= 2
- ETA2_RANDOMNESS_SIZE= 128
*/
ساكن KRML_MUSTINLINE tuple_c6
libcrux_ml_kem_ind_cpa_encrypt_c1_87(
  Eurydice_borrow_ٹکڑا_u8 randomness,
  ثابت Eurydice_arr_c10 *میٹرکس,
  Eurydice_mut_borrow_ٹکڑا_u8 ciphertext
)
{
  Eurydice_arr_fa0 prf_داخلہ = libcrux_ml_kem_utils_into_padded_array_29(randomness);
  Eurydice_arr_bb0 arr_struct0;
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    فراغ *lvalue = (فراغ *)0U;
    arr_struct0.انکڑے[i] = libcrux_ml_kem_ind_cpa_encrypt_c1_call_mut_f1_87(&lvalue, i);
  }
  Eurydice_arr_bb0 r_as_ntt = arr_struct0;
  uint8_t
  domain_separator0 =
    libcrux_ml_kem_ind_cpa_sample_سمتیہ_cbd_then_ntt_bf(&r_as_ntt,
      &prf_داخلہ,
      0U);
  Eurydice_arr_bb0 arr_struct;
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    فراغ *lvalue = (فراغ *)0U;
    arr_struct.انکڑے[i] = libcrux_ml_kem_ind_cpa_encrypt_c1_call_mut_dd_87(&lvalue, i);
  }
  Eurydice_arr_bb0 error_1 = arr_struct;
  uint8_t
  domain_separator =
    libcrux_ml_kem_ind_cpa_sample_ring_element_cbd_bf(&prf_داخلہ,
      domain_separator0,
      &error_1);
  prf_داخلہ.انکڑے[32U] = domain_separator;
  Eurydice_arr_89
  prf_output =
    libcrux_ml_kem_hash_functions_portable_PRF_4a_3b0(Eurydice_array_منزل_ٹکڑا_shared_b5(&prf_داخلہ));
  Eurydice_arr_9e
  error_2 =
    libcrux_ml_kem_sampling_sample_from_دو_رکنی_distribution_66(Eurydice_array_منزل_ٹکڑا_shared_78(&prf_output));
  Eurydice_arr_bb0 u = libcrux_ml_kem_میٹرکس_compute_سمتیہ_u_68(میٹرکس, &r_as_ntt, &error_1);
  libcrux_ml_kem_ind_cpa_compress_then_serialize_u_21(u, ciphertext);
  أرجع (KRML_CLITERAL(tuple_c6){ .fst = r_as_ntt, .snd = error_2 });
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.deserialize_then_decompress_message
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ساكن KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_serialize_deserialize_then_decompress_سنیہا_ea(
  ثابت Eurydice_arr_ec *serialized
)
{
  Eurydice_arr_9e re = libcrux_ml_kem_polynomial_ZERO_d6_ea();
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)16U; i++)
  {
    ناپ_t i0 = i;
    Eurydice_arr_d6
    coefficient_compressed =
      libcrux_ml_kem_سمتیہ_portable_deserialize_1_b8(Eurydice_array_منزل_subslice_shared_d4(serialized,
          (
            KRML_CLITERAL(core_ops_range_Range_87){
              .شروع = (ناپ_t)2U * i0,
              .سرا = (ناپ_t)2U * i0 + (ناپ_t)2U
            }
          )));
    Eurydice_arr_d6
    uu____0 = libcrux_ml_kem_سمتیہ_portable_decompress_1_b8(coefficient_compressed);
    re.انکڑے[i0] = uu____0;
  }
  أرجع re;
}

/**
A monomorphic instance of libcrux_ml_kem.polynomial.add_message_error_reduce
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ساكن KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_polynomial_جوڑو_سنیہا_error_reduce_ea(
  ثابت Eurydice_arr_9e *myself,
  ثابت Eurydice_arr_9e *سنیہا,
  Eurydice_arr_9e نتیجہ
)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_وچ_RING_ELEMENT; i++)
  {
    ناپ_t i0 = i;
    Eurydice_arr_d6
    coefficient_عام_form =
      libcrux_ml_kem_سمتیہ_portable_montgomery_multiply_by_constant_b8(نتیجہ.انکڑے[i0],
        1441);
    Eurydice_arr_d6
    sum1 = libcrux_ml_kem_سمتیہ_portable_جوڑو_b8(myself->انکڑے[i0], &سنیہا->انکڑے[i0]);
    Eurydice_arr_d6 sum2 = libcrux_ml_kem_سمتیہ_portable_جوڑو_b8(coefficient_عام_form, &sum1);
    Eurydice_arr_d6 red = libcrux_ml_kem_سمتیہ_portable_barrett_reduce_b8(sum2);
    نتیجہ.انکڑے[i0] = red;
  }
  أرجع نتیجہ;
}

/**
This function found in impl {libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.polynomial.add_message_error_reduce_d6
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ساكن KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_polynomial_جوڑو_سنیہا_error_reduce_d6_ea(
  ثابت Eurydice_arr_9e *self,
  ثابت Eurydice_arr_9e *سنیہا,
  Eurydice_arr_9e نتیجہ
)
{
  أرجع libcrux_ml_kem_polynomial_جوڑو_سنیہا_error_reduce_ea(self, سنیہا, نتیجہ);
}

/**
 Compute InverseNTT(tᵀ ◦ r̂) + e₂ + message
*/
/**
A monomorphic instance of libcrux_ml_kem.matrix.compute_ring_element_v
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
ساكن KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_میٹرکس_compute_ring_element_v_68(
  ثابت Eurydice_arr_bb0 *t_as_ntt,
  ثابت Eurydice_arr_bb0 *r_as_ntt,
  ثابت Eurydice_arr_9e *error_2,
  ثابت Eurydice_arr_9e *سنیہا
)
{
  Eurydice_arr_9e نتیجہ = libcrux_ml_kem_polynomial_ZERO_d6_ea();
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)3U; i++)
  {
    ناپ_t i0 = i;
    Eurydice_arr_9e
    ضرب_حاصل =
      libcrux_ml_kem_polynomial_ntt_multiply_d6_ea(&t_as_ntt->انکڑے[i0],
        &r_as_ntt->انکڑے[i0]);
    libcrux_ml_kem_polynomial_جوڑو_منزل_ring_element_d6_68(&نتیجہ, &ضرب_حاصل);
  }
  libcrux_ml_kem_invert_ntt_invert_ntt_montgomery_68(&نتیجہ);
  أرجع libcrux_ml_kem_polynomial_جوڑو_سنیہا_error_reduce_d6_ea(error_2, سنیہا, نتیجہ);
}

/**
A monomorphic instance of libcrux_ml_kem.vector.portable.compress.compress
with const generics
- COEFFICIENT_BITS= 4
*/
ساكن KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_سمتیہ_portable_compress_compress_d1(Eurydice_arr_d6 a)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < LIBCRUX_ML_KEM_سمتیہ_TRAITS_میدان_ELEMENTS_وچ_سمتیہ; i++)
  {
    ناپ_t i0 = i;
    int16_t
    uu____0 =
      libcrux_secrets_int_as_i16_f5(libcrux_ml_kem_سمتیہ_portable_compress_compress_ciphertext_coefficient((uint8_t)4,
          libcrux_secrets_int_as_u16_f5(a.انکڑے[i0])));
    a.انکڑے[i0] = uu____0;
  }
  أرجع a;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
/**
A monomorphic instance of libcrux_ml_kem.vector.portable.compress_b8
with const generics
- COEFFICIENT_BITS= 4
*/
ساكن مضمن Eurydice_arr_d6 libcrux_ml_kem_سمتیہ_portable_compress_b8_d1(Eurydice_arr_d6 a)
{
  أرجع libcrux_ml_kem_سمتیہ_portable_compress_compress_d1(a);
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.compress_then_serialize_4
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_kem_serialize_compress_then_serialize_4_ea(
  Eurydice_arr_9e re,
  Eurydice_mut_borrow_ٹکڑا_u8 serialized
)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_وچ_RING_ELEMENT; i++)
  {
    ناپ_t i0 = i;
    Eurydice_arr_d6
    coefficient =
      libcrux_ml_kem_سمتیہ_portable_compress_b8_d1(libcrux_ml_kem_serialize_منزل_unsigned_میدان_modulus_ea(re.انکڑے[i0]));
    Eurydice_array_u8x8 بائٹاں = libcrux_ml_kem_سمتیہ_portable_serialize_4_b8(coefficient);
    Eurydice_ٹکڑا_copy(Eurydice_ٹکڑا_subslice_mut_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .شروع = (ناپ_t)8U * i0,
            .سرا = (ناپ_t)8U * i0 + (ناپ_t)8U
          }
        )),
      Eurydice_array_منزل_ٹکڑا_shared_6e(&بائٹاں),
      uint8_t);
  }
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.compress_then_serialize_ring_element_v
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- COMPRESSION_FACTOR= 4
- OUT_LEN= 128
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_kem_serialize_compress_then_serialize_ring_element_v_30(
  Eurydice_arr_9e re,
  Eurydice_mut_borrow_ٹکڑا_u8 باہرلا
)
{
  libcrux_ml_kem_serialize_compress_then_serialize_4_ea(re, باہرلا);
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.encrypt_c2
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- V_COMPRESSION_FACTOR= 4
- C2_LEN= 128
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_kem_ind_cpa_encrypt_c2_30(
  ثابت Eurydice_arr_bb0 *t_as_ntt,
  ثابت Eurydice_arr_bb0 *r_as_ntt,
  ثابت Eurydice_arr_9e *error_2,
  ثابت Eurydice_arr_ec *سنیہا,
  Eurydice_mut_borrow_ٹکڑا_u8 ciphertext
)
{
  Eurydice_arr_9e
  سنیہا_as_ring_element =
    libcrux_ml_kem_serialize_deserialize_then_decompress_سنیہا_ea(سنیہا);
  Eurydice_arr_9e
  v =
    libcrux_ml_kem_میٹرکس_compute_ring_element_v_68(t_as_ntt,
      r_as_ntt,
      error_2,
      &سنیہا_as_ring_element);
  libcrux_ml_kem_serialize_compress_then_serialize_ring_element_v_30(v, ciphertext);
}

/**
 This function implements <strong>Algorithm 13</strong> of the
 NIST FIPS 203 specification; this is the Kyber CPA-PKE encryption algorithm.

 Algorithm 13 is reproduced below:

 ```plaintext
 Input: encryption key ekₚₖₑ ∈ 𝔹^{384k+32}.
 Input: message m ∈ 𝔹^{32}.
 Input: encryption randomness r ∈ 𝔹^{32}.
 Output: ciphertext c ∈ 𝔹^{32(dᵤk + dᵥ)}.

 N ← 0
 t̂ ← ByteDecode₁₂(ekₚₖₑ[0:384k])
 ρ ← ekₚₖₑ[384k: 384k + 32]
 for (i ← 0; i < k; i++)
     for(j ← 0; j < k; j++)
         Â[i,j] ← SampleNTT(XOF(ρ, i, j))
     end for
 end for
 for(i ← 0; i < k; i++)
     r[i] ← SamplePolyCBD_{η₁}(PRF_{η₁}(r,N))
     N ← N + 1
 end for
 for(i ← 0; i < k; i++)
     e₁[i] ← SamplePolyCBD_{η₂}(PRF_{η₂}(r,N))
     N ← N + 1
 end for
 e₂ ← SamplePolyCBD_{η₂}(PRF_{η₂}(r,N))
 r̂ ← NTT(r)
 u ← NTT-¹(Âᵀ ◦ r̂) + e₁
 μ ← Decompress₁(ByteDecode₁(m)))
 v ← NTT-¹(t̂ᵀ ◦ rˆ) + e₂ + μ
 c₁ ← ByteEncode_{dᵤ}(Compress_{dᵤ}(u))
 c₂ ← ByteEncode_{dᵥ}(Compress_{dᵥ}(v))
 return c ← (c₁ ‖ c₂)
 ```

 The NIST FIPS 203 standard can be found at
 <https://csrc.nist.gov/pubs/fips/203/ipd>.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.encrypt_unpacked
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- CIPHERTEXT_SIZE= 1088
- T_AS_NTT_ENCODED_SIZE= 1152
- C1_LEN= 960
- C2_LEN= 128
- U_COMPRESSION_FACTOR= 10
- V_COMPRESSION_FACTOR= 4
- BLOCK_LEN= 320
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
- ETA2= 2
- ETA2_RANDOMNESS_SIZE= 128
*/
ساكن KRML_MUSTINLINE Eurydice_arr_2b
libcrux_ml_kem_ind_cpa_encrypt_unpacked_d5(
  ثابت libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_عوامی_کلید_Unpacked_51 *عوامی_کلید,
  ثابت Eurydice_arr_ec *سنیہا,
  Eurydice_borrow_ٹکڑا_u8 randomness
)
{
  Eurydice_arr_2b ciphertext = { .انکڑے = { 0U } };
  tuple_c6
  uu____0 =
    libcrux_ml_kem_ind_cpa_encrypt_c1_87(randomness,
      &عوامی_کلید->A,
      Eurydice_array_منزل_subslice_mut_d414(&ciphertext,
        (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = (ناپ_t)0U, .سرا = (ناپ_t)960U })));
  Eurydice_arr_bb0 r_as_ntt = uu____0.fst;
  Eurydice_arr_9e error_2 = uu____0.snd;
  libcrux_ml_kem_ind_cpa_encrypt_c2_30(&عوامی_کلید->t_as_ntt,
    &r_as_ntt,
    &error_2,
    سنیہا,
    Eurydice_array_منزل_subslice_from_mut_5f3(&ciphertext, (ناپ_t)960U));
  أرجع ciphertext;
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.encrypt
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- CIPHERTEXT_SIZE= 1088
- T_AS_NTT_ENCODED_SIZE= 1152
- C1_LEN= 960
- C2_LEN= 128
- U_COMPRESSION_FACTOR= 10
- V_COMPRESSION_FACTOR= 4
- BLOCK_LEN= 320
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
- ETA2= 2
- ETA2_RANDOMNESS_SIZE= 128
*/
ساكن KRML_MUSTINLINE Eurydice_arr_2b
libcrux_ml_kem_ind_cpa_encrypt_d5(
  Eurydice_borrow_ٹکڑا_u8 عوامی_کلید,
  ثابت Eurydice_arr_ec *سنیہا,
  Eurydice_borrow_ٹکڑا_u8 randomness
)
{
  libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_عوامی_کلید_Unpacked_51
  unpacked_عوامی_کلید = libcrux_ml_kem_ind_cpa_build_unpacked_عوامی_کلید_05(عوامی_کلید);
  أرجع libcrux_ml_kem_ind_cpa_encrypt_unpacked_d5(&unpacked_عوامی_کلید, سنیہا, randomness);
}

/**
This function found in impl {libcrux_ml_kem::variant::Variant for libcrux_ml_kem::variant::MlKem}
*/
/**
A monomorphic instance of libcrux_ml_kem.variant.kdf_39
with types libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- CIPHERTEXT_SIZE= 1088
*/
ساكن KRML_MUSTINLINE Eurydice_arr_ec
libcrux_ml_kem_variant_kdf_39_52(
  Eurydice_borrow_ٹکڑا_u8 shared_secret,
  ثابت Eurydice_arr_2b *_
)
{
  Eurydice_arr_ec باہرلا = { .انکڑے = { 0U } };
  Eurydice_ٹکڑا_copy(Eurydice_array_منزل_ٹکڑا_mut_01(&باہرلا), shared_secret, uint8_t);
  أرجع باہرلا;
}

/**
 This code verifies on some machines, runs out of memory on others
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.decapsulate
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]], libcrux_ml_kem_variant_MlKem
with const generics
- K= 3
- SECRET_KEY_SIZE= 2400
- CPA_SECRET_KEY_SIZE= 1152
- PUBLIC_KEY_SIZE= 1184
- CIPHERTEXT_SIZE= 1088
- T_AS_NTT_ENCODED_SIZE= 1152
- C1_SIZE= 960
- C2_SIZE= 128
- VECTOR_U_COMPRESSION_FACTOR= 10
- VECTOR_V_COMPRESSION_FACTOR= 4
- C1_BLOCK_SIZE= 320
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
- ETA2= 2
- ETA2_RANDOMNESS_SIZE= 128
- IMPLICIT_REJECTION_HASH_INPUT_SIZE= 1120
*/
ساكن KRML_MUSTINLINE Eurydice_arr_ec
libcrux_ml_kem_ind_cca_decapsulate_fd(
  ثابت Eurydice_arr_7d *نجی_کلید,
  ثابت Eurydice_arr_2b *ciphertext
)
{
  Eurydice_borrow_ٹکڑا_u8_x4
  uu____0 =
    libcrux_ml_kem_types_unpack_نجی_کلید_64(Eurydice_array_منزل_ٹکڑا_shared_51(نجی_کلید));
  Eurydice_borrow_ٹکڑا_u8 ind_cpa_secret_کلید = uu____0.fst;
  Eurydice_borrow_ٹکڑا_u8 ind_cpa_عوامی_کلید = uu____0.snd;
  Eurydice_borrow_ٹکڑا_u8 ind_cpa_عوامی_کلید_hash = uu____0.thd;
  Eurydice_borrow_ٹکڑا_u8 implicit_rejection_قدر = uu____0.f3;
  Eurydice_arr_ec decrypted = libcrux_ml_kem_ind_cpa_decrypt_01(ind_cpa_secret_کلید, ciphertext);
  Eurydice_arr_c7
  منزل_hash0 =
    libcrux_ml_kem_utils_into_padded_array_c9(Eurydice_array_منزل_ٹکڑا_shared_01(&decrypted));
  Eurydice_ٹکڑا_copy(Eurydice_array_منزل_subslice_from_mut_5f1(&منزل_hash0,
      LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_ناپ),
    ind_cpa_عوامی_کلید_hash,
    uint8_t);
  Eurydice_arr_c7
  hashed =
    libcrux_ml_kem_hash_functions_portable_G_4a_78(Eurydice_array_منزل_ٹکڑا_shared_17(&منزل_hash0));
  Eurydice_borrow_ٹکڑا_u8_x2
  uu____1 =
    Eurydice_ٹکڑا_ونڈو_at(Eurydice_array_منزل_ٹکڑا_shared_17(&hashed),
      LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_ناپ,
      uint8_t,
      Eurydice_borrow_ٹکڑا_u8_x2);
  Eurydice_borrow_ٹکڑا_u8 shared_secret0 = uu____1.fst;
  Eurydice_borrow_ٹکڑا_u8 pseudorandomness = uu____1.snd;
  Eurydice_arr_af منزل_hash = libcrux_ml_kem_utils_into_padded_array_66(implicit_rejection_قدر);
  Eurydice_mut_borrow_ٹکڑا_u8
  uu____2 =
    Eurydice_array_منزل_subslice_from_mut_5f2(&منزل_hash,
      LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_ناپ);
  Eurydice_ٹکڑا_copy(uu____2, libcrux_ml_kem_types_as_ref_c1_52(ciphertext), uint8_t);
  Eurydice_arr_ec
  implicit_rejection_shared_secret =
    libcrux_ml_kem_hash_functions_portable_PRF_4a_3b(Eurydice_array_منزل_ٹکڑا_shared_81(&منزل_hash));
  Eurydice_arr_2b
  expected_ciphertext =
    libcrux_ml_kem_ind_cpa_encrypt_d5(ind_cpa_عوامی_کلید,
      &decrypted,
      pseudorandomness);
  Eurydice_borrow_ٹکڑا_u8
  uu____3 = Eurydice_array_منزل_ٹکڑا_shared_01(&implicit_rejection_shared_secret);
  Eurydice_arr_ec
  implicit_rejection_shared_secret0 =
    libcrux_ml_kem_variant_kdf_39_52(uu____3,
      libcrux_ml_kem_types_as_ٹکڑا_a9_52(ciphertext));
  Eurydice_arr_ec
  shared_secret =
    libcrux_ml_kem_variant_kdf_39_52(shared_secret0,
      libcrux_ml_kem_types_as_ٹکڑا_a9_52(ciphertext));
  Eurydice_borrow_ٹکڑا_u8 uu____4 = libcrux_ml_kem_types_as_ref_c1_52(ciphertext);
  أرجع
    libcrux_ml_kem_constant_ویلا_ops_compare_ciphertexts_select_shared_secret_وچ_constant_ویلا(uu____4,
      Eurydice_array_منزل_ٹکڑا_shared_06(&expected_ciphertext),
      Eurydice_array_منزل_ٹکڑا_shared_01(&shared_secret),
      Eurydice_array_منزل_ٹکڑا_shared_01(&implicit_rejection_shared_secret0));
}

/**
 Portable decapsulate
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.instantiations.portable.decapsulate
with const generics
- K= 3
- SECRET_KEY_SIZE= 2400
- CPA_SECRET_KEY_SIZE= 1152
- PUBLIC_KEY_SIZE= 1184
- CIPHERTEXT_SIZE= 1088
- T_AS_NTT_ENCODED_SIZE= 1152
- C1_SIZE= 960
- C2_SIZE= 128
- VECTOR_U_COMPRESSION_FACTOR= 10
- VECTOR_V_COMPRESSION_FACTOR= 4
- C1_BLOCK_SIZE= 320
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
- ETA2= 2
- ETA2_RANDOMNESS_SIZE= 128
- IMPLICIT_REJECTION_HASH_INPUT_SIZE= 1120
*/
ساكن مضمن Eurydice_arr_ec
libcrux_ml_kem_ind_cca_instantiations_portable_decapsulate_19(
  ثابت Eurydice_arr_7d *نجی_کلید,
  ثابت Eurydice_arr_2b *ciphertext
)
{
  أرجع libcrux_ml_kem_ind_cca_decapsulate_fd(نجی_کلید, ciphertext);
}

/**
 Decapsulate ML-KEM 768

 Generates an [`MlKemSharedSecret`].
 The input is a reference to an [`MlKem768PrivateKey`] and an [`MlKem768Ciphertext`].
*/
ساكن مضمن Eurydice_arr_ec
libcrux_ml_kem_mlkem768_portable_decapsulate(
  ثابت Eurydice_arr_7d *نجی_کلید,
  ثابت Eurydice_arr_2b *ciphertext
)
{
  أرجع libcrux_ml_kem_ind_cca_instantiations_portable_decapsulate_19(نجی_کلید, ciphertext);
}

/**
This function found in impl {libcrux_ml_kem::variant::Variant for libcrux_ml_kem::variant::MlKem}
*/
/**
A monomorphic instance of libcrux_ml_kem.variant.entropy_preprocess_39
with types libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
*/
ساكن KRML_MUSTINLINE Eurydice_arr_ec
libcrux_ml_kem_variant_entropy_preprocess_39_13(Eurydice_borrow_ٹکڑا_u8 randomness)
{
  Eurydice_arr_ec باہرلا = { .انکڑے = { 0U } };
  Eurydice_ٹکڑا_copy(Eurydice_array_منزل_ٹکڑا_mut_01(&باہرلا), randomness, uint8_t);
  أرجع باہرلا;
}

/**
This function found in impl {libcrux_ml_kem::hash_functions::Hash<K> for libcrux_ml_kem::hash_functions::portable::PortableHash<K>}
*/
/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.H_4a
with const generics
- K= 3
*/
ساكن مضمن Eurydice_arr_ec
libcrux_ml_kem_hash_functions_portable_H_4a_78(Eurydice_borrow_ٹکڑا_u8 داخلہ)
{
  أرجع libcrux_ml_kem_hash_functions_portable_H(داخلہ);
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cca.encapsulate
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]], libcrux_ml_kem_variant_MlKem
with const generics
- K= 3
- CIPHERTEXT_SIZE= 1088
- PUBLIC_KEY_SIZE= 1184
- T_AS_NTT_ENCODED_SIZE= 1152
- C1_SIZE= 960
- C2_SIZE= 128
- VECTOR_U_COMPRESSION_FACTOR= 10
- VECTOR_V_COMPRESSION_FACTOR= 4
- C1_BLOCK_SIZE= 320
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
- ETA2= 2
- ETA2_RANDOMNESS_SIZE= 128
*/
ساكن KRML_MUSTINLINE tuple_f4
libcrux_ml_kem_ind_cca_encapsulate_99(
  ثابت Eurydice_arr_5f *عوامی_کلید,
  ثابت Eurydice_arr_ec *randomness
)
{
  Eurydice_arr_ec
  randomness0 =
    libcrux_ml_kem_variant_entropy_preprocess_39_13(Eurydice_array_منزل_ٹکڑا_shared_01(randomness));
  Eurydice_arr_c7
  منزل_hash =
    libcrux_ml_kem_utils_into_padded_array_c9(Eurydice_array_منزل_ٹکڑا_shared_01(&randomness0));
  Eurydice_mut_borrow_ٹکڑا_u8
  uu____0 =
    Eurydice_array_منزل_subslice_from_mut_5f1(&منزل_hash,
      LIBCRUX_ML_KEM_CONSTANTS_H_DIGEST_ناپ);
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_ec
  lvalue =
    libcrux_ml_kem_hash_functions_portable_H_4a_78(Eurydice_array_منزل_ٹکڑا_shared_ff(libcrux_ml_kem_types_as_ٹکڑا_e6_3d(عوامی_کلید)));
  Eurydice_ٹکڑا_copy(uu____0, Eurydice_array_منزل_ٹکڑا_shared_01(&lvalue), uint8_t);
  Eurydice_arr_c7
  hashed =
    libcrux_ml_kem_hash_functions_portable_G_4a_78(Eurydice_array_منزل_ٹکڑا_shared_17(&منزل_hash));
  Eurydice_borrow_ٹکڑا_u8_x2
  uu____1 =
    Eurydice_ٹکڑا_ونڈو_at(Eurydice_array_منزل_ٹکڑا_shared_17(&hashed),
      LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_ناپ,
      uint8_t,
      Eurydice_borrow_ٹکڑا_u8_x2);
  Eurydice_borrow_ٹکڑا_u8 shared_secret = uu____1.fst;
  Eurydice_borrow_ٹکڑا_u8 pseudorandomness = uu____1.snd;
  Eurydice_arr_2b
  ciphertext =
    libcrux_ml_kem_ind_cpa_encrypt_d5(Eurydice_array_منزل_ٹکڑا_shared_ff(libcrux_ml_kem_types_as_ٹکڑا_e6_3d(عوامی_کلید)),
      &randomness0,
      pseudorandomness);
  Eurydice_arr_2b uu____2 = libcrux_ml_kem_types_from_19_52(ciphertext);
  أرجع
    (
      KRML_CLITERAL(tuple_f4){
        .fst = uu____2,
        .snd = libcrux_ml_kem_variant_kdf_39_52(shared_secret, &ciphertext)
      }
    );
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cca.instantiations.portable.encapsulate
with const generics
- K= 3
- CIPHERTEXT_SIZE= 1088
- PUBLIC_KEY_SIZE= 1184
- T_AS_NTT_ENCODED_SIZE= 1152
- C1_SIZE= 960
- C2_SIZE= 128
- VECTOR_U_COMPRESSION_FACTOR= 10
- VECTOR_V_COMPRESSION_FACTOR= 4
- C1_BLOCK_SIZE= 320
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
- ETA2= 2
- ETA2_RANDOMNESS_SIZE= 128
*/
ساكن مضمن tuple_f4
libcrux_ml_kem_ind_cca_instantiations_portable_encapsulate_26(
  ثابت Eurydice_arr_5f *عوامی_کلید,
  ثابت Eurydice_arr_ec *randomness
)
{
  أرجع libcrux_ml_kem_ind_cca_encapsulate_99(عوامی_کلید, randomness);
}

/**
 Encapsulate ML-KEM 768

 Generates an ([`MlKem768Ciphertext`], [`MlKemSharedSecret`]) tuple.
 The input is a reference to an [`MlKem768PublicKey`] and [`SHARED_SECRET_SIZE`]
 bytes of `randomness`.
*/
ساكن مضمن tuple_f4
libcrux_ml_kem_mlkem768_portable_encapsulate(
  ثابت Eurydice_arr_5f *عوامی_کلید,
  Eurydice_arr_ec randomness
)
{
  أرجع libcrux_ml_kem_ind_cca_instantiations_portable_encapsulate_26(عوامی_کلید, &randomness);
}

/**
This function found in impl {core::default::Default for libcrux_ml_kem::ind_cpa::unpacked::IndCpaPrivateKeyUnpacked<Vector, K>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.unpacked.default_70
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
ساكن مضمن Eurydice_arr_bb0 libcrux_ml_kem_ind_cpa_unpacked_default_70_68(فراغ)
{
  Eurydice_arr_bb0 lit;
  Eurydice_arr_9e repeat_عبارت[3U];
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)3U; i++)
  {
    repeat_عبارت[i] = libcrux_ml_kem_polynomial_ZERO_d6_ea();
  }
  حافظہ_نقل(lit.انکڑے, repeat_عبارت, (ناپ_t)3U * حجم (Eurydice_arr_9e));
  أرجع lit;
}

/**
This function found in impl {libcrux_ml_kem::variant::Variant for libcrux_ml_kem::variant::MlKem}
*/
/**
A monomorphic instance of libcrux_ml_kem.variant.cpa_keygen_seed_39
with types libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
*/
ساكن KRML_MUSTINLINE Eurydice_arr_c7
libcrux_ml_kem_variant_cpa_keygen_بیج_39_13(Eurydice_borrow_ٹکڑا_u8 کلید_generation_بیج)
{
  Eurydice_arr_fa0 بیج = { .انکڑے = { 0U } };
  Eurydice_ٹکڑا_copy(Eurydice_array_منزل_subslice_mut_d412(&بیج,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .شروع = (ناپ_t)0U,
          .سرا = LIBCRUX_ML_KEM_CONSTANTS_CPA_PKE_کلید_GENERATION_بیج_ناپ
        }
      )),
    کلید_generation_بیج,
    uint8_t);
  بیج.انکڑے[LIBCRUX_ML_KEM_CONSTANTS_CPA_PKE_کلید_GENERATION_بیج_ناپ] = (uint8_t)(ناپ_t)3U;
  أرجع
    libcrux_ml_kem_hash_functions_portable_G_4a_78(Eurydice_array_منزل_ٹکڑا_shared_b5(&بیج));
}

/**
This function found in impl {core::ops::function::FnMut<(usize), libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@3]> for libcrux_ml_kem::ind_cpa::generate_keypair_unpacked::closure<Vector, Hasher, Scheme, K, ETA1, ETA1_RANDOMNESS_SIZE>[TraitClause@0, TraitClause@1, TraitClause@2, TraitClause@3, TraitClause@4, TraitClause@5]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.generate_keypair_unpacked.call_mut_73
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]], libcrux_ml_kem_variant_MlKem
with const generics
- K= 3
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
*/
ساكن مضمن Eurydice_arr_9e
libcrux_ml_kem_ind_cpa_generate_keypair_unpacked_call_mut_73_39(فراغ **_, ناپ_t tupled_دلیلاں)
{
  أرجع libcrux_ml_kem_polynomial_ZERO_d6_ea();
}

/**
A monomorphic instance of libcrux_ml_kem.polynomial.to_standard_domain
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ساكن KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_polynomial_منزل_standard_domain_ea(Eurydice_arr_d6 سمتیہ)
{
  أرجع
    libcrux_ml_kem_سمتیہ_portable_montgomery_multiply_by_constant_b8(سمتیہ,
      LIBCRUX_ML_KEM_سمتیہ_TRAITS_MONTGOMERY_R_SQUARED_MOD_میدان_MODULUS);
}

/**
A monomorphic instance of libcrux_ml_kem.polynomial.add_standard_error_reduce
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_kem_polynomial_جوڑو_standard_error_reduce_ea(
  Eurydice_arr_9e *myself,
  ثابت Eurydice_arr_9e *error
)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_وچ_RING_ELEMENT; i++)
  {
    ناپ_t j = i;
    Eurydice_arr_d6
    coefficient_عام_form = libcrux_ml_kem_polynomial_منزل_standard_domain_ea(myself->انکڑے[j]);
    Eurydice_arr_d6
    جوڑ = libcrux_ml_kem_سمتیہ_portable_جوڑو_b8(coefficient_عام_form, &error->انکڑے[j]);
    Eurydice_arr_d6 red = libcrux_ml_kem_سمتیہ_portable_barrett_reduce_b8(جوڑ);
    myself->انکڑے[j] = red;
  }
}

/**
This function found in impl {libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.polynomial.add_standard_error_reduce_d6
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_kem_polynomial_جوڑو_standard_error_reduce_d6_ea(
  Eurydice_arr_9e *self,
  ثابت Eurydice_arr_9e *error
)
{
  libcrux_ml_kem_polynomial_جوڑو_standard_error_reduce_ea(self, error);
}

/**
 Compute Â ◦ ŝ + ê
*/
/**
A monomorphic instance of libcrux_ml_kem.matrix.compute_As_plus_e
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_kem_میٹرکس_compute_As_plus_e_68(
  Eurydice_arr_bb0 *t_as_ntt,
  ثابت Eurydice_arr_c10 *میٹرکس_A,
  ثابت Eurydice_arr_bb0 *s_as_ntt,
  ثابت Eurydice_arr_bb0 *error_as_ntt
)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)3U; i++)
  {
    ناپ_t i0 = i;
    ثابت Eurydice_arr_bb0 *صف = &میٹرکس_A->انکڑے[i0];
    Eurydice_arr_9e uu____0 = libcrux_ml_kem_polynomial_ZERO_d6_ea();
    t_as_ntt->انکڑے[i0] = uu____0;
    لكل (ناپ_t i1 = (ناپ_t)0U; i1 < (ناپ_t)3U; i1++)
    {
      ناپ_t j = i1;
      ثابت Eurydice_arr_9e *میٹرکس_element = &صف->انکڑے[j];
      Eurydice_arr_9e
      ضرب_حاصل = libcrux_ml_kem_polynomial_ntt_multiply_d6_ea(میٹرکس_element, &s_as_ntt->انکڑے[j]);
      libcrux_ml_kem_polynomial_جوڑو_منزل_ring_element_d6_68(&t_as_ntt->انکڑے[i0], &ضرب_حاصل);
    }
    libcrux_ml_kem_polynomial_جوڑو_standard_error_reduce_d6_ea(&t_as_ntt->انکڑے[i0],
      &error_as_ntt->انکڑے[i0]);
  }
}

/**
 This function implements most of <strong>Algorithm 12</strong> of the
 NIST FIPS 203 specification; this is the Kyber CPA-PKE key generation algorithm.

 We say "most of" since Algorithm 12 samples the required randomness within
 the function itself, whereas this implementation expects it to be provided
 through the `key_generation_seed` parameter.

 Algorithm 12 is reproduced below:

 ```plaintext
 Output: encryption key ekₚₖₑ ∈ 𝔹^{384k+32}.
 Output: decryption key dkₚₖₑ ∈ 𝔹^{384k}.

 d ←$ B
 (ρ,σ) ← G(d)
 N ← 0
 for (i ← 0; i < k; i++)
     for(j ← 0; j < k; j++)
         Â[i,j] ← SampleNTT(XOF(ρ, i, j))
     end for
 end for
 for(i ← 0; i < k; i++)
     s[i] ← SamplePolyCBD_{η₁}(PRF_{η₁}(σ,N))
     N ← N + 1
 end for
 for(i ← 0; i < k; i++)
     e[i] ← SamplePolyCBD_{η₂}(PRF_{η₂}(σ,N))
     N ← N + 1
 end for
 ŝ ← NTT(s)
 ê ← NTT(e)
 t̂ ← Â◦ŝ + ê
 ekₚₖₑ ← ByteEncode₁₂(t̂) ‖ ρ
 dkₚₖₑ ← ByteEncode₁₂(ŝ)
 ```

 The NIST FIPS 203 standard can be found at
 <https://csrc.nist.gov/pubs/fips/203/ipd>.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.generate_keypair_unpacked
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]], libcrux_ml_kem_variant_MlKem
with const generics
- K= 3
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_kem_ind_cpa_generate_keypair_unpacked_39(
  Eurydice_borrow_ٹکڑا_u8 کلید_generation_بیج,
  Eurydice_arr_bb0 *نجی_کلید,
  libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_عوامی_کلید_Unpacked_51 *عوامی_کلید
)
{
  Eurydice_arr_c7 hashed = libcrux_ml_kem_variant_cpa_keygen_بیج_39_13(کلید_generation_بیج);
  Eurydice_borrow_ٹکڑا_u8_x2
  uu____0 =
    Eurydice_ٹکڑا_ونڈو_at(Eurydice_array_منزل_ٹکڑا_shared_17(&hashed),
      (ناپ_t)32U,
      uint8_t,
      Eurydice_borrow_ٹکڑا_u8_x2);
  Eurydice_borrow_ٹکڑا_u8 بیج_for_A = uu____0.fst;
  Eurydice_borrow_ٹکڑا_u8 بیج_for_secret_and_error = uu____0.snd;
  Eurydice_arr_c10 *uu____1 = &عوامی_کلید->A;
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_31 lvalue0 = libcrux_ml_kem_utils_into_padded_array_de(بیج_for_A);
  libcrux_ml_kem_میٹرکس_sample_میٹرکس_A_91(uu____1, &lvalue0, true);
  Eurydice_arr_fa0
  prf_داخلہ = libcrux_ml_kem_utils_into_padded_array_29(بیج_for_secret_and_error);
  uint8_t
  domain_separator =
    libcrux_ml_kem_ind_cpa_sample_سمتیہ_cbd_then_ntt_bf(نجی_کلید,
      &prf_داخلہ,
      0U);
  Eurydice_arr_bb0 arr_struct;
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    فراغ *lvalue = (فراغ *)0U;
    arr_struct.انکڑے[i] =
      libcrux_ml_kem_ind_cpa_generate_keypair_unpacked_call_mut_73_39(&lvalue,
        i);
  }
  Eurydice_arr_bb0 error_as_ntt = arr_struct;
  libcrux_ml_kem_ind_cpa_sample_سمتیہ_cbd_then_ntt_bf(&error_as_ntt,
    &prf_داخلہ,
    domain_separator);
  libcrux_ml_kem_میٹرکس_compute_As_plus_e_68(&عوامی_کلید->t_as_ntt,
    &عوامی_کلید->A,
    &نجی_کلید[0U],
    &error_as_ntt);
  Eurydice_arr_ec arr;
  حافظہ_نقل(arr.انکڑے, بیج_for_A.ptr, (ناپ_t)32U * حجم (uint8_t));
  Eurydice_arr_ec
  uu____2 =
    core_نتیجہ_unwrap_26_39((
        KRML_CLITERAL(core_نتیجہ_نتیجہ_07){ .ٹیگ = core_نتیجہ_Ok, .val = { .case_Ok = arr } }
      ));
  عوامی_کلید->بیج_for_A = uu____2;
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.serialize_uncompressed_ring_element
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ساكن KRML_MUSTINLINE Eurydice_arr_b20
libcrux_ml_kem_serialize_serialize_uncompressed_ring_element_ea(ثابت Eurydice_arr_9e *re)
{
  Eurydice_arr_b20 serialized = { .انکڑے = { 0U } };
  لكل (ناپ_t i = (ناپ_t)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_وچ_RING_ELEMENT; i++)
  {
    ناپ_t i0 = i;
    Eurydice_arr_d6
    coefficient = libcrux_ml_kem_serialize_منزل_unsigned_میدان_modulus_ea(re->انکڑے[i0]);
    Eurydice_arr_94 بائٹاں = libcrux_ml_kem_سمتیہ_portable_serialize_12_b8(coefficient);
    Eurydice_ٹکڑا_copy(Eurydice_array_منزل_subslice_mut_d415(&serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .شروع = (ناپ_t)24U * i0,
            .سرا = (ناپ_t)24U * i0 + (ناپ_t)24U
          }
        )),
      Eurydice_array_منزل_ٹکڑا_shared_ed(&بائٹاں),
      uint8_t);
  }
  أرجع serialized;
}

/**
 Call [`serialize_uncompressed_ring_element`] for each ring element.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.serialize_vector
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_kem_ind_cpa_serialize_سمتیہ_68(
  ثابت Eurydice_arr_bb0 *کلید,
  Eurydice_mut_borrow_ٹکڑا_u8 باہرلا
)
{
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)3U; i++)
  {
    ناپ_t i0 = i;
    Eurydice_arr_9e re = کلید->انکڑے[i0];
    Eurydice_mut_borrow_ٹکڑا_u8
    uu____0 =
      Eurydice_ٹکڑا_subslice_mut_c8(باہرلا,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .شروع = i0 * LIBCRUX_ML_KEM_CONSTANTS_بائٹاں_فی_RING_ELEMENT,
            .سرا = (i0 + (ناپ_t)1U) * LIBCRUX_ML_KEM_CONSTANTS_بائٹاں_فی_RING_ELEMENT
          }
        ));
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_b20 lvalue = libcrux_ml_kem_serialize_serialize_uncompressed_ring_element_ea(&re);
    Eurydice_ٹکڑا_copy(uu____0, Eurydice_array_منزل_ٹکڑا_shared_a9(&lvalue), uint8_t);
  }
}

/**
 Concatenate `t` and `ρ` into the public key.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.serialize_public_key_mut
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- PUBLIC_KEY_SIZE= 1184
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_kem_ind_cpa_serialize_عوامی_کلید_mut_b6(
  ثابت Eurydice_arr_bb0 *t_as_ntt,
  Eurydice_borrow_ٹکڑا_u8 بیج_for_a,
  Eurydice_arr_5f *serialized
)
{
  libcrux_ml_kem_ind_cpa_serialize_سمتیہ_68(t_as_ntt,
    Eurydice_array_منزل_subslice_mut_d416(serialized,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .شروع = (ناپ_t)0U,
          .سرا = libcrux_ml_kem_constants_ranked_بائٹاں_فی_ring_element((ناپ_t)3U)
        }
      )));
  Eurydice_ٹکڑا_copy(Eurydice_array_منزل_subslice_from_mut_5f4(serialized,
      libcrux_ml_kem_constants_ranked_بائٹاں_فی_ring_element((ناپ_t)3U)),
    بیج_for_a,
    uint8_t);
}

/**
 Concatenate `t` and `ρ` into the public key.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.serialize_public_key
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- PUBLIC_KEY_SIZE= 1184
*/
ساكن KRML_MUSTINLINE Eurydice_arr_5f
libcrux_ml_kem_ind_cpa_serialize_عوامی_کلید_b6(
  ثابت Eurydice_arr_bb0 *t_as_ntt,
  Eurydice_borrow_ٹکڑا_u8 بیج_for_a
)
{
  Eurydice_arr_5f عوامی_کلید_serialized = { .انکڑے = { 0U } };
  libcrux_ml_kem_ind_cpa_serialize_عوامی_کلید_mut_b6(t_as_ntt,
    بیج_for_a,
    &عوامی_کلید_serialized);
  أرجع عوامی_کلید_serialized;
}

/**
 Serialize the secret key from the unpacked key pair generation.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.serialize_unpacked_secret_key
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- PRIVATE_KEY_SIZE= 1152
- PUBLIC_KEY_SIZE= 1184
*/
ساكن مضمن libcrux_ml_kem_utils_extraction_helper_Keypair768
libcrux_ml_kem_ind_cpa_serialize_unpacked_secret_کلید_30(
  ثابت libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_عوامی_کلید_Unpacked_51 *عوامی_کلید,
  ثابت Eurydice_arr_bb0 *نجی_کلید
)
{
  Eurydice_arr_5f
  عوامی_کلید_serialized =
    libcrux_ml_kem_ind_cpa_serialize_عوامی_کلید_b6(&عوامی_کلید->t_as_ntt,
      Eurydice_array_منزل_ٹکڑا_shared_01(&عوامی_کلید->بیج_for_A));
  Eurydice_arr_0e secret_کلید_serialized = { .انکڑے = { 0U } };
  libcrux_ml_kem_ind_cpa_serialize_سمتیہ_68(نجی_کلید,
    Eurydice_array_منزل_ٹکڑا_mut_f4(&secret_کلید_serialized));
  أرجع
    (
      KRML_CLITERAL(libcrux_ml_kem_utils_extraction_helper_Keypair768){
        .fst = secret_کلید_serialized,
        .snd = عوامی_کلید_serialized
      }
    );
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.generate_keypair
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]], libcrux_ml_kem_variant_MlKem
with const generics
- K= 3
- PRIVATE_KEY_SIZE= 1152
- PUBLIC_KEY_SIZE= 1184
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
*/
ساكن KRML_MUSTINLINE libcrux_ml_kem_utils_extraction_helper_Keypair768
libcrux_ml_kem_ind_cpa_generate_keypair_30(Eurydice_borrow_ٹکڑا_u8 کلید_generation_بیج)
{
  Eurydice_arr_bb0 نجی_کلید = libcrux_ml_kem_ind_cpa_unpacked_default_70_68();
  libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_عوامی_کلید_Unpacked_51
  عوامی_کلید = libcrux_ml_kem_ind_cpa_unpacked_default_8b_68();
  libcrux_ml_kem_ind_cpa_generate_keypair_unpacked_39(کلید_generation_بیج,
    &نجی_کلید,
    &عوامی_کلید);
  أرجع libcrux_ml_kem_ind_cpa_serialize_unpacked_secret_کلید_30(&عوامی_کلید, &نجی_کلید);
}

/**
 Serialize the secret key.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.serialize_kem_secret_key_mut
with types libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- SERIALIZED_KEY_LEN= 2400
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_kem_ind_cca_serialize_kem_secret_کلید_mut_52(
  Eurydice_borrow_ٹکڑا_u8 نجی_کلید,
  Eurydice_borrow_ٹکڑا_u8 عوامی_کلید,
  Eurydice_borrow_ٹکڑا_u8 implicit_rejection_قدر,
  Eurydice_arr_7d *serialized
)
{
  ناپ_t اشارہ_گر = (ناپ_t)0U;
  Eurydice_ٹکڑا_copy(Eurydice_array_منزل_subslice_mut_d417(serialized,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .شروع = اشارہ_گر,
          .سرا = اشارہ_گر + نجی_کلید.meta
        }
      )),
    نجی_کلید,
    uint8_t);
  اشارہ_گر += نجی_کلید.meta;
  Eurydice_ٹکڑا_copy(Eurydice_array_منزل_subslice_mut_d417(serialized,
      (KRML_CLITERAL(core_ops_range_Range_87){ .شروع = اشارہ_گر, .سرا = اشارہ_گر + عوامی_کلید.meta })),
    عوامی_کلید,
    uint8_t);
  اشارہ_گر += عوامی_کلید.meta;
  Eurydice_mut_borrow_ٹکڑا_u8
  uu____0 =
    Eurydice_array_منزل_subslice_mut_d417(serialized,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .شروع = اشارہ_گر,
          .سرا = اشارہ_گر + LIBCRUX_ML_KEM_CONSTANTS_H_DIGEST_ناپ
        }
      ));
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_ec lvalue = libcrux_ml_kem_hash_functions_portable_H_4a_78(عوامی_کلید);
  Eurydice_ٹکڑا_copy(uu____0, Eurydice_array_منزل_ٹکڑا_shared_01(&lvalue), uint8_t);
  اشارہ_گر += LIBCRUX_ML_KEM_CONSTANTS_H_DIGEST_ناپ;
  Eurydice_ٹکڑا_copy(Eurydice_array_منزل_subslice_mut_d417(serialized,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .شروع = اشارہ_گر,
          .سرا = اشارہ_گر + implicit_rejection_قدر.meta
        }
      )),
    implicit_rejection_قدر,
    uint8_t);
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cca.serialize_kem_secret_key
with types libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- SERIALIZED_KEY_LEN= 2400
*/
ساكن KRML_MUSTINLINE Eurydice_arr_7d
libcrux_ml_kem_ind_cca_serialize_kem_secret_کلید_52(
  Eurydice_borrow_ٹکڑا_u8 نجی_کلید,
  Eurydice_borrow_ٹکڑا_u8 عوامی_کلید,
  Eurydice_borrow_ٹکڑا_u8 implicit_rejection_قدر
)
{
  Eurydice_arr_7d باہرلا = { .انکڑے = { 0U } };
  libcrux_ml_kem_ind_cca_serialize_kem_secret_کلید_mut_52(نجی_کلید,
    عوامی_کلید,
    implicit_rejection_قدر,
    &باہرلا);
  أرجع باہرلا;
}

/**
 Packed API

 Generate a key pair.

 Depending on the `Vector` and `Hasher` used, this requires different hardware
 features
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.generate_keypair
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]], libcrux_ml_kem_variant_MlKem
with const generics
- K= 3
- CPA_PRIVATE_KEY_SIZE= 1152
- PRIVATE_KEY_SIZE= 2400
- PUBLIC_KEY_SIZE= 1184
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
*/
ساكن KRML_MUSTINLINE libcrux_ml_kem_mlkem768_Ml_Kem768_کلید_Pair
libcrux_ml_kem_ind_cca_generate_keypair_b8(ثابت Eurydice_arr_c7 *randomness)
{
  Eurydice_borrow_ٹکڑا_u8
  ind_cpa_keypair_randomness =
    Eurydice_array_منزل_subslice_shared_d47(randomness,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .شروع = (ناپ_t)0U,
          .سرا = LIBCRUX_ML_KEM_CONSTANTS_CPA_PKE_کلید_GENERATION_بیج_ناپ
        }
      ));
  Eurydice_borrow_ٹکڑا_u8
  implicit_rejection_قدر =
    Eurydice_array_منزل_subslice_from_shared_5f1(randomness,
      LIBCRUX_ML_KEM_CONSTANTS_CPA_PKE_کلید_GENERATION_بیج_ناپ);
  libcrux_ml_kem_utils_extraction_helper_Keypair768
  uu____0 = libcrux_ml_kem_ind_cpa_generate_keypair_30(ind_cpa_keypair_randomness);
  Eurydice_arr_0e ind_cpa_نجی_کلید = uu____0.fst;
  Eurydice_arr_5f عوامی_کلید = uu____0.snd;
  Eurydice_arr_7d
  secret_کلید_serialized =
    libcrux_ml_kem_ind_cca_serialize_kem_secret_کلید_52(Eurydice_array_منزل_ٹکڑا_shared_f4(&ind_cpa_نجی_کلید),
      Eurydice_array_منزل_ٹکڑا_shared_ff(&عوامی_کلید),
      implicit_rejection_قدر);
  Eurydice_arr_7d نجی_کلید = libcrux_ml_kem_types_from_b2_79(secret_کلید_serialized);
  أرجع
    libcrux_ml_kem_types_from_17_bc(نجی_کلید,
      libcrux_ml_kem_types_from_51_3d(عوامی_کلید));
}

/**
 Portable generate key pair.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.instantiations.portable.generate_keypair
with const generics
- K= 3
- CPA_PRIVATE_KEY_SIZE= 1152
- PRIVATE_KEY_SIZE= 2400
- PUBLIC_KEY_SIZE= 1184
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
*/
ساكن مضمن libcrux_ml_kem_mlkem768_Ml_Kem768_کلید_Pair
libcrux_ml_kem_ind_cca_instantiations_portable_generate_keypair_e9(
  ثابت Eurydice_arr_c7 *randomness
)
{
  أرجع libcrux_ml_kem_ind_cca_generate_keypair_b8(randomness);
}

/**
 Generate ML-KEM 768 Key Pair
*/
ساكن مضمن libcrux_ml_kem_mlkem768_Ml_Kem768_کلید_Pair
libcrux_ml_kem_mlkem768_portable_generate_کلید_pair(Eurydice_arr_c7 randomness)
{
  أرجع libcrux_ml_kem_ind_cca_instantiations_portable_generate_keypair_e9(&randomness);
}

/**
 Validate an ML-KEM private key.

 This implements the Hash check in 7.3 3.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.validate_private_key_only
with types libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- SECRET_KEY_SIZE= 2400
*/
ساكن KRML_MUSTINLINE bool
libcrux_ml_kem_ind_cca_validate_نجی_کلید_only_52(ثابت Eurydice_arr_7d *نجی_کلید)
{
  Eurydice_arr_ec
  t =
    libcrux_ml_kem_hash_functions_portable_H_4a_78(Eurydice_array_منزل_subslice_shared_d48(نجی_کلید,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .شروع = (ناپ_t)384U * (ناپ_t)3U,
            .سرا = (ناپ_t)768U * (ناپ_t)3U + (ناپ_t)32U
          }
        )));
  Eurydice_borrow_ٹکڑا_u8
  expected =
    Eurydice_array_منزل_subslice_shared_d48(نجی_کلید,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .شروع = (ناپ_t)768U * (ناپ_t)3U + (ناپ_t)32U,
          .سرا = (ناپ_t)768U * (ناپ_t)3U + (ناپ_t)64U
        }
      ));
  أرجع Eurydice_array_eq_ٹکڑا_shared((ناپ_t)32U, &t, &expected, uint8_t, bool);
}

/**
 Validate an ML-KEM private key.

 This implements the Hash check in 7.3 3.
 Note that the size checks in 7.2 1 and 2 are covered by the `SECRET_KEY_SIZE`
 and `CIPHERTEXT_SIZE` in the `private_key` and `ciphertext` types.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.validate_private_key
with types libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- SECRET_KEY_SIZE= 2400
- CIPHERTEXT_SIZE= 1088
*/
ساكن KRML_MUSTINLINE bool
libcrux_ml_kem_ind_cca_validate_نجی_کلید_ba(
  ثابت Eurydice_arr_7d *نجی_کلید,
  ثابت Eurydice_arr_2b *_ciphertext
)
{
  أرجع libcrux_ml_kem_ind_cca_validate_نجی_کلید_only_52(نجی_کلید);
}

/**
 Private key validation
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.instantiations.portable.validate_private_key
with const generics
- K= 3
- SECRET_KEY_SIZE= 2400
- CIPHERTEXT_SIZE= 1088
*/
ساكن KRML_MUSTINLINE bool
libcrux_ml_kem_ind_cca_instantiations_portable_validate_نجی_کلید_d3(
  ثابت Eurydice_arr_7d *نجی_کلید,
  ثابت Eurydice_arr_2b *ciphertext
)
{
  أرجع libcrux_ml_kem_ind_cca_validate_نجی_کلید_ba(نجی_کلید, ciphertext);
}

/**
 Validate a private key.

 Returns `true` if valid, and `false` otherwise.
*/
ساكن مضمن bool
libcrux_ml_kem_mlkem768_portable_validate_نجی_کلید(
  ثابت Eurydice_arr_7d *نجی_کلید,
  ثابت Eurydice_arr_2b *ciphertext
)
{
  أرجع
    libcrux_ml_kem_ind_cca_instantiations_portable_validate_نجی_کلید_d3(نجی_کلید,
      ciphertext);
}

/**
 Private key validation
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.instantiations.portable.validate_private_key_only
with const generics
- K= 3
- SECRET_KEY_SIZE= 2400
*/
ساكن KRML_MUSTINLINE bool
libcrux_ml_kem_ind_cca_instantiations_portable_validate_نجی_کلید_only_3b(
  ثابت Eurydice_arr_7d *نجی_کلید
)
{
  أرجع libcrux_ml_kem_ind_cca_validate_نجی_کلید_only_52(نجی_کلید);
}

/**
 Validate the private key only.

 Returns `true` if valid, and `false` otherwise.
*/
ساكن مضمن bool
libcrux_ml_kem_mlkem768_portable_validate_نجی_کلید_only(ثابت Eurydice_arr_7d *نجی_کلید)
{
  أرجع
    libcrux_ml_kem_ind_cca_instantiations_portable_validate_نجی_کلید_only_3b(نجی_کلید);
}

/**
This function found in impl {core::ops::function::FnMut<(usize), libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]> for libcrux_ml_kem::serialize::deserialize_ring_elements_reduced_out::closure<Vector, K>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.serialize.deserialize_ring_elements_reduced_out.call_mut_0b
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
ساكن مضمن Eurydice_arr_9e
libcrux_ml_kem_serialize_deserialize_ring_elements_reduced_باہرلا_call_mut_0b_68(
  فراغ **_,
  ناپ_t tupled_دلیلاں
)
{
  أرجع libcrux_ml_kem_polynomial_ZERO_d6_ea();
}

/**
 This function deserializes ring elements and reduces the result by the field
 modulus.

 This function MUST NOT be used on secret inputs.
*/
/**
A monomorphic instance of libcrux_ml_kem.serialize.deserialize_ring_elements_reduced_out
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
ساكن KRML_MUSTINLINE Eurydice_arr_bb0
libcrux_ml_kem_serialize_deserialize_ring_elements_reduced_باہرلا_68(
  Eurydice_borrow_ٹکڑا_u8 عوامی_کلید
)
{
  Eurydice_arr_bb0 arr_struct;
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    فراغ *lvalue = (فراغ *)0U;
    arr_struct.انکڑے[i] =
      libcrux_ml_kem_serialize_deserialize_ring_elements_reduced_باہرلا_call_mut_0b_68(&lvalue,
        i);
  }
  Eurydice_arr_bb0 deserialized_pk = arr_struct;
  libcrux_ml_kem_serialize_deserialize_ring_elements_reduced_68(عوامی_کلید, &deserialized_pk);
  أرجع deserialized_pk;
}

/**
 Validate an ML-KEM public key.

 This implements the Modulus check in 7.2 2.
 Note that the size check in 7.2 1 is covered by the `PUBLIC_KEY_SIZE` in the
 `public_key` type.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.validate_public_key
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- PUBLIC_KEY_SIZE= 1184
*/
ساكن KRML_MUSTINLINE bool
libcrux_ml_kem_ind_cca_validate_عوامی_کلید_b6(ثابت Eurydice_arr_5f *عوامی_کلید)
{
  Eurydice_arr_bb0
  deserialized_pk =
    libcrux_ml_kem_serialize_deserialize_ring_elements_reduced_باہرلا_68(Eurydice_array_منزل_subslice_منزل_shared_210(عوامی_کلید,
        libcrux_ml_kem_constants_ranked_بائٹاں_فی_ring_element((ناپ_t)3U)));
  Eurydice_arr_5f
  عوامی_کلید_serialized =
    libcrux_ml_kem_ind_cpa_serialize_عوامی_کلید_b6(&deserialized_pk,
      Eurydice_array_منزل_subslice_from_shared_5f2(عوامی_کلید,
        libcrux_ml_kem_constants_ranked_بائٹاں_فی_ring_element((ناپ_t)3U)));
  أرجع Eurydice_array_eq((ناپ_t)1184U, عوامی_کلید, &عوامی_کلید_serialized, uint8_t);
}

/**
 Public key validation
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.instantiations.portable.validate_public_key
with const generics
- K= 3
- PUBLIC_KEY_SIZE= 1184
*/
ساكن KRML_MUSTINLINE bool
libcrux_ml_kem_ind_cca_instantiations_portable_validate_عوامی_کلید_3b(
  ثابت Eurydice_arr_5f *عوامی_کلید
)
{
  أرجع libcrux_ml_kem_ind_cca_validate_عوامی_کلید_b6(عوامی_کلید);
}

/**
 Validate a public key.

 Returns `true` if valid, and `false` otherwise.
*/
ساكن مضمن bool
libcrux_ml_kem_mlkem768_portable_validate_عوامی_کلید(ثابت Eurydice_arr_5f *عوامی_کلید)
{
  أرجع libcrux_ml_kem_ind_cca_instantiations_portable_validate_عوامی_کلید_3b(عوامی_کلید);
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.MlKemPublicKeyUnpacked
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- $3size_t
*/
تعريفنوع بنية libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_عوامی_کلید_Unpacked_51_s
{
  libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_عوامی_کلید_Unpacked_51 ind_cpa_عوامی_کلید;
  Eurydice_arr_ec عوامی_کلید_hash;
}
libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_عوامی_کلید_Unpacked_51;

تعريفنوع libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_عوامی_کلید_Unpacked_51
libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_عوامی_کلید_Unpacked;

/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.MlKemPrivateKeyUnpacked
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- $3size_t
*/
تعريفنوع بنية libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_نجی_کلید_Unpacked_51_s
{
  Eurydice_arr_bb0 ind_cpa_نجی_کلید;
  Eurydice_arr_ec implicit_rejection_قدر;
}
libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_نجی_کلید_Unpacked_51;

تعريفنوع بنية libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_کلید_Pair_Unpacked_s
{
  libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_نجی_کلید_Unpacked_51 نجی_کلید;
  libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_عوامی_کلید_Unpacked_51 عوامی_کلید;
}
libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_کلید_Pair_Unpacked;

/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.decapsulate
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- SECRET_KEY_SIZE= 2400
- CPA_SECRET_KEY_SIZE= 1152
- PUBLIC_KEY_SIZE= 1184
- CIPHERTEXT_SIZE= 1088
- T_AS_NTT_ENCODED_SIZE= 1152
- C1_SIZE= 960
- C2_SIZE= 128
- VECTOR_U_COMPRESSION_FACTOR= 10
- VECTOR_V_COMPRESSION_FACTOR= 4
- C1_BLOCK_SIZE= 320
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
- ETA2= 2
- ETA2_RANDOMNESS_SIZE= 128
- IMPLICIT_REJECTION_HASH_INPUT_SIZE= 1120
*/
ساكن KRML_MUSTINLINE Eurydice_arr_ec
libcrux_ml_kem_ind_cca_unpacked_decapsulate_0c(
  ثابت libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_کلید_Pair_Unpacked *کلید_pair,
  ثابت Eurydice_arr_2b *ciphertext
)
{
  Eurydice_arr_ec
  decrypted =
    libcrux_ml_kem_ind_cpa_decrypt_unpacked_01(&کلید_pair->نجی_کلید.ind_cpa_نجی_کلید,
      ciphertext);
  Eurydice_arr_c7
  منزل_hash0 =
    libcrux_ml_kem_utils_into_padded_array_c9(Eurydice_array_منزل_ٹکڑا_shared_01(&decrypted));
  Eurydice_mut_borrow_ٹکڑا_u8
  uu____0 =
    Eurydice_array_منزل_subslice_from_mut_5f1(&منزل_hash0,
      LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_ناپ);
  Eurydice_ٹکڑا_copy(uu____0,
    Eurydice_array_منزل_ٹکڑا_shared_01(&کلید_pair->عوامی_کلید.عوامی_کلید_hash),
    uint8_t);
  Eurydice_arr_c7
  hashed =
    libcrux_ml_kem_hash_functions_portable_G_4a_78(Eurydice_array_منزل_ٹکڑا_shared_17(&منزل_hash0));
  Eurydice_borrow_ٹکڑا_u8_x2
  uu____1 =
    Eurydice_ٹکڑا_ونڈو_at(Eurydice_array_منزل_ٹکڑا_shared_17(&hashed),
      LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_ناپ,
      uint8_t,
      Eurydice_borrow_ٹکڑا_u8_x2);
  Eurydice_borrow_ٹکڑا_u8 shared_secret = uu____1.fst;
  Eurydice_borrow_ٹکڑا_u8 pseudorandomness = uu____1.snd;
  Eurydice_arr_af
  منزل_hash =
    libcrux_ml_kem_utils_into_padded_array_66(Eurydice_array_منزل_ٹکڑا_shared_01(&کلید_pair->نجی_کلید.implicit_rejection_قدر));
  Eurydice_mut_borrow_ٹکڑا_u8
  uu____2 =
    Eurydice_array_منزل_subslice_from_mut_5f2(&منزل_hash,
      LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_ناپ);
  Eurydice_ٹکڑا_copy(uu____2, libcrux_ml_kem_types_as_ref_c1_52(ciphertext), uint8_t);
  Eurydice_arr_ec
  implicit_rejection_shared_secret =
    libcrux_ml_kem_hash_functions_portable_PRF_4a_3b(Eurydice_array_منزل_ٹکڑا_shared_81(&منزل_hash));
  Eurydice_arr_2b
  expected_ciphertext =
    libcrux_ml_kem_ind_cpa_encrypt_unpacked_d5(&کلید_pair->عوامی_کلید.ind_cpa_عوامی_کلید,
      &decrypted,
      pseudorandomness);
  Eurydice_borrow_ٹکڑا_u8 uu____3 = libcrux_ml_kem_types_as_ref_c1_52(ciphertext);
  uint8_t
  selector =
    libcrux_ml_kem_constant_ویلا_ops_compare_ciphertexts_وچ_constant_ویلا(uu____3,
      Eurydice_array_منزل_ٹکڑا_shared_06(&expected_ciphertext));
  أرجع
    libcrux_ml_kem_constant_ویلا_ops_select_shared_secret_وچ_constant_ویلا(shared_secret,
      Eurydice_array_منزل_ٹکڑا_shared_01(&implicit_rejection_shared_secret),
      selector);
}

/**
 Unpacked decapsulate
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.instantiations.portable.unpacked.decapsulate
with const generics
- K= 3
- SECRET_KEY_SIZE= 2400
- CPA_SECRET_KEY_SIZE= 1152
- PUBLIC_KEY_SIZE= 1184
- CIPHERTEXT_SIZE= 1088
- T_AS_NTT_ENCODED_SIZE= 1152
- C1_SIZE= 960
- C2_SIZE= 128
- VECTOR_U_COMPRESSION_FACTOR= 10
- VECTOR_V_COMPRESSION_FACTOR= 4
- C1_BLOCK_SIZE= 320
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
- ETA2= 2
- ETA2_RANDOMNESS_SIZE= 128
- IMPLICIT_REJECTION_HASH_INPUT_SIZE= 1120
*/
ساكن KRML_MUSTINLINE Eurydice_arr_ec
libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_decapsulate_19(
  ثابت libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_کلید_Pair_Unpacked *کلید_pair,
  ثابت Eurydice_arr_2b *ciphertext
)
{
  أرجع libcrux_ml_kem_ind_cca_unpacked_decapsulate_0c(کلید_pair, ciphertext);
}

/**
 Decapsulate ML-KEM 768 (unpacked)

 Generates an [`MlKemSharedSecret`].
 The input is a reference to an unpacked key pair of type [`MlKem768KeyPairUnpacked`]
 and an [`MlKem768Ciphertext`].
*/
ساكن مضمن Eurydice_arr_ec
libcrux_ml_kem_mlkem768_portable_unpacked_decapsulate(
  ثابت libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_کلید_Pair_Unpacked *نجی_کلید,
  ثابت Eurydice_arr_2b *ciphertext
)
{
  أرجع
    libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_decapsulate_19(نجی_کلید,
      ciphertext);
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.encaps_prepare
with types libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
*/
ساكن مضمن Eurydice_arr_c7
libcrux_ml_kem_ind_cca_unpacked_encaps_prepare_13(
  Eurydice_borrow_ٹکڑا_u8 randomness,
  Eurydice_borrow_ٹکڑا_u8 pk_hash
)
{
  Eurydice_arr_c7 منزل_hash = libcrux_ml_kem_utils_into_padded_array_c9(randomness);
  Eurydice_ٹکڑا_copy(Eurydice_array_منزل_subslice_from_mut_5f1(&منزل_hash,
      LIBCRUX_ML_KEM_CONSTANTS_H_DIGEST_ناپ),
    pk_hash,
    uint8_t);
  أرجع
    libcrux_ml_kem_hash_functions_portable_G_4a_78(Eurydice_array_منزل_ٹکڑا_shared_17(&منزل_hash));
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.encapsulate
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- CIPHERTEXT_SIZE= 1088
- PUBLIC_KEY_SIZE= 1184
- T_AS_NTT_ENCODED_SIZE= 1152
- C1_SIZE= 960
- C2_SIZE= 128
- VECTOR_U_COMPRESSION_FACTOR= 10
- VECTOR_V_COMPRESSION_FACTOR= 4
- VECTOR_U_BLOCK_LEN= 320
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
- ETA2= 2
- ETA2_RANDOMNESS_SIZE= 128
*/
ساكن KRML_MUSTINLINE tuple_f4
libcrux_ml_kem_ind_cca_unpacked_encapsulate_a7(
  ثابت libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_عوامی_کلید_Unpacked_51 *عوامی_کلید,
  ثابت Eurydice_arr_ec *randomness
)
{
  Eurydice_arr_c7
  hashed =
    libcrux_ml_kem_ind_cca_unpacked_encaps_prepare_13(Eurydice_array_منزل_ٹکڑا_shared_01(randomness),
      Eurydice_array_منزل_ٹکڑا_shared_01(&عوامی_کلید->عوامی_کلید_hash));
  Eurydice_borrow_ٹکڑا_u8_x2
  uu____0 =
    Eurydice_ٹکڑا_ونڈو_at(Eurydice_array_منزل_ٹکڑا_shared_17(&hashed),
      LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_ناپ,
      uint8_t,
      Eurydice_borrow_ٹکڑا_u8_x2);
  Eurydice_borrow_ٹکڑا_u8 shared_secret = uu____0.fst;
  Eurydice_borrow_ٹکڑا_u8 pseudorandomness = uu____0.snd;
  Eurydice_arr_2b
  ciphertext =
    libcrux_ml_kem_ind_cpa_encrypt_unpacked_d5(&عوامی_کلید->ind_cpa_عوامی_کلید,
      randomness,
      pseudorandomness);
  Eurydice_arr_ec shared_secret_array = { .انکڑے = { 0U } };
  Eurydice_ٹکڑا_copy(Eurydice_array_منزل_ٹکڑا_mut_01(&shared_secret_array),
    shared_secret,
    uint8_t);
  أرجع
    (
      KRML_CLITERAL(tuple_f4){
        .fst = libcrux_ml_kem_types_from_19_52(ciphertext),
        .snd = shared_secret_array
      }
    );
}

/**
 Unpacked encapsulate
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.instantiations.portable.unpacked.encapsulate
with const generics
- K= 3
- CIPHERTEXT_SIZE= 1088
- PUBLIC_KEY_SIZE= 1184
- T_AS_NTT_ENCODED_SIZE= 1152
- C1_SIZE= 960
- C2_SIZE= 128
- VECTOR_U_COMPRESSION_FACTOR= 10
- VECTOR_V_COMPRESSION_FACTOR= 4
- VECTOR_U_BLOCK_LEN= 320
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
- ETA2= 2
- ETA2_RANDOMNESS_SIZE= 128
*/
ساكن KRML_MUSTINLINE tuple_f4
libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_encapsulate_26(
  ثابت libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_عوامی_کلید_Unpacked_51 *عوامی_کلید,
  ثابت Eurydice_arr_ec *randomness
)
{
  أرجع libcrux_ml_kem_ind_cca_unpacked_encapsulate_a7(عوامی_کلید, randomness);
}

/**
 Encapsulate ML-KEM 768 (unpacked)

 Generates an ([`MlKem768Ciphertext`], [`MlKemSharedSecret`]) tuple.
 The input is a reference to an unpacked public key of type [`MlKem768PublicKeyUnpacked`],
 the SHA3-256 hash of this public key, and [`SHARED_SECRET_SIZE`] bytes of `randomness`.
*/
ساكن مضمن tuple_f4
libcrux_ml_kem_mlkem768_portable_unpacked_encapsulate(
  ثابت libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_عوامی_کلید_Unpacked_51 *عوامی_کلید,
  Eurydice_arr_ec randomness
)
{
  أرجع
    libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_encapsulate_26(عوامی_کلید,
      &randomness);
}

/**
This function found in impl {core::ops::function::FnMut<(usize), libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]> for libcrux_ml_kem::ind_cca::unpacked::transpose_a::closure::closure<Vector, K>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.transpose_a.closure.call_mut_b4
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
ساكن مضمن Eurydice_arr_9e
libcrux_ml_kem_ind_cca_unpacked_transpose_a_گھیرا_call_mut_b4_68(
  فراغ **_,
  ناپ_t tupled_دلیلاں
)
{
  أرجع libcrux_ml_kem_polynomial_ZERO_d6_ea();
}

/**
This function found in impl {core::ops::function::FnMut<(usize), [libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]; K]> for libcrux_ml_kem::ind_cca::unpacked::transpose_a::closure<Vector, K>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.transpose_a.call_mut_22
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
ساكن مضمن Eurydice_arr_bb0
libcrux_ml_kem_ind_cca_unpacked_transpose_a_call_mut_22_68(فراغ **_, ناپ_t tupled_دلیلاں)
{
  Eurydice_arr_bb0 arr_struct;
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    فراغ *lvalue = (فراغ *)0U;
    arr_struct.انکڑے[i] =
      libcrux_ml_kem_ind_cca_unpacked_transpose_a_گھیرا_call_mut_b4_68(&lvalue,
        i);
  }
  أرجع arr_struct;
}

/**
This function found in impl {core::clone::Clone for libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@2]}
*/
/**
A monomorphic instance of libcrux_ml_kem.polynomial.clone_c1
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ساكن مضمن Eurydice_arr_9e
libcrux_ml_kem_polynomial_clone_c1_ea(ثابت Eurydice_arr_9e *self)
{
  أرجع
    core_array__core__clone__Clone_for__T__N___clone((ناپ_t)16U,
      self,
      Eurydice_arr_d6,
      Eurydice_arr_9e);
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.transpose_a
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
ساكن مضمن Eurydice_arr_c10
libcrux_ml_kem_ind_cca_unpacked_transpose_a_68(Eurydice_arr_c10 ind_cpa_a)
{
  Eurydice_arr_c10 arr_struct;
  لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    فراغ *lvalue = (فراغ *)0U;
    arr_struct.انکڑے[i] = libcrux_ml_kem_ind_cca_unpacked_transpose_a_call_mut_22_68(&lvalue, i);
  }
  Eurydice_arr_c10 A = arr_struct;
  لكل (ناپ_t i0 = (ناپ_t)0U; i0 < (ناپ_t)3U; i0++)
  {
    ناپ_t i1 = i0;
    لكل (ناپ_t i = (ناپ_t)0U; i < (ناپ_t)3U; i++)
    {
      ناپ_t j = i;
      Eurydice_arr_9e uu____0 = libcrux_ml_kem_polynomial_clone_c1_ea(&ind_cpa_a.انکڑے[j].انکڑے[i1]);
      A.انکڑے[i1].انکڑے[j] = uu____0;
    }
  }
  أرجع A;
}

/**
 Generate Unpacked Keys
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.generate_keypair
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]], libcrux_ml_kem_variant_MlKem
with const generics
- K= 3
- CPA_PRIVATE_KEY_SIZE= 1152
- PRIVATE_KEY_SIZE= 2400
- PUBLIC_KEY_SIZE= 1184
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_kem_ind_cca_unpacked_generate_keypair_b8(
  Eurydice_arr_c7 randomness,
  libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_کلید_Pair_Unpacked *باہرلا
)
{
  Eurydice_borrow_ٹکڑا_u8
  ind_cpa_keypair_randomness =
    Eurydice_array_منزل_subslice_shared_d47(&randomness,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .شروع = (ناپ_t)0U,
          .سرا = LIBCRUX_ML_KEM_CONSTANTS_CPA_PKE_کلید_GENERATION_بیج_ناپ
        }
      ));
  Eurydice_borrow_ٹکڑا_u8
  implicit_rejection_قدر =
    Eurydice_array_منزل_subslice_from_shared_5f1(&randomness,
      LIBCRUX_ML_KEM_CONSTANTS_CPA_PKE_کلید_GENERATION_بیج_ناپ);
  libcrux_ml_kem_ind_cpa_generate_keypair_unpacked_39(ind_cpa_keypair_randomness,
    &باہرلا->نجی_کلید.ind_cpa_نجی_کلید,
    &باہرلا->عوامی_کلید.ind_cpa_عوامی_کلید);
  Eurydice_arr_c10
  A = libcrux_ml_kem_ind_cca_unpacked_transpose_a_68(باہرلا->عوامی_کلید.ind_cpa_عوامی_کلید.A);
  باہرلا->عوامی_کلید.ind_cpa_عوامی_کلید.A = A;
  Eurydice_arr_5f
  pk_serialized =
    libcrux_ml_kem_ind_cpa_serialize_عوامی_کلید_b6(&باہرلا->عوامی_کلید.ind_cpa_عوامی_کلید.t_as_ntt,
      Eurydice_array_منزل_ٹکڑا_shared_01(&باہرلا->عوامی_کلید.ind_cpa_عوامی_کلید.بیج_for_A));
  Eurydice_arr_ec
  uu____0 =
    libcrux_ml_kem_hash_functions_portable_H_4a_78(Eurydice_array_منزل_ٹکڑا_shared_ff(&pk_serialized));
  باہرلا->عوامی_کلید.عوامی_کلید_hash = uu____0;
  Eurydice_arr_ec arr;
  حافظہ_نقل(arr.انکڑے, implicit_rejection_قدر.ptr, (ناپ_t)32U * حجم (uint8_t));
  Eurydice_arr_ec
  uu____1 =
    core_نتیجہ_unwrap_26_39((
        KRML_CLITERAL(core_نتیجہ_نتیجہ_07){ .ٹیگ = core_نتیجہ_Ok, .val = { .case_Ok = arr } }
      ));
  باہرلا->نجی_کلید.implicit_rejection_قدر = uu____1;
}

/**
 Generate a key pair
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.instantiations.portable.unpacked.generate_keypair
with const generics
- K= 3
- CPA_PRIVATE_KEY_SIZE= 1152
- PRIVATE_KEY_SIZE= 2400
- PUBLIC_KEY_SIZE= 1184
- ETA1= 2
- ETA1_RANDOMNESS_SIZE= 128
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_generate_keypair_e9(
  Eurydice_arr_c7 randomness,
  libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_کلید_Pair_Unpacked *باہرلا
)
{
  libcrux_ml_kem_ind_cca_unpacked_generate_keypair_b8(randomness, باہرلا);
}

/**
 Generate ML-KEM 768 Key Pair in "unpacked" form.
*/
ساكن مضمن فراغ
libcrux_ml_kem_mlkem768_portable_unpacked_generate_کلید_pair_mut(
  Eurydice_arr_c7 randomness,
  libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_کلید_Pair_Unpacked *کلید_pair
)
{
  libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_generate_keypair_e9(randomness,
    کلید_pair);
}

/**
This function found in impl {core::default::Default for libcrux_ml_kem::ind_cca::unpacked::MlKemPublicKeyUnpacked<Vector, K>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.default_30
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
ساكن KRML_MUSTINLINE libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_عوامی_کلید_Unpacked_51
libcrux_ml_kem_ind_cca_unpacked_default_30_68(فراغ)
{
  أرجع
    (
      KRML_CLITERAL(libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_عوامی_کلید_Unpacked_51){
        .ind_cpa_عوامی_کلید = libcrux_ml_kem_ind_cpa_unpacked_default_8b_68(),
        .عوامی_کلید_hash = { .انکڑے = { 0U } }
      }
    );
}

/**
This function found in impl {core::default::Default for libcrux_ml_kem::ind_cca::unpacked::MlKemKeyPairUnpacked<Vector, K>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.default_7b
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
ساكن KRML_MUSTINLINE libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_کلید_Pair_Unpacked
libcrux_ml_kem_ind_cca_unpacked_default_7b_68(فراغ)
{
  libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_نجی_کلید_Unpacked_51
  uu____0 =
    {
      .ind_cpa_نجی_کلید = libcrux_ml_kem_ind_cpa_unpacked_default_70_68(),
      .implicit_rejection_قدر = { .انکڑے = { 0U } }
    };
  أرجع
    (
      KRML_CLITERAL(libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_کلید_Pair_Unpacked){
        .نجی_کلید = uu____0,
        .عوامی_کلید = libcrux_ml_kem_ind_cca_unpacked_default_30_68()
      }
    );
}

/**
 Generate ML-KEM 768 Key Pair in "unpacked" form.
*/
ساكن مضمن libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_کلید_Pair_Unpacked
libcrux_ml_kem_mlkem768_portable_unpacked_generate_کلید_pair(Eurydice_arr_c7 randomness)
{
  libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_کلید_Pair_Unpacked
  کلید_pair = libcrux_ml_kem_ind_cca_unpacked_default_7b_68();
  libcrux_ml_kem_mlkem768_portable_unpacked_generate_کلید_pair_mut(randomness, &کلید_pair);
  أرجع کلید_pair;
}

/**
 Create a new, empty unpacked key.
*/
ساكن مضمن libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_کلید_Pair_Unpacked
libcrux_ml_kem_mlkem768_portable_unpacked_init_کلید_pair(فراغ)
{
  أرجع libcrux_ml_kem_ind_cca_unpacked_default_7b_68();
}

/**
 Create a new, empty unpacked public key.
*/
ساكن مضمن libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_عوامی_کلید_Unpacked_51
libcrux_ml_kem_mlkem768_portable_unpacked_init_عوامی_کلید(فراغ)
{
  أرجع libcrux_ml_kem_ind_cca_unpacked_default_30_68();
}

/**
 Take a serialized private key and generate an unpacked key pair from it.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.keys_from_private_key
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- SECRET_KEY_SIZE= 2400
- CPA_SECRET_KEY_SIZE= 1152
- PUBLIC_KEY_SIZE= 1184
- T_AS_NTT_ENCODED_SIZE= 1152
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_kem_ind_cca_unpacked_کلیدیں_from_نجی_کلید_01(
  ثابت Eurydice_arr_7d *نجی_کلید,
  libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_کلید_Pair_Unpacked *کلید_pair
)
{
  Eurydice_borrow_ٹکڑا_u8_x4
  uu____0 =
    libcrux_ml_kem_types_unpack_نجی_کلید_64(Eurydice_array_منزل_ٹکڑا_shared_51(نجی_کلید));
  Eurydice_borrow_ٹکڑا_u8 ind_cpa_secret_کلید = uu____0.fst;
  Eurydice_borrow_ٹکڑا_u8 ind_cpa_عوامی_کلید = uu____0.snd;
  Eurydice_borrow_ٹکڑا_u8 ind_cpa_عوامی_کلید_hash = uu____0.thd;
  Eurydice_borrow_ٹکڑا_u8 implicit_rejection_قدر = uu____0.f3;
  libcrux_ml_kem_ind_cpa_deserialize_سمتیہ_68(ind_cpa_secret_کلید,
    &کلید_pair->نجی_کلید.ind_cpa_نجی_کلید);
  libcrux_ml_kem_ind_cpa_build_unpacked_عوامی_کلید_mut_05(ind_cpa_عوامی_کلید,
    &کلید_pair->عوامی_کلید.ind_cpa_عوامی_کلید);
  Eurydice_ٹکڑا_copy(Eurydice_array_منزل_ٹکڑا_mut_01(&کلید_pair->عوامی_کلید.عوامی_کلید_hash),
    ind_cpa_عوامی_کلید_hash,
    uint8_t);
  Eurydice_ٹکڑا_copy(Eurydice_array_منزل_ٹکڑا_mut_01(&کلید_pair->نجی_کلید.implicit_rejection_قدر),
    implicit_rejection_قدر,
    uint8_t);
  Eurydice_ٹکڑا_copy(Eurydice_array_منزل_ٹکڑا_mut_01(&کلید_pair->عوامی_کلید.ind_cpa_عوامی_کلید.بیج_for_A),
    Eurydice_ٹکڑا_subslice_from_shared_6d(ind_cpa_عوامی_کلید, (ناپ_t)1152U),
    uint8_t);
}

/**
 Take a serialized private key and generate an unpacked key pair from it.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.instantiations.portable.unpacked.keypair_from_private_key
with const generics
- K= 3
- SECRET_KEY_SIZE= 2400
- CPA_SECRET_KEY_SIZE= 1152
- PUBLIC_KEY_SIZE= 1184
- T_AS_NTT_ENCODED_SIZE= 1152
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_keypair_from_نجی_کلید_71(
  ثابت Eurydice_arr_7d *نجی_کلید,
  libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_کلید_Pair_Unpacked *کلید_pair
)
{
  libcrux_ml_kem_ind_cca_unpacked_کلیدیں_from_نجی_کلید_01(نجی_کلید, کلید_pair);
}

/**
 Get an unpacked key from a private key.
*/
ساكن مضمن فراغ
libcrux_ml_kem_mlkem768_portable_unpacked_کلید_pair_from_نجی_mut(
  ثابت Eurydice_arr_7d *نجی_کلید,
  libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_کلید_Pair_Unpacked *کلید_pair
)
{
  libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_keypair_from_نجی_کلید_71(نجی_کلید,
    کلید_pair);
}

/**
 Get the serialized private key.
*/
/**
This function found in impl {libcrux_ml_kem::ind_cca::unpacked::MlKemKeyPairUnpacked<Vector, K>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.serialized_private_key_mut_11
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- CPA_PRIVATE_KEY_SIZE= 1152
- PRIVATE_KEY_SIZE= 2400
- PUBLIC_KEY_SIZE= 1184
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_kem_ind_cca_unpacked_serialized_نجی_کلید_mut_11_21(
  ثابت libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_کلید_Pair_Unpacked *self,
  Eurydice_arr_7d *serialized
)
{
  libcrux_ml_kem_utils_extraction_helper_Keypair768
  uu____0 =
    libcrux_ml_kem_ind_cpa_serialize_unpacked_secret_کلید_30(&self->عوامی_کلید.ind_cpa_عوامی_کلید,
      &self->نجی_کلید.ind_cpa_نجی_کلید);
  Eurydice_arr_0e ind_cpa_نجی_کلید = uu____0.fst;
  Eurydice_arr_5f ind_cpa_عوامی_کلید = uu____0.snd;
  libcrux_ml_kem_ind_cca_serialize_kem_secret_کلید_mut_52(Eurydice_array_منزل_ٹکڑا_shared_f4(&ind_cpa_نجی_کلید),
    Eurydice_array_منزل_ٹکڑا_shared_ff(&ind_cpa_عوامی_کلید),
    Eurydice_array_منزل_ٹکڑا_shared_01(&self->نجی_کلید.implicit_rejection_قدر),
    serialized);
}

/**
 Get the serialized private key.
*/
/**
This function found in impl {libcrux_ml_kem::ind_cca::unpacked::MlKemKeyPairUnpacked<Vector, K>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.serialized_private_key_11
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- CPA_PRIVATE_KEY_SIZE= 1152
- PRIVATE_KEY_SIZE= 2400
- PUBLIC_KEY_SIZE= 1184
*/
ساكن KRML_MUSTINLINE Eurydice_arr_7d
libcrux_ml_kem_ind_cca_unpacked_serialized_نجی_کلید_11_21(
  ثابت libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_کلید_Pair_Unpacked *self
)
{
  Eurydice_arr_7d sk = libcrux_ml_kem_types_default_d3_79();
  libcrux_ml_kem_ind_cca_unpacked_serialized_نجی_کلید_mut_11_21(self, &sk);
  أرجع sk;
}

/**
 Get the serialized private key.
*/
ساكن مضمن Eurydice_arr_7d
libcrux_ml_kem_mlkem768_portable_unpacked_کلید_pair_serialized_نجی_کلید(
  ثابت libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_کلید_Pair_Unpacked *کلید_pair
)
{
  أرجع libcrux_ml_kem_ind_cca_unpacked_serialized_نجی_کلید_11_21(کلید_pair);
}

/**
 Get the serialized private key.
*/
ساكن مضمن فراغ
libcrux_ml_kem_mlkem768_portable_unpacked_کلید_pair_serialized_نجی_کلید_mut(
  ثابت libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_کلید_Pair_Unpacked *کلید_pair,
  Eurydice_arr_7d *serialized
)
{
  libcrux_ml_kem_ind_cca_unpacked_serialized_نجی_کلید_mut_11_21(کلید_pair, serialized);
}

/**
 Get the serialized public key.
*/
/**
This function found in impl {libcrux_ml_kem::ind_cca::unpacked::MlKemPublicKeyUnpacked<Vector, K>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.serialized_dd
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- PUBLIC_KEY_SIZE= 1184
*/
ساكن KRML_MUSTINLINE Eurydice_arr_5f
libcrux_ml_kem_ind_cca_unpacked_serialized_dd_b6(
  ثابت libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_عوامی_کلید_Unpacked_51 *self
)
{
  أرجع
    libcrux_ml_kem_types_from_51_3d(libcrux_ml_kem_ind_cpa_serialize_عوامی_کلید_b6(&self->ind_cpa_عوامی_کلید.t_as_ntt,
        Eurydice_array_منزل_ٹکڑا_shared_01(&self->ind_cpa_عوامی_کلید.بیج_for_A)));
}

/**
 Get the serialized public key.
*/
/**
This function found in impl {libcrux_ml_kem::ind_cca::unpacked::MlKemKeyPairUnpacked<Vector, K>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.serialized_public_key_11
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- PUBLIC_KEY_SIZE= 1184
*/
ساكن KRML_MUSTINLINE Eurydice_arr_5f
libcrux_ml_kem_ind_cca_unpacked_serialized_عوامی_کلید_11_b6(
  ثابت libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_کلید_Pair_Unpacked *self
)
{
  أرجع libcrux_ml_kem_ind_cca_unpacked_serialized_dd_b6(&self->عوامی_کلید);
}

/**
 Get the serialized public key.
*/
ساكن مضمن Eurydice_arr_5f
libcrux_ml_kem_mlkem768_portable_unpacked_کلید_pair_serialized_عوامی_کلید(
  ثابت libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_کلید_Pair_Unpacked *کلید_pair
)
{
  أرجع libcrux_ml_kem_ind_cca_unpacked_serialized_عوامی_کلید_11_b6(کلید_pair);
}

/**
 Get the serialized public key.
*/
/**
This function found in impl {libcrux_ml_kem::ind_cca::unpacked::MlKemPublicKeyUnpacked<Vector, K>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.serialized_mut_dd
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- PUBLIC_KEY_SIZE= 1184
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_kem_ind_cca_unpacked_serialized_mut_dd_b6(
  ثابت libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_عوامی_کلید_Unpacked_51 *self,
  Eurydice_arr_5f *serialized
)
{
  libcrux_ml_kem_ind_cpa_serialize_عوامی_کلید_mut_b6(&self->ind_cpa_عوامی_کلید.t_as_ntt,
    Eurydice_array_منزل_ٹکڑا_shared_01(&self->ind_cpa_عوامی_کلید.بیج_for_A),
    serialized);
}

/**
 Get the serialized public key.
*/
/**
This function found in impl {libcrux_ml_kem::ind_cca::unpacked::MlKemKeyPairUnpacked<Vector, K>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.serialized_public_key_mut_11
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- PUBLIC_KEY_SIZE= 1184
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_kem_ind_cca_unpacked_serialized_عوامی_کلید_mut_11_b6(
  ثابت libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_کلید_Pair_Unpacked *self,
  Eurydice_arr_5f *serialized
)
{
  libcrux_ml_kem_ind_cca_unpacked_serialized_mut_dd_b6(&self->عوامی_کلید, serialized);
}

/**
 Get the serialized public key.
*/
ساكن مضمن فراغ
libcrux_ml_kem_mlkem768_portable_unpacked_کلید_pair_serialized_عوامی_کلید_mut(
  ثابت libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_کلید_Pair_Unpacked *کلید_pair,
  Eurydice_arr_5f *serialized
)
{
  libcrux_ml_kem_ind_cca_unpacked_serialized_عوامی_کلید_mut_11_b6(کلید_pair, serialized);
}

/**
This function found in impl {core::clone::Clone for libcrux_ml_kem::ind_cpa::unpacked::IndCpaPublicKeyUnpacked<Vector, K>[TraitClause@0, TraitClause@2]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.unpacked.clone_91
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
ساكن مضمن libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_عوامی_کلید_Unpacked_51
libcrux_ml_kem_ind_cpa_unpacked_clone_91_68(
  ثابت libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_عوامی_کلید_Unpacked_51 *self
)
{
  Eurydice_arr_bb0
  uu____0 =
    core_array__core__clone__Clone_for__T__N___clone((ناپ_t)3U,
      &self->t_as_ntt,
      Eurydice_arr_9e,
      Eurydice_arr_bb0);
  Eurydice_arr_ec
  uu____1 =
    core_array__core__clone__Clone_for__T__N___clone((ناپ_t)32U,
      &self->بیج_for_A,
      uint8_t,
      Eurydice_arr_ec);
  أرجع
    (
      KRML_CLITERAL(libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_عوامی_کلید_Unpacked_51){
        .t_as_ntt = uu____0,
        .بیج_for_A = uu____1,
        .A = core_array__core__clone__Clone_for__T__N___clone((ناپ_t)3U,
          &self->A,
          Eurydice_arr_bb0,
          Eurydice_arr_c10)
      }
    );
}

/**
This function found in impl {core::clone::Clone for libcrux_ml_kem::ind_cca::unpacked::MlKemPublicKeyUnpacked<Vector, K>[TraitClause@0, TraitClause@2]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.clone_d7
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
ساكن مضمن libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_عوامی_کلید_Unpacked_51
libcrux_ml_kem_ind_cca_unpacked_clone_d7_68(
  ثابت libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_عوامی_کلید_Unpacked_51 *self
)
{
  libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_عوامی_کلید_Unpacked_51
  uu____0 = libcrux_ml_kem_ind_cpa_unpacked_clone_91_68(&self->ind_cpa_عوامی_کلید);
  أرجع
    (
      KRML_CLITERAL(libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_عوامی_کلید_Unpacked_51){
        .ind_cpa_عوامی_کلید = uu____0,
        .عوامی_کلید_hash = core_array__core__clone__Clone_for__T__N___clone((ناپ_t)32U,
          &self->عوامی_کلید_hash,
          uint8_t,
          Eurydice_arr_ec)
      }
    );
}

/**
 Get the serialized public key.
*/
/**
This function found in impl {libcrux_ml_kem::ind_cca::unpacked::MlKemKeyPairUnpacked<Vector, K>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.public_key_11
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
ساكن KRML_MUSTINLINE ثابت
libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_عوامی_کلید_Unpacked_51
*libcrux_ml_kem_ind_cca_unpacked_عوامی_کلید_11_68(
  ثابت libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_کلید_Pair_Unpacked *self
)
{
  أرجع &self->عوامی_کلید;
}

/**
 Get the unpacked public key.
*/
ساكن مضمن فراغ
libcrux_ml_kem_mlkem768_portable_unpacked_عوامی_کلید(
  ثابت libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_کلید_Pair_Unpacked *کلید_pair,
  libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_عوامی_کلید_Unpacked_51 *pk
)
{
  libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_عوامی_کلید_Unpacked_51
  uu____0 =
    libcrux_ml_kem_ind_cca_unpacked_clone_d7_68(libcrux_ml_kem_ind_cca_unpacked_عوامی_کلید_11_68(کلید_pair));
  pk[0U] = uu____0;
}

/**
 Get the serialized public key.
*/
ساكن مضمن فراغ
libcrux_ml_kem_mlkem768_portable_unpacked_serialized_عوامی_کلید(
  ثابت libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_عوامی_کلید_Unpacked_51 *عوامی_کلید,
  Eurydice_arr_5f *serialized
)
{
  libcrux_ml_kem_ind_cca_unpacked_serialized_mut_dd_b6(عوامی_کلید, serialized);
}

/**
 Generate an unpacked key from a serialized key.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.unpack_public_key
with types libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]], libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- T_AS_NTT_ENCODED_SIZE= 1152
- PUBLIC_KEY_SIZE= 1184
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_kem_ind_cca_unpacked_unpack_عوامی_کلید_22(
  ثابت Eurydice_arr_5f *عوامی_کلید,
  libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_عوامی_کلید_Unpacked_51 *unpacked_عوامی_کلید
)
{
  Eurydice_borrow_ٹکڑا_u8
  uu____0 = Eurydice_array_منزل_subslice_منزل_shared_210(عوامی_کلید, (ناپ_t)1152U);
  libcrux_ml_kem_serialize_deserialize_ring_elements_reduced_68(uu____0,
    &unpacked_عوامی_کلید->ind_cpa_عوامی_کلید.t_as_ntt);
  unpacked_عوامی_کلید->ind_cpa_عوامی_کلید.بیج_for_A =
    libcrux_ml_kem_utils_into_padded_array_ce(Eurydice_array_منزل_subslice_from_shared_5f2(عوامی_کلید,
        (ناپ_t)1152U));
  Eurydice_arr_c10 *uu____2 = &unpacked_عوامی_کلید->ind_cpa_عوامی_کلید.A;
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_31
  lvalue =
    libcrux_ml_kem_utils_into_padded_array_de(Eurydice_array_منزل_subslice_from_shared_5f2(عوامی_کلید,
        (ناپ_t)1152U));
  libcrux_ml_kem_میٹرکس_sample_میٹرکس_A_91(uu____2, &lvalue, false);
  Eurydice_arr_ec
  uu____3 =
    libcrux_ml_kem_hash_functions_portable_H_4a_78(Eurydice_array_منزل_ٹکڑا_shared_ff(libcrux_ml_kem_types_as_ٹکڑا_e6_3d(عوامی_کلید)));
  unpacked_عوامی_کلید->عوامی_کلید_hash = uu____3;
}

/**
 Get the unpacked public key.
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cca.instantiations.portable.unpacked.unpack_public_key
with const generics
- K= 3
- T_AS_NTT_ENCODED_SIZE= 1152
- PUBLIC_KEY_SIZE= 1184
*/
ساكن KRML_MUSTINLINE فراغ
libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_unpack_عوامی_کلید_d3(
  ثابت Eurydice_arr_5f *عوامی_کلید,
  libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_عوامی_کلید_Unpacked_51 *unpacked_عوامی_کلید
)
{
  libcrux_ml_kem_ind_cca_unpacked_unpack_عوامی_کلید_22(عوامی_کلید, unpacked_عوامی_کلید);
}

/**
 Get the unpacked public key.
*/
ساكن مضمن فراغ
libcrux_ml_kem_mlkem768_portable_unpacked_unpacked_عوامی_کلید(
  ثابت Eurydice_arr_5f *عوامی_کلید,
  libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_عوامی_کلید_Unpacked_51 *unpacked_عوامی_کلید
)
{
  libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_unpack_عوامی_کلید_d3(عوامی_کلید,
    unpacked_عوامی_کلید);
}

#إذا defined(__cplusplus)
}
#جے_انت

#تعریف_کرو libcrux_mlkem768_portable_H_DEFINED
#جے_انت /* libcrux_mlkem768_portable_H */


/* rename some types to be a bit more ergonomic */

/* ML-KEM 768 */
تعريفنوع Eurydice_arr_c7 libcrux_mlkem768_keypair_rnd;
تعريفنوع Eurydice_arr_ec libcrux_mlkem768_enc_rnd;
تعريفنوع libcrux_ml_kem_mlkem768_Ml_Kem768_کلید_Pair libcrux_mlkem768_keypair;
تعريفنوع Eurydice_arr_5f libcrux_mlkem768_pk;
تعريفنوع Eurydice_arr_7d libcrux_mlkem768_sk;
تعريفنوع Eurydice_arr_2b libcrux_mlkem768_ciphertext;
تعريفنوع tuple_f4 libcrux_mlkem768_enc_نتیجہ;
تعريفنوع Eurydice_arr_ec libcrux_mlkem768_dec_نتیجہ;
/* ML-DSA 44 */
تعريفنوع Eurydice_arr_ec libcrux_mldsa44_keypair_rnd;
تعريفنوع libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_MLDSA44_کلید_Pair
    libcrux_mldsa44_keypair;
تعريفنوع Eurydice_arr_10 libcrux_mldsa44_sk;
تعريفنوع Eurydice_arr_02 libcrux_mldsa44_pk;
تعريفنوع Eurydice_borrow_ٹکڑا_u8 libcrux_mldsa44_سنیہا;
تعريفنوع Eurydice_arr_ec libcrux_mldsa44_sign_rnd;
تعريفنوع core_نتیجہ_نتیجہ_48 libcrux_mldsa44_sign_نتیجہ;
تعريفنوع core_نتیجہ_نتیجہ_41 libcrux_mldsa44_verify_نتیجہ;
تعريفنوع Eurydice_arr_85 libcrux_mldsa44_signature;
/* ML-DSA 65 */
تعريفنوع Eurydice_arr_ec libcrux_mldsa65_keypair_rnd;
تعريفنوع libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_MLDSA65_کلید_Pair
    libcrux_mldsa65_keypair;
تعريفنوع Eurydice_arr_24 libcrux_mldsa65_sk;
تعريفنوع Eurydice_arr_29 libcrux_mldsa65_pk;
تعريفنوع Eurydice_borrow_ٹکڑا_u8 libcrux_mldsa65_سنیہا;
تعريفنوع Eurydice_arr_ec libcrux_mldsa65_sign_rnd;
تعريفنوع core_نتیجہ_نتیجہ_8c libcrux_mldsa65_sign_نتیجہ;
تعريفنوع core_نتیجہ_نتیجہ_41 libcrux_mldsa65_verify_نتیجہ;
تعريفنوع Eurydice_arr_0c libcrux_mldsa65_signature;
/* ML-DSA 87 */
تعريفنوع Eurydice_arr_ec libcrux_mldsa87_keypair_rnd;
تعريفنوع libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_MLDSA87_کلید_Pair
    libcrux_mldsa87_keypair;
تعريفنوع Eurydice_arr_e2 libcrux_mldsa87_sk;
تعريفنوع Eurydice_arr_43 libcrux_mldsa87_pk;
تعريفنوع Eurydice_borrow_ٹکڑا_u8 libcrux_mldsa87_سنیہا;
تعريفنوع Eurydice_arr_ec libcrux_mldsa87_sign_rnd;
تعريفنوع core_نتیجہ_نتیجہ_8b libcrux_mldsa87_sign_نتیجہ;
تعريفنوع core_نتیجہ_نتیجہ_41 libcrux_mldsa87_verify_نتیجہ;
تعريفنوع Eurydice_arr_93 libcrux_mldsa87_signature;

#تعریف_کرو LIBCRUX_نتیجہ_OK	core_نتیجہ_Ok

