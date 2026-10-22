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

#ಆದರೆ !defined(__GNUC__) || (__GNUC__ < 2)
# define __attribute__(x)
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿಸು KRML_MUSTINLINE ಸಾಲೊಳಗೆ
#ವ್ಯಾಖ್ಯಾನಿಸು KRML_NOINLINE __attribute__((noinline, ಬಳಸದ))
#ವ್ಯಾಖ್ಯಾನಿಸು KRML_HOST_EPRINTF(...)
#ವ್ಯಾಖ್ಯಾನಿಸು KRML_HOST_EXIT(x) fatal_f("internal error")
#ವ್ಯಾಖ್ಯಾನಿಸು KRML_UNION_CONSTRUCTOR(T)

ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
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

ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
store32_le(uint8_t dst[4], uint32_t src)
{
	dst[0] = src & 0xff;
	dst[1] = (src >> 8) & 0xff;
	dst[2] = (src >> 16) & 0xff;
	dst[3] = (src >> 24) & 0xff;
}

ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
store16_le(uint8_t dst[2], uint16_t src)
{
	dst[0] = src & 0xff;
	dst[1] = (src >> 8) & 0xff;
}

ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
store32_be(uint8_t dst[4], uint32_t src)
{
	dst[0] = (src >> 24) & 0xff;
	dst[1] = (src >> 16) & 0xff;
	dst[2] = (src >> 8) & 0xff;
	dst[3] = src & 0xff;
}

ಸ್ಥಿರ ಸಾಲೊಳಗೆ uint64_t
load64_le(uint8_t src[8])
{
	ಹಿಂತಿರುಗಿ (uint64_t)(src[0]) |
	    ((uint64_t)(src[1]) << 8) |
	    ((uint64_t)(src[2]) << 16) |
	    ((uint64_t)(src[3]) << 24) |
	    ((uint64_t)(src[4]) << 32) |
	    ((uint64_t)(src[5]) << 40) |
	    ((uint64_t)(src[6]) << 48) |
	    ((uint64_t)(src[7]) << 56);
}

ಸ್ಥಿರ ಸಾಲೊಳಗೆ uint32_t
load32_le(uint8_t src[4])
{
	ಹಿಂತಿರುಗಿ (uint32_t)(src[0]) |
	    ((uint32_t)(src[1]) << 8) |
	    ((uint32_t)(src[2]) << 16) |
	    ((uint32_t)(src[3]) << 24);
}

ಸ್ಥಿರ ಸಾಲೊಳಗೆ uint16_t
load16_le(uint8_t src[4])
{
	ಹಿಂತಿರುಗಿ (uint16_t)(src[0]) |
	    ((uint16_t)(src[1]) << 8);
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ MISSING_BUILTIN_POPCOUNT
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ
__builtin_popcount(ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ ಅಂಕೆ)
{
  ಸ್ಥಿರಾಂಕ ಪೂರ್ಣಾಂಕ v[16] = { 0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4 };
  ಹಿಂತಿರುಗಿ v[ಅಂಕೆ & 0xf] + v[(ಅಂಕೆ >> 4) & 0xf];
}
#ಆದರೆ_ಅಂತ್ಯ

/* from libcrux/combined_extraction/generated/eurydice_glue.h */
#ಸೂಚನೆ once


#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ _MSC_VER
// For __popcnt
#ಆದರೆ_ಅಂತ್ಯ


// C++ HELPERS

#ಆದರೆ defined(__cplusplus)

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ KRML_HOST_EPRINTF
#ವ್ಯಾಖ್ಯಾನಿಸು KRML_HOST_EPRINTF(...) fprintf(stderr, __VA_ARGS__)
#ಆದರೆ_ಅಂತ್ಯ


#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ __cpp_lib_type_identity
ಮಾದರಿ <class T>
ರಚನೆ type_ತಟಸ್ಥ {
  using type = T;
};

ಮಾದರಿ <class T>
using type_ತಟಸ್ಥ_t = typename type_ತಟಸ್ಥ<T>::type;
#ಇಲ್ಲದಿದ್ದರೆ
using std::type_ತಟಸ್ಥ_t;
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿಸು KRML_UNION_CONSTRUCTOR(T)                              \
  ಮಾದರಿ <typename V>                                        \
  constexpr T(ಪೂರ್ಣಾಂಕ t, V U::*m, type_ತಟಸ್ಥ_t<V> v) : ಟ್ಯಾಗ್(t) { \
    val.*m = std::move(v);                                     \
  }                                                            \
  T() = ಪೂರ್ವನಿಯೋಜಿತ;

#ಆದರೆ_ಅಂತ್ಯ

// GENERAL-PURPOSE STUFF

#ವ್ಯಾಖ್ಯಾನಿಸು ಕೆಳಗಿನ_ನಕ್ಷತ್ರ_Ignore_ignore(e, t, _ret_t) ((ಶೂನ್ಯ)e)

#ವ್ಯಾಖ್ಯಾನಿಸು EURYDICE_ASSERT(test, ಸಂದೇಶ)                                            \
  ಮಾಡು {                                                                        \
    ಆದರೆ (!(test)) {                                                            \
      fprintf(stderr, "assertion \"%s\" failed: file \"%s\", line %d\n", ಸಂದೇಶ, \
              __FILE__, __LINE__);                                            \
      ನಿರ್ಗಮಿಸು(255);                                                              \
    }                                                                         \
  } ಆಗ (0)

// SIZEOF, ALIGNOF

#ವ್ಯಾಖ್ಯಾನಿಸು Eurydice_sizeof(t) ಗಾತ್ರ(t)

#ವ್ಯಾಖ್ಯಾನಿಸು Eurydice_alignof(t) alignof(t)

// SLICES, ARRAYS, ETC.

// For convenience, we give these common slice types, below, a distinguished
// status and rather than emit them in the client code, we skip their
// code-generation in Cleanup3.ml and write them by hand here. This makes it
// easy to write interop code that brings those definitions in scope.

// &[u8]
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_borrow_ತುಂಡು_u8_s {
  ಸ್ಥಿರಾಂಕ uint8_t *ptr;
  ಗಾತ್ರ_t meta;
} Eurydice_borrow_ತುಂಡು_u8;

// &[u16]
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_borrow_ತುಂಡು_i16_s {
  ಸ್ಥಿರಾಂಕ int16_t *ptr;
  ಗಾತ್ರ_t meta;
} Eurydice_borrow_ತುಂಡು_i16;

// &mut [u8]
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_mut_borrow_ತುಂಡು_u8_s {
  uint8_t *ptr;
  ಗಾತ್ರ_t meta;
} Eurydice_mut_borrow_ತುಂಡು_u8;

// &mut [u16]
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_mut_borrow_ತುಂಡು_i16_s {
  int16_t *ptr;
  ಗಾತ್ರ_t meta;
} Eurydice_mut_borrow_ತುಂಡು_i16;

#ಆದರೆ defined(__cplusplus)
#ವ್ಯಾಖ್ಯಾನಿಸು KRML_CLITERAL(type) type
#ಇಲ್ಲದಿದ್ದರೆ
#ವ್ಯಾಖ್ಯಾನಿಸು KRML_CLITERAL(type) (type)
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ defined(__cplusplus) && defined(__cpp_designated_initializers) || \
    !(defined(__cplusplus))
#ವ್ಯಾಖ್ಯಾನಿಸು EURYDICE_CFIELD(X) X
#ಇಲ್ಲದಿದ್ದರೆ
#ವ್ಯಾಖ್ಯಾನಿಸು EURYDICE_CFIELD(X)
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿಸು Eurydice_array_repeat(dst, len, init, t) \
  ERROR "should've been desugared"

// Copy a slice with memcopy
#ವ್ಯಾಖ್ಯಾನಿಸು Eurydice_ತುಂಡು_copy(dst, src, t) \
  ಸ್ಮರಣೆ_ನಕಲು(dst.ptr, src.ptr, dst.meta * ಗಾತ್ರ(t))

#ವ್ಯಾಖ್ಯಾನಿಸು core_array_T_N_as_ತುಂಡು(len_, ptr_, t, ret_t)   \
  (KRML_CLITERAL(ret_t){EURYDICE_CFIELD(.ptr =)(ptr_)->ದತ್ತಾಂಶ, \
                        EURYDICE_CFIELD(.meta =) len_})

#ವ್ಯಾಖ್ಯಾನಿಸು core_array__core__clone__Clone_for__T__N___clone(len, src, elem_type, \
                                                         _ret_t)              \
  (*(src))
#ವ್ಯಾಖ್ಯಾನಿಸು Try_From_ತುಂಡು_Error uint8_t
#ವ್ಯಾಖ್ಯಾನಿಸು core_array_Try_From_ತುಂಡು_Error uint8_t

// Distinguished support for some PartialEq trait implementations
//
// core::cmp::PartialEq<@Array<U, N>> for @Array<T, N>
#ವ್ಯಾಖ್ಯಾನಿಸು Eurydice_array_eq(sz, a1, a2, t) \
  (memcmp((a1)->ದತ್ತಾಂಶ, (a2)->ದತ್ತಾಂಶ, sz * ಗಾತ್ರ(t)) == 0)
// core::cmp::PartialEq<&0 (@Slice<U>)> for @Array<T, N>
#ವ್ಯಾಖ್ಯಾನಿಸು Eurydice_array_eq_ತುಂಡು_shared(sz, a1, s2, t, _) \
  (memcmp((a1)->ದತ್ತಾಂಶ, (s2)->ptr, sz * ಗಾತ್ರ(t)) == 0)
#ವ್ಯಾಖ್ಯಾನಿಸು Eurydice_array_eq_ತುಂಡು_mut(sz, a1, s2, t, _) \
  Eurydice_array_eq_ತುಂಡು_shared(sz, a1, s2, t, _)

// DEPRECATED -- should no longer be generated
#ವ್ಯಾಖ್ಯಾನಿಸು core_array_equality__core__cmp__PartialEq__Array_U__N___for__Array_T__N___eq( \
    sz, a1, a2, t, _, _ret_t)                                                         \
  Eurydice_array_eq(sz, a1, a2, t)
#ವ್ಯಾಖ್ಯಾನಿಸು core_array_equality_core_cmp_Partial_Eq_0_ತುಂಡು_U_for_Array_T_N_eq( \
    sz, a1, a2, t, _, _ret_t)                                                           \
  Eurydice_array_eq(sz, a1, ((a2)->ptr), t)
#ವ್ಯಾಖ್ಯಾನಿಸು core_cmp_impls__core__cmp__PartialEq__0_mut__B___for__1_mut__A___eq( \
    _m0, _m1, src1, src2, _0, _1, T)                                         \
  Eurydice_ತುಂಡು_eq(src1, src2, _, _, T, _)

#ವ್ಯಾಖ್ಯಾನಿಸು Eurydice_ತುಂಡು_ವಿಭಜಿಸು_at(ತುಂಡು, mid, element_type, ret_t)        \
  KRML_CLITERAL(ret_t) {                                                \
    EURYDICE_CFIELD(.fst =){EURYDICE_CFIELD(.ptr =)((ತುಂಡು).ptr),       \
                            EURYDICE_CFIELD(.meta =) mid},              \
        EURYDICE_CFIELD(.snd =) {                                       \
      EURYDICE_CFIELD(.ptr =)                                           \
      ((ತುಂಡು).ptr + mid), EURYDICE_CFIELD(.meta =)((ತುಂಡು).meta - mid) \
    }                                                                   \
  }

#ವ್ಯಾಖ್ಯಾನಿಸು Eurydice_ತುಂಡು_ವಿಭಜಿಸು_at_mut(ತುಂಡು, mid, element_type, ret_t)    \
  KRML_CLITERAL(ret_t) {                                                \
    EURYDICE_CFIELD(.fst =){EURYDICE_CFIELD(.ptr =)((ತುಂಡು).ptr),       \
                            EURYDICE_CFIELD(.meta =) mid},              \
        EURYDICE_CFIELD(.snd =) {                                       \
      EURYDICE_CFIELD(.ptr =)                                           \
      ((ತುಂಡು).ptr + mid), EURYDICE_CFIELD(.meta =)((ತುಂಡು).meta - mid) \
    }                                                                   \
  }

// Conversion of slice to an array, rewritten (by Eurydice) to name the
// destination array, since arrays are not values in C.
// N.B.: see note in karamel/lib/Inlining.ml if you change this.

#ವ್ಯಾಖ್ಯಾನಿಸು Eurydice_ತುಂಡು_ಗಮ್ಯ_ref_array2(len_, src, arr_ptr, t_ptr, t_arr, t_err, \
                                     t_res)                                   \
  (src.meta >= len_                                                           \
       ? ((t_res){.ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Ok, .val = {.case_Ok = arr_ptr}})        \
       : ((t_res){.ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Err, .val = {.case_Err = 0}}))

// CORE STUFF (conversions, endianness, ...)

// We slap extern "C" on declarations that intend to implement a prototype
// generated by Eurydice, because Eurydice prototypes are always emitted within
// an extern "C" block, UNLESS you use -fcxx17-compat, in which case, you must
// pass -DKRML_CXX17_COMPAT="" to your C++ compiler.
#ಆದರೆ defined(__cplusplus) && !defined(KRML_CXX17_COMPAT)
ಬಾಹ್ಯ "C" {
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿಸು core_hint_black_box(X, _0, _1) (X)

// [ u8; 2 ]
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_array_u8x2_s {
  uint8_t ದತ್ತಾಂಶ[2];
} Eurydice_array_u8x2;

// [ u8; 4 ]
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_array_u8x4_s {
  uint8_t ದತ್ತಾಂಶ[4];
} Eurydice_array_u8x4;

// [ u8; 8 ]
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_array_u8x8_s {
  uint8_t ದತ್ತಾಂಶ[8];
} Eurydice_array_u8x8;

ಸ್ಥಿರ ಸಾಲೊಳಗೆ uint16_t core_ಅಂಕೆ_u16_from_le_ಬೈಟುಗಳು(Eurydice_array_u8x2 buf) {
  ಹಿಂತಿರುಗಿ load16_le(buf.ದತ್ತಾಂಶ);
}

ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_array_u8x4 core_ಅಂಕೆ_u32_ಗಮ್ಯ_be_ಬೈಟುಗಳು(uint32_t src) {
  // TODO: why not store32_be?
  Eurydice_array_u8x4 a;
  uint32_t x = htobe32(src);
  ಸ್ಮರಣೆ_ನಕಲು(a.ದತ್ತಾಂಶ, &x, 4);
  ಹಿಂತಿರುಗಿ a;
}

ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_array_u8x4 core_ಅಂಕೆ_u32_ಗಮ್ಯ_le_ಬೈಟುಗಳು(uint32_t src) {
  Eurydice_array_u8x4 a;
  store32_le(a.ದತ್ತಾಂಶ, src);
  ಹಿಂತಿರುಗಿ a;
}

ಸ್ಥಿರ ಸಾಲೊಳಗೆ uint32_t core_ಅಂಕೆ_u32_from_le_ಬೈಟುಗಳು(Eurydice_array_u8x4 buf) {
  ಹಿಂತಿರುಗಿ load32_le(buf.ದತ್ತಾಂಶ);
}

ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_array_u8x8 core_ಅಂಕೆ_u64_ಗಮ್ಯ_le_ಬೈಟುಗಳು(uint64_t v) {
  Eurydice_array_u8x8 a;
  store64_le(a.ದತ್ತಾಂಶ, v);
  ಹಿಂತಿರುಗಿ a;
}

ಸ್ಥಿರ ಸಾಲೊಳಗೆ uint64_t core_ಅಂಕೆ_u64_from_le_ಬೈಟುಗಳು(Eurydice_array_u8x8 buf) {
  ಹಿಂತಿರುಗಿ load64_le(buf.ದತ್ತಾಂಶ);
}

ಸ್ಥಿರ ಸಾಲೊಳಗೆ int64_t core_convert_ಅಂಕೆ_core_convert_From_i32_for_i64_from(
    int32_t x) {
  ಹಿಂತಿರುಗಿ x;
}

ಸ್ಥಿರ ಸಾಲೊಳಗೆ uint64_t core_convert_ಅಂಕೆ_core_convert_From_u8_for_u64_from(
    uint8_t x) {
  ಹಿಂತಿರುಗಿ x;
}

ಸ್ಥಿರ ಸಾಲೊಳಗೆ uint64_t core_convert_ಅಂಕೆ_core_convert_From_u16_for_u64_from(
    uint16_t x) {
  ಹಿಂತಿರುಗಿ x;
}

ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಗಾತ್ರ_t core_convert_ಅಂಕೆ_core_convert_From_u16_for_usize_from(
    uint16_t x) {
  ಹಿಂತಿರುಗಿ x;
}

ಸ್ಥಿರ ಸಾಲೊಳಗೆ uint32_t core_ಅಂಕೆ_u8_ಎಣಿಕೆ_ones(uint8_t x0) {
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ _MSC_VER
  ಹಿಂತಿರುಗಿ __popcnt(x0);
#ಇಲ್ಲದಿದ್ದರೆ
  ಹಿಂತಿರುಗಿ __builtin_popcount(x0);
#ಆದರೆ_ಅಂತ್ಯ
}

ಸ್ಥಿರ ಸಾಲೊಳಗೆ uint32_t core_ಅಂಕೆ_u32_ಎಣಿಕೆ_ones(uint32_t x0) {
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ _MSC_VER
  ಹಿಂತಿರುಗಿ __popcnt(x0);
#ಇಲ್ಲದಿದ್ದರೆ
  ಹಿಂತಿರುಗಿ __builtin_popcount(x0);
#ಆದರೆ_ಅಂತ್ಯ
}

ಸ್ಥಿರ ಸಾಲೊಳಗೆ uint32_t core_ಅಂಕೆ_i32_ಎಣಿಕೆ_ones(int32_t x0) {
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ _MSC_VER
  ಹಿಂತಿರುಗಿ __popcnt(x0);
#ಇಲ್ಲದಿದ್ದರೆ
  ಹಿಂತಿರುಗಿ __builtin_popcount(x0);
#ಆದರೆ_ಅಂತ್ಯ
}

ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಗಾತ್ರ_t core_cmp_impls__core__cmp__Ord_for_usize__min(ಗಾತ್ರ_t a,
                                                                   ಗಾತ್ರ_t b) {
  ಆದರೆ (a <= b)
    ಹಿಂತಿರುಗಿ a;
  ಇಲ್ಲದಿದ್ದರೆ
    ಹಿಂತಿರುಗಿ b;
}

// unsigned overflow wraparound semantics in C
ಸ್ಥಿರ ಸಾಲೊಳಗೆ uint8_t core_ಅಂಕೆ_u8_wrapping_sub(uint8_t x, uint8_t y) {
  ಹಿಂತಿರುಗಿ x - y;
}
ಸ್ಥಿರ ಸಾಲೊಳಗೆ uint8_t core_ಅಂಕೆ_u8_wrapping_ಕೂಡಿಸು(uint8_t x, uint8_t y) {
  ಹಿಂತಿರುಗಿ x + y;
}
ಸ್ಥಿರ ಸಾಲೊಳಗೆ uint8_t core_ಅಂಕೆ_u8_wrapping_mul(uint8_t x, uint8_t y) {
  ಹಿಂತಿರುಗಿ x * y;
}
ಸ್ಥಿರ ಸಾಲೊಳಗೆ uint16_t core_ಅಂಕೆ_u16_wrapping_sub(uint16_t x, uint16_t y) {
  ಹಿಂತಿರುಗಿ x - y;
}
ಸ್ಥಿರ ಸಾಲೊಳಗೆ uint16_t core_ಅಂಕೆ_u16_wrapping_ಕೂಡಿಸು(uint16_t x, uint16_t y) {
  ಹಿಂತಿರುಗಿ x + y;
}
ಸ್ಥಿರ ಸಾಲೊಳಗೆ uint16_t core_ಅಂಕೆ_u16_wrapping_mul(uint16_t x, uint16_t y) {
  ಹಿಂತಿರುಗಿ x * y;
}
ಸ್ಥಿರ ಸಾಲೊಳಗೆ uint32_t core_ಅಂಕೆ_u32_wrapping_sub(uint32_t x, uint32_t y) {
  ಹಿಂತಿರುಗಿ x - y;
}
ಸ್ಥಿರ ಸಾಲೊಳಗೆ uint32_t core_ಅಂಕೆ_u32_wrapping_ಕೂಡಿಸು(uint32_t x, uint32_t y) {
  ಹಿಂತಿರುಗಿ x + y;
}
ಸ್ಥಿರ ಸಾಲೊಳಗೆ uint32_t core_ಅಂಕೆ_u32_wrapping_mul(uint32_t x, uint32_t y) {
  ಹಿಂತಿರುಗಿ x * y;
}
ಸ್ಥಿರ ಸಾಲೊಳಗೆ uint64_t core_ಅಂಕೆ_u64_wrapping_sub(uint64_t x, uint64_t y) {
  ಹಿಂತಿರುಗಿ x - y;
}
ಸ್ಥಿರ ಸಾಲೊಳಗೆ uint64_t core_ಅಂಕೆ_u64_wrapping_ಕೂಡಿಸು(uint64_t x, uint64_t y) {
  ಹಿಂತಿರುಗಿ x + y;
}
ಸ್ಥಿರ ಸಾಲೊಳಗೆ uint64_t core_ಅಂಕೆ_u64_wrapping_mul(uint64_t x, uint64_t y) {
  ಹಿಂತಿರುಗಿ x * y;
}
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಗಾತ್ರ_t core_ಅಂಕೆ_usize_wrapping_sub(ಗಾತ್ರ_t x, ಗಾತ್ರ_t y) {
  ಹಿಂತಿರುಗಿ x - y;
}
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಗಾತ್ರ_t core_ಅಂಕೆ_usize_wrapping_ಕೂಡಿಸು(ಗಾತ್ರ_t x, ಗಾತ್ರ_t y) {
  ಹಿಂತಿರುಗಿ x + y;
}
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಗಾತ್ರ_t core_ಅಂಕೆ_usize_wrapping_mul(ಗಾತ್ರ_t x, ಗಾತ್ರ_t y) {
  ಹಿಂತಿರುಗಿ x * y;
}

ಸ್ಥಿರ ಸಾಲೊಳಗೆ int8_t core_ಅಂಕೆ_i8_wrapping_ಕೂಡಿಸು(int8_t x, int8_t y) {
  ಹಿಂತಿರುಗಿ (int8_t)((uint8_t)x + (uint8_t)y);
}
ಸ್ಥಿರ ಸಾಲೊಳಗೆ int8_t core_ಅಂಕೆ_i8_wrapping_sub(int8_t x, int8_t y) {
  ಹಿಂತಿರುಗಿ (int8_t)((uint8_t)x - (uint8_t)y);
}
ಸ್ಥಿರ ಸಾಲೊಳಗೆ int8_t core_ಅಂಕೆ_i8_wrapping_mul(int8_t x, int8_t y) {
  ಹಿಂತಿರುಗಿ (int8_t)((uint8_t)x * (uint8_t)y);
}
ಸ್ಥಿರ ಸಾಲೊಳಗೆ int16_t core_ಅಂಕೆ_i16_wrapping_ಕೂಡಿಸು(int16_t x, int16_t y) {
  ಹಿಂತಿರುಗಿ (int16_t)((uint16_t)x + (uint16_t)y);
}
ಸ್ಥಿರ ಸಾಲೊಳಗೆ int16_t core_ಅಂಕೆ_i16_wrapping_sub(int16_t x, int16_t y) {
  ಹಿಂತಿರುಗಿ (int16_t)((uint16_t)x - (uint16_t)y);
}
ಸ್ಥಿರ ಸಾಲೊಳಗೆ int16_t core_ಅಂಕೆ_i16_wrapping_mul(int16_t x, int16_t y) {
  ಹಿಂತಿರುಗಿ (int16_t)((uint16_t)x * (uint16_t)y);
}
ಸ್ಥಿರ ಸಾಲೊಳಗೆ int32_t core_ಅಂಕೆ_i32_wrapping_ಕೂಡಿಸು(int32_t x, int32_t y) {
  ಹಿಂತಿರುಗಿ (int32_t)((uint32_t)x + (uint32_t)y);
}
ಸ್ಥಿರ ಸಾಲೊಳಗೆ int32_t core_ಅಂಕೆ_i32_wrapping_sub(int32_t x, int32_t y) {
  ಹಿಂತಿರುಗಿ (int32_t)((uint32_t)x - (uint32_t)y);
}
ಸ್ಥಿರ ಸಾಲೊಳಗೆ int32_t core_ಅಂಕೆ_i32_wrapping_mul(int32_t x, int32_t y) {
  ಹಿಂತಿರುಗಿ (int32_t)((uint32_t)x * (uint32_t)y);
}
ಸ್ಥಿರ ಸಾಲೊಳಗೆ int64_t core_ಅಂಕೆ_i64_wrapping_ಕೂಡಿಸು(int64_t x, int64_t y) {
  ಹಿಂತಿರುಗಿ (int64_t)((uint64_t)x + (uint64_t)y);
}
ಸ್ಥಿರ ಸಾಲೊಳಗೆ int64_t core_ಅಂಕೆ_i64_wrapping_sub(int64_t x, int64_t y) {
  ಹಿಂತಿರುಗಿ (int64_t)((uint64_t)x - (uint64_t)y);
}
ಸ್ಥಿರ ಸಾಲೊಳಗೆ int64_t core_ಅಂಕೆ_i64_wrapping_mul(int64_t x, int64_t y) {
  ಹಿಂತಿರುಗಿ (int64_t)((uint64_t)x * (uint64_t)y);
}
ಸ್ಥಿರ ಸಾಲೊಳಗೆ int8_t core_ಅಂಕೆ_i8_wrapping_neg(int8_t x) {
  ಹಿಂತಿರುಗಿ (int8_t)(-(uint8_t)x);
}
ಸ್ಥಿರ ಸಾಲೊಳಗೆ int16_t core_ಅಂಕೆ_i16_wrapping_neg(int16_t x) {
  ಹಿಂತಿರುಗಿ (int16_t)(-(uint16_t)x);
}
ಸ್ಥಿರ ಸಾಲೊಳಗೆ int32_t core_ಅಂಕೆ_i32_wrapping_neg(int32_t x) {
  ಹಿಂತಿರುಗಿ (int32_t)(-(uint32_t)x);
}
ಸ್ಥಿರ ಸಾಲೊಳಗೆ int64_t core_ಅಂಕೆ_i64_wrapping_neg(int64_t x) {
  ಹಿಂತಿರುಗಿ (int64_t)(-(uint64_t)x);
}

ಸ್ಥಿರ ಸಾಲೊಳಗೆ uint64_t core_ಅಂಕೆ_u64_rotate_ಎಡ(uint64_t x0, uint32_t x1) {
  ಹಿಂತಿರುಗಿ (x0 << x1) | (x0 >> ((-x1) & 63));
}

ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ core_ops_arith_i32_ಕೂಡಿಸು_ನಿಯೋಜಿಸು(int32_t *x0, int32_t *x1) {
  *x0 = *x0 + *x1;
}

ಸ್ಥಿರ ಸಾಲೊಳಗೆ uint8_t Eurydice_bitand_pv_u8(ಸ್ಥಿರಾಂಕ uint8_t *p, uint8_t v) {
  ಹಿಂತಿರುಗಿ (*p) & v;
}
ಸ್ಥಿರ ಸಾಲೊಳಗೆ uint8_t Eurydice_shr_pv_u8(ಸ್ಥಿರಾಂಕ uint8_t *p, int32_t v) {
  ಹಿಂತಿರುಗಿ (*p) >> v;
}
ಸ್ಥಿರ ಸಾಲೊಳಗೆ uint32_t Eurydice_min_u32(uint32_t x, uint32_t y) {
  ಹಿಂತಿರುಗಿ x < y ? x : y;
}

ಸ್ಥಿರ ಸಾಲೊಳಗೆ uint8_t
core_ops_ಬಿಟ್_core_ops_ಬಿಟ್_ಬಿಟ್_And_u8_u8_for_0_u8_bitand(
    ಸ್ಥಿರಾಂಕ uint8_t *x0, uint8_t x1) {
  ಹಿಂತಿರುಗಿ Eurydice_bitand_pv_u8(x0, x1);
}

ಸ್ಥಿರ ಸಾಲೊಳಗೆ uint8_t
core_ops_ಬಿಟ್_core_ops_ಬಿಟ್_Shr_i32_u8_for_0_u8_shr(ಸ್ಥಿರಾಂಕ uint8_t *x0,
                                                            int32_t x1) {
  ಹಿಂತಿರುಗಿ Eurydice_shr_pv_u8(x0, x1);
}

#ವ್ಯಾಖ್ಯಾನಿಸು core_ಅಂಕೆ_nonzero_ಖಾಸಗಿ_Non_Zero_Usize_Inner ಗಾತ್ರ_t
ಸ್ಥಿರ ಸಾಲೊಳಗೆ core_ಅಂಕೆ_nonzero_ಖಾಸಗಿ_Non_Zero_Usize_Inner
core_ಅಂಕೆ_nonzero_ಖಾಸಗಿ_core_clone_Clone_for_core_ಅಂಕೆ_nonzero_ಖಾಸಗಿ_Non_Zero_Usize_Inner_clone(
    core_ಅಂಕೆ_nonzero_ಖಾಸಗಿ_Non_Zero_Usize_Inner *x0) {
  ಹಿಂತಿರುಗಿ *x0;
}

#ಆದರೆ defined(__cplusplus) && !defined(KRML_CXX17_COMPAT)
}
#ಆದರೆ_ಅಂತ್ಯ

// ITERATORS

#ವ್ಯಾಖ್ಯಾನಿಸು Eurydice_range_iter_ಮುಂದಿನ(iter_ptr, t, ret_t)      \
  (((iter_ptr)->ಆರಂಭ >= (iter_ptr)->ಕೊನೆ)                 \
       ? (KRML_CLITERAL(ret_t){EURYDICE_CFIELD(.ಟ್ಯಾಗ್ =) 0, \
                               EURYDICE_CFIELD(.f0 =) 0}) \
       : (KRML_CLITERAL(ret_t){EURYDICE_CFIELD(.ಟ್ಯಾಗ್ =) 1, \
                               EURYDICE_CFIELD(.f0 =)(iter_ptr)->ಆರಂಭ++}))

#ವ್ಯಾಖ್ಯಾನಿಸು core_iter_range_core_iter_traits_iterator_Iterator_A_for_core_ops_range_Range_A_Trait_Clause_0_ಮುಂದಿನ \
  Eurydice_range_iter_ಮುಂದಿನ

// See note in karamel/lib/Inlining.ml if you change this
#ವ್ಯಾಖ್ಯಾನಿಸು Eurydice_into_iter(x, t, _ret_t, _) (x)
#ವ್ಯಾಖ್ಯಾನಿಸು core_iter_traits_collect_core_iter_traits_collect_Into_Iterator_Clause1_ಅಂಶ_I_for_I_into_iter \
  Eurydice_into_iter

//ಅಕ್ಷರಸರಣಿಗಳು

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಅಕ್ಷರ Eurydice_c_char_t;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಸ್ಥಿರಾಂಕ Eurydice_c_char_t *Prims_string;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಶೂನ್ಯ Eurydice_c_void_t;

// UNSAFE CODE

#ವ್ಯಾಖ್ಯಾನಿಸು core_ತುಂಡು_ತುಂಡು_T_as_mut_ptr(x, t, _) (x.ptr)
#ವ್ಯಾಖ್ಯಾನಿಸು core_mem_ಗಾತ್ರ_ದ(t, _) (ಗಾತ್ರ(t))
#ವ್ಯಾಖ್ಯಾನಿಸು core_ತುಂಡು_raw_from_raw_parts_mut(ptr, len, _0, _1) \
  (KRML_CLITERAL(Eurydice_ತುಂಡು){(ಶೂನ್ಯ *)(ptr), len})
#ವ್ಯಾಖ್ಯಾನಿಸು core_ತುಂಡು_raw_from_raw_parts(ptr, len, _0, _1) \
  (KRML_CLITERAL(Eurydice_ತುಂಡು){(ಶೂನ್ಯ *)(ptr), len})

// FIXME: add dedicated extraction to extract NonNull<T> as T*
#ವ್ಯಾಖ್ಯಾನಿಸು core_ptr_non_null_NonNull ಶೂನ್ಯ *

// PRINTING
//
// This is temporary. Ultimately we want to be able to extract all of this.

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಶೂನ್ಯ *core_fmt_Formatter;
#ವ್ಯಾಖ್ಯಾನಿಸು core_fmt_rt_core_fmt_rt_ವಾದ_a_new_display(x1, x2, x3, x4) \
  ಖಾಲಿ

// BOXES

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ EURYDICE_MALLOC
#ವ್ಯಾಖ್ಯಾನಿಸು EURYDICE_MALLOC ಸ್ಮರಣೆ_ಕೊಡು
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ EURYDICE_REALLOC
#ವ್ಯಾಖ್ಯಾನಿಸು EURYDICE_REALLOC realloc
#ಆದರೆ_ಅಂತ್ಯ

ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಅಕ್ಷರ *malloc_and_init(ಗಾತ್ರ_t sz, ಅಕ್ಷರ *init) {
  ಅಕ್ಷರ *ptr = (ಅಕ್ಷರ *)EURYDICE_MALLOC(sz);
  ಆದರೆ (ptr != ಖಾಲಿ) ಸ್ಮರಣೆ_ನಕಲು(ptr, init, sz);
  ಹಿಂತಿರುಗಿ ptr;
}

#ವ್ಯಾಖ್ಯಾನಿಸು Eurydice_box_new(init, t, t_dst) \
  ((t_dst)(malloc_and_init(ಗಾತ್ರ(t), (ಅಕ್ಷರ *)(&init))))

// Initializer for array of size zero
#ವ್ಯಾಖ್ಯಾನಿಸು Eurydice_ಖಾಲಿಗಳು_array(dummy, t, t_dst) ((t_dst){.ದತ್ತಾಂಶ = {}})

#ವ್ಯಾಖ್ಯಾನಿಸು Eurydice_box_new_array(len, ptr, t, t_dst) \
  ((t_dst)(malloc_and_init(len * ಗಾತ್ರ(t), (ಅಕ್ಷರ *)(ptr))))

// FIXME this needs to handle allocation failure errors, but this seems hard to
// do without evaluating malloc_and_init twice...
#ವ್ಯಾಖ್ಯಾನಿಸು alloc_boxed__alloc__boxed__Box_T___try_new(init, t, t_ret) \
  ((t_ret){.ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Ok,                                  \
           .f0 = (t *)malloc_and_init(ಗಾತ್ರ(t), (ಅಕ್ಷರ *)(&init))})

// OPTIONS

#ವ್ಯಾಖ್ಯಾನಿಸು core_option__core__option__Option_T__TraitClause_0___is_some( \
    x, ದ_type, _)                                                   \
  x->ಟ್ಯಾಗ್

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


#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ combined_core_H
#ವ್ಯಾಖ್ಯಾನಿಸು combined_core_H



#ಆದರೆ defined(__cplusplus)
ಬಾಹ್ಯ "C" {
#ಆದರೆ_ಅಂತ್ಯ

ಸ್ಥಿರ ಸಾಲೊಳಗೆ uint32_t core_ಅಂಕೆ_i32_ಎಣಿಕೆ_ones(int32_t x0);

ಸ್ಥಿರ ಸಾಲೊಳಗೆ uint16_t core_ಅಂಕೆ_u16_wrapping_ಕೂಡಿಸು(uint16_t x0, uint16_t x1);

ಸ್ಥಿರ ಸಾಲೊಳಗೆ uint64_t core_ಅಂಕೆ_u64_from_le_ಬೈಟುಗಳು(Eurydice_array_u8x8 x0);

ಸ್ಥಿರ ಸಾಲೊಳಗೆ uint64_t core_ಅಂಕೆ_u64_rotate_ಎಡ(uint64_t x0, uint32_t x1);

ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_array_u8x8 core_ಅಂಕೆ_u64_ಗಮ್ಯ_le_ಬೈಟುಗಳು(uint64_t x0);

ಸ್ಥಿರ ಸಾಲೊಳಗೆ uint32_t core_ಅಂಕೆ_u8_ಎಣಿಕೆ_ones(uint8_t x0);

ಸ್ಥಿರ ಸಾಲೊಳಗೆ uint8_t core_ಅಂಕೆ_u8_wrapping_sub(uint8_t x0, uint8_t x1);

ಸ್ಥಿರ ಸಾಲೊಳಗೆ uint8_t
core_ops_ಬಿಟ್_core_ops_ಬಿಟ್_ಬಿಟ್_And_u8_u8_for_0_u8_bitand(ಸ್ಥಿರಾಂಕ uint8_t *x0, uint8_t x1);

ಸ್ಥಿರ ಸಾಲೊಳಗೆ uint8_t
core_ops_ಬಿಟ್_core_ops_ಬಿಟ್_Shr_i32_u8_for_0_u8_shr(ಸ್ಥಿರಾಂಕ uint8_t *x0, int32_t x1);

/**
A monomorphic instance of core.ops.range.Range
with types size_t

*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ core_ops_range_Range_87_s
{
  ಗಾತ್ರ_t ಆರಂಭ;
  ಗಾತ್ರ_t ಕೊನೆ;
}
core_ops_range_Range_87;

/**
A monomorphic instance of Eurydice.slice_subslice_mut
with types int16_t, core_ops_range_Range size_t, Eurydice_derefed_slice int16_t

*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_i16
Eurydice_ತುಂಡು_subslice_mut_a6(Eurydice_mut_borrow_ತುಂಡು_i16 s, core_ops_range_Range_87 r)
{
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ತುಂಡು_i16){
        .ptr = s.ptr + r.ಆರಂಭ,
        .meta = r.ಕೊನೆ - r.ಆರಂಭ
      }
    );
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $16size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_b2_s { uint8_t ದತ್ತಾಂಶ[16U]; } Eurydice_arr_b2;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_b2
with const generics
- $256size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_87_s { Eurydice_arr_b2 ದತ್ತಾಂಶ[256U]; } Eurydice_arr_87;

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $24size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_94_s { uint8_t ದತ್ತಾಂಶ[24U]; } Eurydice_arr_94;

#ವ್ಯಾಖ್ಯಾನಿಸು core_ಫಲಿತಾಂಶ_Ok 0
#ವ್ಯಾಖ್ಯಾನಿಸು core_ಫಲಿತಾಂಶ_Err 1

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ uint8_t core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_57_ಟ್ಯಾಗುಗಳು;

/**
A monomorphic instance of core.result.Result
with types Eurydice_arr_94, core_array_TryFromSliceError

*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_57_s
{
  core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_57_ಟ್ಯಾಗುಗಳು ಟ್ಯಾಗ್;
  ಒಕ್ಕೂಟ {
    Eurydice_arr_94 case_Ok;
    core_array_Try_From_ತುಂಡು_Error case_Err;
  }
  val;
}
core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_57;

/**
This function found in impl {core::result::Result<T, E>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of core.result.unwrap_26
with types Eurydice_arr uint8_t[[$24size_t]], core_array_TryFromSliceError

*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_94 core_ಫಲಿತಾಂಶ_unwrap_26_78(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_57 self)
{
  ಆದರೆ (self.ಟ್ಯಾಗ್ == core_ಫಲಿತಾಂಶ_Ok)
  {
    ಹಿಂತಿರುಗಿ self.val.case_Ok;
  }
  ಇಲ್ಲದಿದ್ದರೆ
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
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_d6_s { int16_t ದತ್ತಾಂಶ[16U]; } Eurydice_arr_d6;

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $20size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_fc_s { uint8_t ದತ್ತಾಂಶ[20U]; } Eurydice_arr_fc;

/**
A monomorphic instance of core.result.Result
with types Eurydice_arr_fc, core_array_TryFromSliceError

*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_83_s
{
  core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_57_ಟ್ಯಾಗುಗಳು ಟ್ಯಾಗ್;
  ಒಕ್ಕೂಟ {
    Eurydice_arr_fc case_Ok;
    core_array_Try_From_ತುಂಡು_Error case_Err;
  }
  val;
}
core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_83;

/**
This function found in impl {core::result::Result<T, E>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of core.result.unwrap_26
with types Eurydice_arr uint8_t[[$20size_t]], core_array_TryFromSliceError

*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_fc core_ಫಲಿತಾಂಶ_unwrap_26_7d(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_83 self)
{
  ಆದರೆ (self.ಟ್ಯಾಗ್ == core_ಫಲಿತಾಂಶ_Ok)
  {
    ಹಿಂತಿರುಗಿ self.val.case_Ok;
  }
  ಇಲ್ಲದಿದ್ದರೆ
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
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_5f_s { uint8_t ದತ್ತಾಂಶ[1184U]; } Eurydice_arr_5f;

/**
A monomorphic instance of Eurydice.array_to_subslice_from_shared
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1184
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_subslice_from_shared_5f2(ಸ್ಥಿರಾಂಕ Eurydice_arr_5f *a, ಗಾತ್ರ_t r)
{
  ಹಿಂತಿರುಗಿ
    (KRML_CLITERAL(Eurydice_borrow_ತುಂಡು_u8){ .ptr = a->ದತ್ತಾಂಶ + r, .meta = (ಗಾತ್ರ_t)1184U - r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_to_shared
with types uint8_t, core_ops_range_RangeTo size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1184
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_subslice_ಗಮ್ಯ_shared_210(ಸ್ಥಿರಾಂಕ Eurydice_arr_5f *a, ಗಾತ್ರ_t r)
{
  Eurydice_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = r;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $2400size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_7d_s { uint8_t ದತ್ತಾಂಶ[2400U]; } Eurydice_arr_7d;

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 2400
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_subslice_shared_d48(ಸ್ಥಿರಾಂಕ Eurydice_arr_7d *a, core_ops_range_Range_87 r)
{
  ಹಿಂತಿರುಗಿ
    (KRML_CLITERAL(Eurydice_borrow_ತುಂಡು_u8){ .ptr = a->ದತ್ತಾಂಶ + r.ಆರಂಭ, .meta = r.ಕೊನೆ - r.ಆರಂಭ });
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $1152size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_0e_s { uint8_t ದತ್ತಾಂಶ[1152U]; } Eurydice_arr_0e;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 1152
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_f4(ಸ್ಥಿರಾಂಕ Eurydice_arr_0e *a)
{
  Eurydice_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)1152U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 2400
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_subslice_mut_d417(Eurydice_arr_7d *a, core_ops_range_Range_87 r)
{
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ತುಂಡು_u8){
        .ptr = a->ದತ್ತಾಂಶ + r.ಆರಂಭ,
        .meta = r.ಕೊನೆ - r.ಆರಂಭ
      }
    );
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 1152
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8 Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_f4(Eurydice_arr_0e *a)
{
  Eurydice_mut_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)1152U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_from_mut
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1184
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_subslice_from_mut_5f4(Eurydice_arr_5f *a, ಗಾತ್ರ_t r)
{
  ಹಿಂತಿರುಗಿ
    (KRML_CLITERAL(Eurydice_mut_borrow_ತುಂಡು_u8){ .ptr = a->ದತ್ತಾಂಶ + r, .meta = (ಗಾತ್ರ_t)1184U - r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1184
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_subslice_mut_d416(Eurydice_arr_5f *a, core_ops_range_Range_87 r)
{
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ತುಂಡು_u8){
        .ptr = a->ದತ್ತಾಂಶ + r.ಆರಂಭ,
        .meta = r.ಕೊನೆ - r.ಆರಂಭ
      }
    );
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 24
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_ed(ಸ್ಥಿರಾಂಕ Eurydice_arr_94 *a)
{
  Eurydice_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)24U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $384size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_b20_s { uint8_t ದತ್ತಾಂಶ[384U]; } Eurydice_arr_b20;

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 384
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_subslice_mut_d415(Eurydice_arr_b20 *a, core_ops_range_Range_87 r)
{
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ತುಂಡು_u8){
        .ptr = a->ದತ್ತಾಂಶ + r.ಆರಂಭ,
        .meta = r.ಕೊನೆ - r.ಆರಂಭ
      }
    );
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 384
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_a9(ಸ್ಥಿರಾಂಕ Eurydice_arr_b20 *a)
{
  Eurydice_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)384U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $32size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_ec_s { uint8_t ದತ್ತಾಂಶ[32U]; } Eurydice_arr_ec;

/**
A monomorphic instance of core.result.Result
with types Eurydice_arr_ec, core_array_TryFromSliceError

*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_07_s
{
  core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_57_ಟ್ಯಾಗುಗಳು ಟ್ಯಾಗ್;
  ಒಕ್ಕೂಟ {
    Eurydice_arr_ec case_Ok;
    core_array_Try_From_ತುಂಡು_Error case_Err;
  }
  val;
}
core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_07;

/**
This function found in impl {core::result::Result<T, E>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of core.result.unwrap_26
with types Eurydice_arr uint8_t[[$32size_t]], core_array_TryFromSliceError

*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_ec core_ಫಲಿತಾಂಶ_unwrap_26_39(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_07 self)
{
  ಆದರೆ (self.ಟ್ಯಾಗ್ == core_ಫಲಿತಾಂಶ_Ok)
  {
    ಹಿಂತಿರುಗಿ self.val.case_Ok;
  }
  ಇಲ್ಲದಿದ್ದರೆ
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
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_c7_s { uint8_t ದತ್ತಾಂಶ[64U]; } Eurydice_arr_c7;

/**
A monomorphic instance of Eurydice.array_to_subslice_from_shared
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 64
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_subslice_from_shared_5f1(ಸ್ಥಿರಾಂಕ Eurydice_arr_c7 *a, ಗಾತ್ರ_t r)
{
  ಹಿಂತಿರುಗಿ
    (KRML_CLITERAL(Eurydice_borrow_ತುಂಡು_u8){ .ptr = a->ದತ್ತಾಂಶ + r, .meta = (ಗಾತ್ರ_t)64U - r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 64
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_subslice_shared_d47(ಸ್ಥಿರಾಂಕ Eurydice_arr_c7 *a, core_ops_range_Range_87 r)
{
  ಹಿಂತಿರುಗಿ
    (KRML_CLITERAL(Eurydice_borrow_ತುಂಡು_u8){ .ptr = a->ದತ್ತಾಂಶ + r.ಆರಂಭ, .meta = r.ಕೊನೆ - r.ಆರಂಭ });
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 1184
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_ff(ಸ್ಥಿರಾಂಕ Eurydice_arr_5f *a)
{
  Eurydice_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)1184U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $1088size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_2b_s { uint8_t ದತ್ತಾಂಶ[1088U]; } Eurydice_arr_2b;

/**
A monomorphic instance of Eurydice.array_to_subslice_from_mut
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1088
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_subslice_from_mut_5f3(Eurydice_arr_2b *a, ಗಾತ್ರ_t r)
{
  ಹಿಂತಿರುಗಿ
    (KRML_CLITERAL(Eurydice_mut_borrow_ತುಂಡು_u8){ .ptr = a->ದತ್ತಾಂಶ + r, .meta = (ಗಾತ್ರ_t)1088U - r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1088
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_subslice_mut_d414(Eurydice_arr_2b *a, core_ops_range_Range_87 r)
{
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ತುಂಡು_u8){
        .ptr = a->ದತ್ತಾಂಶ + r.ಆರಂಭ,
        .meta = r.ಕೊನೆ - r.ಆರಂಭ
      }
    );
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 20
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_8f(ಸ್ಥಿರಾಂಕ Eurydice_arr_fc *a)
{
  Eurydice_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)20U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $320size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_b0_s { uint8_t ದತ್ತಾಂಶ[320U]; } Eurydice_arr_b0;

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 320
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_subslice_mut_d413(Eurydice_arr_b0 *a, core_ops_range_Range_87 r)
{
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ತುಂಡು_u8){
        .ptr = a->ದತ್ತಾಂಶ + r.ಆರಂಭ,
        .meta = r.ಕೊನೆ - r.ಆರಂಭ
      }
    );
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 320
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_56(ಸ್ಥಿರಾಂಕ Eurydice_arr_b0 *a)
{
  Eurydice_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)320U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.arr
with types int16_t
with const generics
- $256size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_04_s { int16_t ದತ್ತಾಂಶ[256U]; } Eurydice_arr_04;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types int16_t
with const generics
- N= 256
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_i16
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_99(ಸ್ಥಿರಾಂಕ Eurydice_arr_04 *a)
{
  Eurydice_borrow_ತುಂಡು_i16 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)256U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $128size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_89_s { uint8_t ದತ್ತಾಂಶ[128U]; } Eurydice_arr_89;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_89
with const generics
- $3size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_58_s { Eurydice_arr_89 ದತ್ತಾಂಶ[3U]; } Eurydice_arr_58;

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $33size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_fa0_s { uint8_t ದತ್ತಾಂಶ[33U]; } Eurydice_arr_fa0;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 33
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_b5(ಸ್ಥಿರಾಂಕ Eurydice_arr_fa0 *a)
{
  Eurydice_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)33U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_fa0
with const generics
- $3size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_fd_s { Eurydice_arr_fa0 ದತ್ತಾಂಶ[3U]; } Eurydice_arr_fd;

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 33
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_subslice_mut_d412(Eurydice_arr_fa0 *a, core_ops_range_Range_87 r)
{
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ತುಂಡು_u8){
        .ptr = a->ದತ್ತಾಂಶ + r.ಆರಂಭ,
        .meta = r.ಕೊನೆ - r.ಆರಂಭ
      }
    );
}

/**
A monomorphic instance of Eurydice.arr
with types int16_t
with const generics
- $272size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_5b_s { int16_t ದತ್ತಾಂಶ[272U]; } Eurydice_arr_5b;

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types int16_t, core_ops_range_Range size_t, Eurydice_derefed_slice int16_t
with const generics
- N= 272
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_i16
Eurydice_array_ಗಮ್ಯ_subslice_shared_e70(ಸ್ಥಿರಾಂಕ Eurydice_arr_5b *a, core_ops_range_Range_87 r)
{
  ಹಿಂತಿರುಗಿ
    (KRML_CLITERAL(Eurydice_borrow_ತುಂಡು_i16){ .ptr = a->ದತ್ತಾಂಶ + r.ಆರಂಭ, .meta = r.ಕೊನೆ - r.ಆರಂಭ });
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $168size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_c5_s { uint8_t ದತ್ತಾಂಶ[168U]; } Eurydice_arr_c5;

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 168
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_subslice_shared_d46(ಸ್ಥಿರಾಂಕ Eurydice_arr_c5 *a, core_ops_range_Range_87 r)
{
  ಹಿಂತಿರುಗಿ
    (KRML_CLITERAL(Eurydice_borrow_ತುಂಡು_u8){ .ptr = a->ದತ್ತಾಂಶ + r.ಆರಂಭ, .meta = r.ಕೊನೆ - r.ಆರಂಭ });
}

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_c5
with const generics
- $3size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_2c_s { Eurydice_arr_c5 ದತ್ತಾಂಶ[3U]; } Eurydice_arr_2c;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_5b
with const generics
- $3size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_b1_s { Eurydice_arr_5b ದತ್ತಾಂಶ[3U]; } Eurydice_arr_b1;

/**
A monomorphic instance of Eurydice.arr
with types size_t
with const generics
- $3size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_eb_s { ಗಾತ್ರ_t ದತ್ತಾಂಶ[3U]; } Eurydice_arr_eb;

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types int16_t, core_ops_range_Range size_t, Eurydice_derefed_slice int16_t
with const generics
- N= 272
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_i16
Eurydice_array_ಗಮ್ಯ_subslice_mut_e7(Eurydice_arr_5b *a, core_ops_range_Range_87 r)
{
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ತುಂಡು_i16){
        .ptr = a->ದತ್ತಾಂಶ + r.ಆರಂಭ,
        .meta = r.ಕೊನೆ - r.ಆರಂಭ
      }
    );
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $504size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_79_s { uint8_t ದತ್ತಾಂಶ[504U]; } Eurydice_arr_79;

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 504
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_subslice_shared_d45(ಸ್ಥಿರಾಂಕ Eurydice_arr_79 *a, core_ops_range_Range_87 r)
{
  ಹಿಂತಿರುಗಿ
    (KRML_CLITERAL(Eurydice_borrow_ತುಂಡು_u8){ .ptr = a->ದತ್ತಾಂಶ + r.ಆರಂಭ, .meta = r.ಕೊನೆ - r.ಆರಂಭ });
}

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_79
with const generics
- $3size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_7e_s { Eurydice_arr_79 ದತ್ತಾಂಶ[3U]; } Eurydice_arr_7e;

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 504
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8 Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_48(Eurydice_arr_79 *a)
{
  Eurydice_mut_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)504U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $34size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_31_s { uint8_t ದತ್ತಾಂಶ[34U]; } Eurydice_arr_31;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_31
with const generics
- $3size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_810_s { Eurydice_arr_31 ದತ್ತಾಂಶ[3U]; } Eurydice_arr_810;

/**
A monomorphic instance of Eurydice.slice_subslice_from_shared
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t

*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_ತುಂಡು_subslice_from_shared_6d(Eurydice_borrow_ತುಂಡು_u8 s, ಗಾತ್ರ_t r)
{
  ಹಿಂತಿರುಗಿ (KRML_CLITERAL(Eurydice_borrow_ತುಂಡು_u8){ .ptr = s.ptr + r, .meta = s.meta - r });
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $1120size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_af_s { uint8_t ದತ್ತಾಂಶ[1120U]; } Eurydice_arr_af;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 1120
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_81(ಸ್ಥಿರಾಂಕ Eurydice_arr_af *a)
{
  Eurydice_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)1120U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 1088
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_06(ಸ್ಥಿರಾಂಕ Eurydice_arr_2b *a)
{
  Eurydice_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)1088U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_from_mut
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1120
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_subslice_from_mut_5f2(Eurydice_arr_af *a, ಗಾತ್ರ_t r)
{
  ಹಿಂತಿರುಗಿ
    (KRML_CLITERAL(Eurydice_mut_borrow_ತುಂಡು_u8){ .ptr = a->ದತ್ತಾಂಶ + r, .meta = (ಗಾತ್ರ_t)1120U - r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1120
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_subslice_mut_d411(Eurydice_arr_af *a, core_ops_range_Range_87 r)
{
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ತುಂಡು_u8){
        .ptr = a->ದತ್ತಾಂಶ + r.ಆರಂಭ,
        .meta = r.ಕೊನೆ - r.ಆರಂಭ
      }
    );
}

/**
A monomorphic instance of Eurydice.array_to_subslice_from_mut
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 64
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_subslice_from_mut_5f1(Eurydice_arr_c7 *a, ಗಾತ್ರ_t r)
{
  ಹಿಂತಿರುಗಿ
    (KRML_CLITERAL(Eurydice_mut_borrow_ತುಂಡು_u8){ .ptr = a->ದತ್ತಾಂಶ + r, .meta = (ಗಾತ್ರ_t)64U - r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 64
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_subslice_mut_d410(Eurydice_arr_c7 *a, core_ops_range_Range_87 r)
{
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ತುಂಡು_u8){
        .ptr = a->ದತ್ತಾಂಶ + r.ಆರಂಭ,
        .meta = r.ಕೊನೆ - r.ಆರಂಭ
      }
    );
}

/**
A monomorphic instance of Eurydice.array_to_subslice_from_shared
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1088
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_subslice_from_shared_5f0(ಸ್ಥಿರಾಂಕ Eurydice_arr_2b *a, ಗಾತ್ರ_t r)
{
  ಹಿಂತಿರುಗಿ
    (KRML_CLITERAL(Eurydice_borrow_ತುಂಡು_u8){ .ptr = a->ದತ್ತಾಂಶ + r, .meta = (ಗಾತ್ರ_t)1088U - r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 1088
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_subslice_shared_d44(ಸ್ಥಿರಾಂಕ Eurydice_arr_2b *a, core_ops_range_Range_87 r)
{
  ಹಿಂತಿರುಗಿ
    (KRML_CLITERAL(Eurydice_borrow_ತುಂಡು_u8){ .ptr = a->ದತ್ತಾಂಶ + r.ಆರಂಭ, .meta = r.ಕೊನೆ - r.ಆರಂಭ });
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 2400
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_51(ಸ್ಥಿರಾಂಕ Eurydice_arr_7d *a)
{
  Eurydice_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)2400U;
  ಹಿಂತಿರುಗಿ lit;
}

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ int16_t_x2_s
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
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_94
libcrux_secrets_int_ಬಹಿರಂಗ_integers_declassify_d8_40(Eurydice_arr_94 self)
{
  ಹಿಂತಿರುಗಿ self;
}

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ uint8_t_x3_s
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
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_fc
libcrux_secrets_int_ಬಹಿರಂಗ_integers_declassify_d8_2b(Eurydice_arr_fc self)
{
  ಹಿಂತಿರುಗಿ self;
}

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ uint8_t_x5_s
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
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_array_u8x8
libcrux_secrets_int_ಬಹಿರಂಗ_integers_declassify_d8_52(Eurydice_array_u8x8 self)
{
  ಹಿಂತಿರುಗಿ self;
}

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ uint8_t_x4_s
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
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_array_u8x2
libcrux_secrets_int_ಬಹಿರಂಗ_integers_declassify_d8_75(Eurydice_array_u8x2 self)
{
  ಹಿಂತಿರುಗಿ self;
}

/**
This function found in impl {libcrux_secrets::traits::Classify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.classify_27
with types Eurydice_arr int16_t[[$16size_t]]

*/
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_d6
libcrux_secrets_int_ಬಹಿರಂಗ_integers_classify_27_4b(Eurydice_arr_d6 self)
{
  ಹಿಂತಿರುಗಿ self;
}

/**
This function found in impl {libcrux_secrets::traits::ClassifyRef<&'a ([T])> for &'a ([T])}
*/
/**
A monomorphic instance of libcrux_secrets.int.classify_public.classify_ref_6d
with types uint8_t

*/
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_borrow_ತುಂಡು_u8
libcrux_secrets_int_classify_ಬಹಿರಂಗ_classify_ref_6d_90(Eurydice_borrow_ತುಂಡು_u8 self)
{
  ಹಿಂತಿರುಗಿ self;
}

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ int16_t_x8_s
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_i16
Eurydice_array_ಗಮ್ಯ_subslice_shared_e7(ಸ್ಥಿರಾಂಕ Eurydice_arr_d6 *a, core_ops_range_Range_87 r)
{
  ಹಿಂತಿರುಗಿ
    (KRML_CLITERAL(Eurydice_borrow_ತುಂಡು_i16){ .ptr = a->ದತ್ತಾಂಶ + r.ಆರಂಭ, .meta = r.ಕೊನೆ - r.ಆರಂಭ });
}

/**
This function found in impl {libcrux_secrets::traits::ClassifyRef<&'a ([T])> for &'a ([T])}
*/
/**
A monomorphic instance of libcrux_secrets.int.classify_public.classify_ref_6d
with types int16_t

*/
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_borrow_ತುಂಡು_i16
libcrux_secrets_int_classify_ಬಹಿರಂಗ_classify_ref_6d_39(Eurydice_borrow_ತುಂಡು_i16 self)
{
  ಹಿಂತಿರುಗಿ self;
}

/**
A monomorphic instance of Eurydice.slice_subslice_shared
with types int16_t, core_ops_range_Range size_t, Eurydice_derefed_slice int16_t

*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_i16
Eurydice_ತುಂಡು_subslice_shared_a6(Eurydice_borrow_ತುಂಡು_i16 s, core_ops_range_Range_87 r)
{
  ಹಿಂತಿರುಗಿ
    (KRML_CLITERAL(Eurydice_borrow_ತುಂಡು_i16){ .ptr = s.ptr + r.ಆರಂಭ, .meta = r.ಕೊನೆ - r.ಆರಂಭ });
}

/**
A monomorphic instance of core.result.Result
with types Eurydice_arr_d6, core_array_TryFromSliceError

*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_ec_s
{
  core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_57_ಟ್ಯಾಗುಗಳು ಟ್ಯಾಗ್;
  ಒಕ್ಕೂಟ {
    Eurydice_arr_d6 case_Ok;
    core_array_Try_From_ತುಂಡು_Error case_Err;
  }
  val;
}
core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_ec;

/**
This function found in impl {core::result::Result<T, E>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of core.result.unwrap_26
with types Eurydice_arr int16_t[[$16size_t]], core_array_TryFromSliceError

*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_d6 core_ಫಲಿತಾಂಶ_unwrap_26_d3(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_ec self)
{
  ಆದರೆ (self.ಟ್ಯಾಗ್ == core_ಫಲಿತಾಂಶ_Ok)
  {
    ಹಿಂತಿರುಗಿ self.val.case_Ok;
  }
  ಇಲ್ಲದಿದ್ದರೆ
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
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_34_s { int16_t ದತ್ತಾಂಶ[128U]; } Eurydice_arr_34;

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 24
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_subslice_shared_d43(ಸ್ಥಿರಾಂಕ Eurydice_arr_94 *a, core_ops_range_Range_87 r)
{
  ಹಿಂತಿರುಗಿ
    (KRML_CLITERAL(Eurydice_borrow_ತುಂಡು_u8){ .ptr = a->ದತ್ತಾಂಶ + r.ಆರಂಭ, .meta = r.ಕೊನೆ - r.ಆರಂಭ });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 24
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_subslice_mut_d49(Eurydice_arr_94 *a, core_ops_range_Range_87 r)
{
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ತುಂಡು_u8){
        .ptr = a->ದತ್ತಾಂಶ + r.ಆರಂಭ,
        .meta = r.ಕೊನೆ - r.ಆರಂಭ
      }
    );
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 16
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8 Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_29(Eurydice_arr_b2 *a)
{
  Eurydice_mut_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)16U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 16
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_subslice_shared_d42(ಸ್ಥಿರಾಂಕ Eurydice_arr_b2 *a, core_ops_range_Range_87 r)
{
  ಹಿಂತಿರುಗಿ
    (KRML_CLITERAL(Eurydice_borrow_ತುಂಡು_u8){ .ptr = a->ದತ್ತಾಂಶ + r.ಆರಂಭ, .meta = r.ಕೊನೆ - r.ಆರಂಭ });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 16
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_subslice_mut_d48(Eurydice_arr_b2 *a, core_ops_range_Range_87 r)
{
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ತುಂಡು_u8){
        .ptr = a->ದತ್ತಾಂಶ + r.ಆರಂಭ,
        .meta = r.ಕೊನೆ - r.ಆರಂಭ
      }
    );
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $19size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_38_s { uint8_t ದತ್ತಾಂಶ[19U]; } Eurydice_arr_38;

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 19
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_subslice_shared_d41(ಸ್ಥಿರಾಂಕ Eurydice_arr_38 *a, core_ops_range_Range_87 r)
{
  ಹಿಂತಿರುಗಿ
    (KRML_CLITERAL(Eurydice_borrow_ತುಂಡು_u8){ .ptr = a->ದತ್ತಾಂಶ + r.ಆರಂಭ, .meta = r.ಕೊನೆ - r.ಆರಂಭ });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 19
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_subslice_mut_d47(Eurydice_arr_38 *a, core_ops_range_Range_87 r)
{
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ತುಂಡು_u8){
        .ptr = a->ದತ್ತಾಂಶ + r.ಆರಂಭ,
        .meta = r.ಕೊನೆ - r.ಆರಂಭ
      }
    );
}

/**
A monomorphic instance of Eurydice.dst_ref_mut
with types int32_t, size_t

*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_dst_ref_mut_83_s
{
  int32_t *ptr;
  ಗಾತ್ರ_t meta;
}
Eurydice_dst_ref_mut_83;

/**
A monomorphic instance of Eurydice.slice_subslice_mut
with types int32_t, core_ops_range_Range size_t, Eurydice_derefed_slice int32_t

*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_dst_ref_mut_83
Eurydice_ತುಂಡು_subslice_mut_47(Eurydice_dst_ref_mut_83 s, core_ops_range_Range_87 r)
{
  ಹಿಂತಿರುಗಿ
    (KRML_CLITERAL(Eurydice_dst_ref_mut_83){ .ptr = s.ptr + r.ಆರಂಭ, .meta = r.ಕೊನೆ - r.ಆರಂಭ });
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 16
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_29(ಸ್ಥಿರಾಂಕ Eurydice_arr_b2 *a)
{
  Eurydice_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)16U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_b2
with const generics
- $16size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_a30_s { Eurydice_arr_b2 ದತ್ತಾಂಶ[16U]; } Eurydice_arr_a30;

/**
A monomorphic instance of Eurydice.array_to_subslice_to_mut
with types uint8_t, core_ops_range_RangeTo size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 32
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_subslice_ಗಮ್ಯ_mut_21(Eurydice_arr_ec *a, ಗಾತ್ರ_t r)
{
  Eurydice_mut_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = r;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $4627size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_93_s { uint8_t ದತ್ತಾಂಶ[4627U]; } Eurydice_arr_93;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 4627
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_11(ಸ್ಥಿರಾಂಕ Eurydice_arr_93 *a)
{
  Eurydice_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)4627U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $2592size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_43_s { uint8_t ದತ್ತಾಂಶ[2592U]; } Eurydice_arr_43;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 2592
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_fc(ಸ್ಥಿರಾಂಕ Eurydice_arr_43 *a)
{
  Eurydice_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)2592U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $4896size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_e2_s { uint8_t ದತ್ತಾಂಶ[4896U]; } Eurydice_arr_e2;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 4896
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_f7(ಸ್ಥಿರಾಂಕ Eurydice_arr_e2 *a)
{
  Eurydice_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)4896U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.arr
with types int32_t
with const generics
- $256size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_6c_s { int32_t ದತ್ತಾಂಶ[256U]; } Eurydice_arr_6c;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_6c
with const generics
- $8size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_81_s { Eurydice_arr_6c ದತ್ತಾಂಶ[8U]; } Eurydice_arr_81;

#ವ್ಯಾಖ್ಯಾನಿಸು core_option_None 0
#ವ್ಯಾಖ್ಯಾನಿಸು core_option_Some 1

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ uint8_t core_option_Option_45_ಟ್ಯಾಗುಗಳು;

/**
A monomorphic instance of core.option.Option
with types Eurydice_arr_81

*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ core_option_Option_45_s
{
  core_option_Option_45_ಟ್ಯಾಗುಗಳು ಟ್ಯಾಗ್;
  Eurydice_arr_81 f0;
}
core_option_Option_45;

/**
A monomorphic instance of core.option.Option
with types Eurydice_arr_c7

*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ core_option_Option_b2_s
{
  core_option_Option_45_ಟ್ಯಾಗುಗಳು ಟ್ಯಾಗ್;
  Eurydice_arr_c7 f0;
}
core_option_Option_b2;

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 4627
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8 Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_11(Eurydice_arr_93 *a)
{
  Eurydice_mut_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)4627U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.dst_ref_shared
with types Eurydice_arr_6c, size_t

*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_dst_ref_shared_20_s
{
  ಸ್ಥಿರಾಂಕ Eurydice_arr_6c *ptr;
  ಗಾತ್ರ_t meta;
}
Eurydice_dst_ref_shared_20;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types Eurydice_arr int32_t[[$256size_t]]
with const generics
- N= 8
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_dst_ref_shared_20
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_861(ಸ್ಥಿರಾಂಕ Eurydice_arr_81 *a)
{
  Eurydice_dst_ref_shared_20 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)8U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.dst_ref_mut
with types Eurydice_arr_6c, size_t

*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_dst_ref_mut_20_s
{
  Eurydice_arr_6c *ptr;
  ಗಾತ್ರ_t meta;
}
Eurydice_dst_ref_mut_20;

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types Eurydice_arr int32_t[[$256size_t]]
with const generics
- N= 8
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_dst_ref_mut_20 Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_861(Eurydice_arr_81 *a)
{
  Eurydice_dst_ref_mut_20 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)8U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
 Declassify secret memory.

 No-op if `valgrind_ct_test` cfg is not enabled.
*/
/**
A monomorphic instance of libcrux_secrets.mem_requests.ct_declassify
with types Eurydice_arr uint8_t[[$64size_t]]

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_secrets_mem_ವಿನಂತಿಗಳು_ct_declassify_56(ಸ್ಥಿರಾಂಕ Eurydice_arr_c7 *val)
{

}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $1024size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_1b_s { uint8_t ದತ್ತಾಂಶ[1024U]; } Eurydice_arr_1b;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 1024
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_68(ಸ್ಥಿರಾಂಕ Eurydice_arr_1b *a)
{
  Eurydice_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)1024U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 1024
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8 Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_68(Eurydice_arr_1b *a)
{
  Eurydice_mut_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)1024U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 2592
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8 Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_fc(Eurydice_arr_43 *a)
{
  Eurydice_mut_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)2592U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 4896
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8 Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_f7(Eurydice_arr_e2 *a)
{
  Eurydice_mut_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)4896U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $3309size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_0c_s { uint8_t ದತ್ತಾಂಶ[3309U]; } Eurydice_arr_0c;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 3309
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_6b(ಸ್ಥಿರಾಂಕ Eurydice_arr_0c *a)
{
  Eurydice_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)3309U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $1952size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_29_s { uint8_t ದತ್ತಾಂಶ[1952U]; } Eurydice_arr_29;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 1952
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_37(ಸ್ಥಿರಾಂಕ Eurydice_arr_29 *a)
{
  Eurydice_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)1952U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $4032size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_24_s { uint8_t ದತ್ತಾಂಶ[4032U]; } Eurydice_arr_24;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 4032
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_98(ಸ್ಥಿರಾಂಕ Eurydice_arr_24 *a)
{
  Eurydice_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)4032U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_6c
with const generics
- $6size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_5d0_s { Eurydice_arr_6c ದತ್ತಾಂಶ[6U]; } Eurydice_arr_5d0;

/**
A monomorphic instance of core.option.Option
with types Eurydice_arr_5d0

*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ core_option_Option_05_s
{
  core_option_Option_45_ಟ್ಯಾಗುಗಳು ಟ್ಯಾಗ್;
  Eurydice_arr_5d0 f0;
}
core_option_Option_05;

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $48size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_65_s { uint8_t ದತ್ತಾಂಶ[48U]; } Eurydice_arr_65;

/**
A monomorphic instance of core.option.Option
with types Eurydice_arr_65

*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ core_option_Option_81_s
{
  core_option_Option_45_ಟ್ಯಾಗುಗಳು ಟ್ಯಾಗ್;
  Eurydice_arr_65 f0;
}
core_option_Option_81;

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 3309
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8 Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_6b(Eurydice_arr_0c *a)
{
  Eurydice_mut_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)3309U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types Eurydice_arr int32_t[[$256size_t]]
with const generics
- N= 6
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_dst_ref_shared_20
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_860(ಸ್ಥಿರಾಂಕ Eurydice_arr_5d0 *a)
{
  Eurydice_dst_ref_shared_20 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)6U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types Eurydice_arr int32_t[[$256size_t]]
with const generics
- N= 6
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_dst_ref_mut_20 Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_860(Eurydice_arr_5d0 *a)
{
  Eurydice_dst_ref_mut_20 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)6U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 48
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_9f0(ಸ್ಥಿರಾಂಕ Eurydice_arr_65 *a)
{
  Eurydice_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)48U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
 Declassify secret memory.

 No-op if `valgrind_ct_test` cfg is not enabled.
*/
/**
A monomorphic instance of libcrux_secrets.mem_requests.ct_declassify
with types Eurydice_arr uint8_t[[$48size_t]]

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_secrets_mem_ವಿನಂತಿಗಳು_ct_declassify_69(ಸ್ಥಿರಾಂಕ Eurydice_arr_65 *val)
{

}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 1952
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8 Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_37(Eurydice_arr_29 *a)
{
  Eurydice_mut_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)1952U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 4032
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8 Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_98(Eurydice_arr_24 *a)
{
  Eurydice_mut_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)4032U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $2420size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_85_s { uint8_t ದತ್ತಾಂಶ[2420U]; } Eurydice_arr_85;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 2420
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_0d(ಸ್ಥಿರಾಂಕ Eurydice_arr_85 *a)
{
  Eurydice_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)2420U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $1312size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_02_s { uint8_t ದತ್ತಾಂಶ[1312U]; } Eurydice_arr_02;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 1312
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_9f(ಸ್ಥಿರಾಂಕ Eurydice_arr_02 *a)
{
  Eurydice_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)1312U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $2560size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_10_s { uint8_t ದತ್ತಾಂಶ[2560U]; } Eurydice_arr_10;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 2560
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_34(ಸ್ಥಿರಾಂಕ Eurydice_arr_10 *a)
{
  Eurydice_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)2560U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_6c
with const generics
- $4size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_b7_s { Eurydice_arr_6c ದತ್ತಾಂಶ[4U]; } Eurydice_arr_b7;

/**
A monomorphic instance of core.option.Option
with types Eurydice_arr_b7

*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ core_option_Option_51_s
{
  core_option_Option_45_ಟ್ಯಾಗುಗಳು ಟ್ಯಾಗ್;
  Eurydice_arr_b7 f0;
}
core_option_Option_51;

/**
A monomorphic instance of core.option.Option
with types Eurydice_arr_ec

*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ core_option_Option_14_s
{
  core_option_Option_45_ಟ್ಯಾಗುಗಳು ಟ್ಯಾಗ್;
  Eurydice_arr_ec f0;
}
core_option_Option_14;

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 2420
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8 Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_0d(Eurydice_arr_85 *a)
{
  Eurydice_mut_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)2420U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types Eurydice_arr int32_t[[$256size_t]]
with const generics
- N= 4
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_dst_ref_shared_20
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_86(ಸ್ಥಿರಾಂಕ Eurydice_arr_b7 *a)
{
  Eurydice_dst_ref_shared_20 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)4U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types Eurydice_arr int32_t[[$256size_t]]
with const generics
- N= 4
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_dst_ref_mut_20 Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_86(Eurydice_arr_b7 *a)
{
  Eurydice_dst_ref_mut_20 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)4U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types int32_t, core_ops_range_Range size_t, Eurydice_derefed_slice int32_t
with const generics
- N= 256
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_dst_ref_mut_83
Eurydice_array_ಗಮ್ಯ_subslice_mut_44(Eurydice_arr_6c *a, core_ops_range_Range_87 r)
{
  ಹಿಂತಿರುಗಿ
    (KRML_CLITERAL(Eurydice_dst_ref_mut_83){ .ptr = a->ದತ್ತಾಂಶ + r.ಆರಂಭ, .meta = r.ಕೊನೆ - r.ಆರಂಭ });
}

/**
A monomorphic instance of Eurydice.dst_ref_shared
with types int32_t, size_t

*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_dst_ref_shared_83_s
{
  ಸ್ಥಿರಾಂಕ int32_t *ptr;
  ಗಾತ್ರ_t meta;
}
Eurydice_dst_ref_shared_83;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types int32_t
with const generics
- N= 256
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_dst_ref_shared_83
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_af(ಸ್ಥಿರಾಂಕ Eurydice_arr_6c *a)
{
  Eurydice_dst_ref_shared_83 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)256U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $136size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_ff_s { uint8_t ದತ್ತಾಂಶ[136U]; } Eurydice_arr_ff;

/**
A monomorphic instance of Eurydice.array_to_subslice_from_shared
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 136
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_subslice_from_shared_5f(ಸ್ಥಿರಾಂಕ Eurydice_arr_ff *a, ಗಾತ್ರ_t r)
{
  ಹಿಂತಿರುಗಿ
    (KRML_CLITERAL(Eurydice_borrow_ತುಂಡು_u8){ .ptr = a->ದತ್ತಾಂಶ + r, .meta = (ಗಾತ್ರ_t)136U - r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 136
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_subslice_shared_d40(ಸ್ಥಿರಾಂಕ Eurydice_arr_ff *a, core_ops_range_Range_87 r)
{
  ಹಿಂತಿರುಗಿ
    (KRML_CLITERAL(Eurydice_borrow_ತುಂಡು_u8){ .ptr = a->ದತ್ತಾಂಶ + r.ಆರಂಭ, .meta = r.ಕೊನೆ - r.ಆರಂಭ });
}

/**
 Declassify secret memory.

 No-op if `valgrind_ct_test` cfg is not enabled.
*/
/**
A monomorphic instance of libcrux_secrets.mem_requests.ct_declassify
with types Eurydice_arr uint8_t[[$32size_t]]

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_secrets_mem_ವಿನಂತಿಗಳು_ct_declassify_4b(ಸ್ಥಿರಾಂಕ Eurydice_arr_ec *val)
{

}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $768size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_d2_s { uint8_t ದತ್ತಾಂಶ[768U]; } Eurydice_arr_d2;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 768
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_27(ಸ್ಥಿರಾಂಕ Eurydice_arr_d2 *a)
{
  Eurydice_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)768U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 768
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8 Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_27(Eurydice_arr_d2 *a)
{
  Eurydice_mut_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)768U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $640size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_20_s { uint8_t ದತ್ತಾಂಶ[640U]; } Eurydice_arr_20;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 640
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_4f(ಸ್ಥಿರಾಂಕ Eurydice_arr_20 *a)
{
  Eurydice_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)640U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 640
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8 Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_4f(Eurydice_arr_20 *a)
{
  Eurydice_mut_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)640U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $576size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_220_s { uint8_t ದತ್ತಾಂಶ[576U]; } Eurydice_arr_220;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 576
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_8a(ಸ್ಥಿರಾಂಕ Eurydice_arr_220 *a)
{
  Eurydice_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)576U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 576
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8 Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_8a(Eurydice_arr_220 *a)
{
  Eurydice_mut_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)576U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $11size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_c9_s { uint8_t ದತ್ತಾಂಶ[11U]; } Eurydice_arr_c9;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 11
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_2f(ಸ್ಥಿರಾಂಕ Eurydice_arr_c9 *a)
{
  Eurydice_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)11U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $1size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_82_s { uint8_t ದತ್ತಾಂಶ[1U]; } Eurydice_arr_82;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 1
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_79(ಸ್ಥಿರಾಂಕ Eurydice_arr_82 *a)
{
  Eurydice_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)1U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
 Mark memory as secret.

 No-op if `valgrind_ct_test` cfg is not enabled.
*/
/**
A monomorphic instance of libcrux_secrets.mem_requests.ct_classify
with types Eurydice_derefed_slice uint8_t

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ libcrux_secrets_mem_ವಿನಂತಿಗಳು_ct_classify_45(ಸ್ಥಿರಾಂಕ uint8_t (*val)[])
{

}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 1312
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8 Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_9f0(Eurydice_arr_02 *a)
{
  Eurydice_mut_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)1312U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 2560
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8 Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_34(Eurydice_arr_10 *a)
{
  Eurydice_mut_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)2560U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 64
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_17(ಸ್ಥಿರಾಂಕ Eurydice_arr_c7 *a)
{
  Eurydice_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)64U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.arr
with types int32_t
with const generics
- $263size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_d0_s { int32_t ದತ್ತಾಂಶ[263U]; } Eurydice_arr_d0;

/**
A monomorphic instance of Eurydice.dst_ref_mut
with types Eurydice_arr_d0, size_t

*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_dst_ref_mut_33_s
{
  Eurydice_arr_d0 *ptr;
  ಗಾತ್ರ_t meta;
}
Eurydice_dst_ref_mut_33;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_d0
with const generics
- $4size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_930_s { Eurydice_arr_d0 ದತ್ತಾಂಶ[4U]; } Eurydice_arr_930;

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types Eurydice_arr int32_t[[$263size_t]]
with const generics
- N= 4
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_dst_ref_mut_33 Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_7e(Eurydice_arr_930 *a)
{
  Eurydice_dst_ref_mut_33 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)4U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.dst_ref_shared
with types Eurydice_arr_d0, size_t

*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_dst_ref_shared_33_s
{
  ಸ್ಥಿರಾಂಕ Eurydice_arr_d0 *ptr;
  ಗಾತ್ರ_t meta;
}
Eurydice_dst_ref_shared_33;

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $840size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_d10_s { uint8_t ದತ್ತಾಂಶ[840U]; } Eurydice_arr_d10;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 840
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_4c(ಸ್ಥಿರಾಂಕ Eurydice_arr_d10 *a)
{
  Eurydice_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)840U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 34
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_e9(ಸ್ಥಿರಾಂಕ Eurydice_arr_31 *a)
{
  Eurydice_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)34U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
 Declassify secret memory.

 No-op if `valgrind_ct_test` cfg is not enabled.
*/
/**
A monomorphic instance of libcrux_secrets.mem_requests.ct_declassify
with types Eurydice_derefed_slice uint8_t

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_secrets_mem_ವಿನಂತಿಗಳು_ct_declassify_45(ಸ್ಥಿರಾಂಕ uint8_t (*val)[])
{

}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types int32_t
with const generics
- N= 263
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_dst_ref_shared_83
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_2c0(ಸ್ಥಿರಾಂಕ Eurydice_arr_d0 *a)
{
  Eurydice_dst_ref_shared_83 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)263U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_from_mut
with types int32_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice int32_t
with const generics
- N= 263
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_dst_ref_mut_83
Eurydice_array_ಗಮ್ಯ_subslice_from_mut_11(Eurydice_arr_d0 *a, ಗಾತ್ರ_t r)
{
  ಹಿಂತಿರುಗಿ
    (KRML_CLITERAL(Eurydice_dst_ref_mut_83){ .ptr = a->ದತ್ತಾಂಶ + r, .meta = (ಗಾತ್ರ_t)263U - r });
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $66size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_91_s { uint8_t ದತ್ತಾಂಶ[66U]; } Eurydice_arr_91;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 66
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_f1(ಸ್ಥಿರಾಂಕ Eurydice_arr_91 *a)
{
  Eurydice_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)66U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 128
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_78(ಸ್ಥಿರಾಂಕ Eurydice_arr_89 *a)
{
  Eurydice_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)128U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 128
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8 Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_78(Eurydice_arr_89 *a)
{
  Eurydice_mut_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)128U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 2
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_82(ಸ್ಥಿರಾಂಕ Eurydice_array_u8x2 *a)
{
  Eurydice_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)2U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 32
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_01(ಸ್ಥಿರಾಂಕ Eurydice_arr_ec *a)
{
  Eurydice_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)32U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
 Mark memory as secret.

 No-op if `valgrind_ct_test` cfg is not enabled.
*/
/**
A monomorphic instance of libcrux_secrets.mem_requests.ct_classify
with types Eurydice_arr uint8_t[[$32size_t]]

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_secrets_mem_ವಿನಂತಿಗಳು_ct_classify_4b(ಸ್ಥಿರಾಂಕ Eurydice_arr_ec *val)
{

}

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_c5_x4_s
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8 Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_2c(Eurydice_arr_c5 *a)
{
  Eurydice_mut_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)168U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 840
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8 Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_4c(Eurydice_arr_d10 *a)
{
  Eurydice_mut_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)840U;
  ಹಿಂತಿರುಗಿ lit;
}

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_ff_x4_s
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8 Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_58(Eurydice_arr_ff *a)
{
  Eurydice_mut_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)136U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 32
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_subslice_shared_d4(ಸ್ಥಿರಾಂಕ Eurydice_arr_ec *a, core_ops_range_Range_87 r)
{
  ಹಿಂತಿರುಗಿ
    (KRML_CLITERAL(Eurydice_borrow_ತುಂಡು_u8){ .ptr = a->ದತ್ತಾಂಶ + r.ಆರಂಭ, .meta = r.ಕೊನೆ - r.ಆರಂಭ });
}

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_ff
with const generics
- $4size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_dc0_s { Eurydice_arr_ff ದತ್ತಾಂಶ[4U]; } Eurydice_arr_dc0;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_c5
with const generics
- $4size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_9c_s { Eurydice_arr_c5 ದತ್ತಾಂಶ[4U]; } Eurydice_arr_9c;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_borrow_slice_u8
with const generics
- $4size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_68_s { Eurydice_borrow_ತುಂಡು_u8 ದತ್ತಾಂಶ[4U]; } Eurydice_arr_68;

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 32
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_subslice_mut_d46(Eurydice_arr_ec *a, core_ops_range_Range_87 r)
{
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ತುಂಡು_u8){
        .ptr = a->ದತ್ತಾಂಶ + r.ಆರಂಭ,
        .meta = r.ಕೊನೆ - r.ಆರಂಭ
      }
    );
}

/**
A monomorphic instance of Eurydice.array_to_subslice_from_mut
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 168
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_subslice_from_mut_5f0(Eurydice_arr_c5 *a, ಗಾತ್ರ_t r)
{
  ಹಿಂತಿರುಗಿ
    (KRML_CLITERAL(Eurydice_mut_borrow_ತುಂಡು_u8){ .ptr = a->ದತ್ತಾಂಶ + r, .meta = (ಗಾತ್ರ_t)168U - r });
}

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_c5
with const generics
- $1size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_88_s { Eurydice_arr_c5 ದತ್ತಾಂಶ[1U]; } Eurydice_arr_88;

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 64
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8 Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_17(Eurydice_arr_c7 *a)
{
  Eurydice_mut_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)64U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 48
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8 Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_9f(Eurydice_arr_65 *a)
{
  Eurydice_mut_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)48U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 32
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8 Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_01(Eurydice_arr_ec *a)
{
  Eurydice_mut_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)32U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $28size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_a2_s { uint8_t ದತ್ತಾಂಶ[28U]; } Eurydice_arr_a2;

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types uint8_t
with const generics
- N= 28
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8 Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_5e(Eurydice_arr_a2 *a)
{
  Eurydice_mut_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)28U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $104size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_c4_s { uint8_t ದತ್ತಾಂಶ[104U]; } Eurydice_arr_c4;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 104
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_72(ಸ್ಥಿರಾಂಕ Eurydice_arr_c4 *a)
{
  Eurydice_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)104U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 104
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_subslice_mut_d45(Eurydice_arr_c4 *a, core_ops_range_Range_87 r)
{
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ತುಂಡು_u8){
        .ptr = a->ದತ್ತಾಂಶ + r.ಆರಂಭ,
        .meta = r.ಕೊನೆ - r.ಆರಂಭ
      }
    );
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $144size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_f4_s { uint8_t ದತ್ತಾಂಶ[144U]; } Eurydice_arr_f4;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 144
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_38(ಸ್ಥಿರಾಂಕ Eurydice_arr_f4 *a)
{
  Eurydice_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)144U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 144
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_subslice_mut_d44(Eurydice_arr_f4 *a, core_ops_range_Range_87 r)
{
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ತುಂಡು_u8){
        .ptr = a->ದತ್ತಾಂಶ + r.ಆರಂಭ,
        .meta = r.ಕೊನೆ - r.ಆರಂಭ
      }
    );
}

/**
A monomorphic instance of Eurydice.arr
with types uint8_t
with const generics
- $72size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_ab_s { uint8_t ದತ್ತಾಂಶ[72U]; } Eurydice_arr_ab;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 72
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_e2(ಸ್ಥಿರಾಂಕ Eurydice_arr_ab *a)
{
  Eurydice_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)72U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 72
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_subslice_mut_d43(Eurydice_arr_ab *a, core_ops_range_Range_87 r)
{
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ತುಂಡು_u8){
        .ptr = a->ದತ್ತಾಂಶ + r.ಆರಂಭ,
        .meta = r.ಕೊನೆ - r.ಆರಂಭ
      }
    );
}

/**
A monomorphic instance of Eurydice.slice_subslice_to_shared
with types uint8_t, core_ops_range_RangeTo size_t, Eurydice_derefed_slice uint8_t

*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_ತುಂಡು_subslice_ಗಮ್ಯ_shared_72(Eurydice_borrow_ತುಂಡು_u8 s, ಗಾತ್ರ_t r)
{
  ಹಿಂತಿರುಗಿ (KRML_CLITERAL(Eurydice_borrow_ತುಂಡು_u8){ .ptr = s.ptr, .meta = r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_from_mut
with types uint8_t, core_ops_range_RangeFrom size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 136
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_subslice_from_mut_5f(Eurydice_arr_ff *a, ಗಾತ್ರ_t r)
{
  ಹಿಂತಿರುಗಿ
    (KRML_CLITERAL(Eurydice_mut_borrow_ತುಂಡು_u8){ .ptr = a->ದತ್ತಾಂಶ + r, .meta = (ಗಾತ್ರ_t)136U - r });
}

/**
A monomorphic instance of Eurydice.array_to_subslice_to_shared
with types uint8_t, core_ops_range_RangeTo size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 8
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_subslice_ಗಮ್ಯ_shared_21(ಸ್ಥಿರಾಂಕ Eurydice_array_u8x8 *a, ಗಾತ್ರ_t r)
{
  Eurydice_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = r;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 8
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_6e(ಸ್ಥಿರಾಂಕ Eurydice_array_u8x8 *a)
{
  Eurydice_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)8U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.slice_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t

*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8
Eurydice_ತುಂಡು_subslice_mut_c8(Eurydice_mut_borrow_ತುಂಡು_u8 s, core_ops_range_Range_87 r)
{
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ತುಂಡು_u8){ .ptr = s.ptr + r.ಆರಂಭ, .meta = r.ಕೊನೆ - r.ಆರಂಭ }
    );
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 136
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_58(ಸ್ಥಿರಾಂಕ Eurydice_arr_ff *a)
{
  Eurydice_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)136U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 136
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_subslice_mut_d42(Eurydice_arr_ff *a, core_ops_range_Range_87 r)
{
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ತುಂಡು_u8){
        .ptr = a->ದತ್ತಾಂಶ + r.ಆರಂಭ,
        .meta = r.ಕೊನೆ - r.ಆರಂಭ
      }
    );
}

/**
A monomorphic instance of Eurydice.arr
with types uint64_t
with const generics
- $5size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_84_s { uint64_t ದತ್ತಾಂಶ[5U]; } Eurydice_arr_84;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ ಗಾತ್ರ_t_x2_s
{
  ಗಾತ್ರ_t fst;
  ಗಾತ್ರ_t snd;
}
ಗಾತ್ರ_t_x2;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_borrow_slice_u8
with const generics
- $1size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_dc_s { Eurydice_borrow_ತುಂಡು_u8 ದತ್ತಾಂಶ[1U]; } Eurydice_arr_dc;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types uint8_t
with const generics
- N= 168
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_2c(ಸ್ಥಿರಾಂಕ Eurydice_arr_c5 *a)
{
  Eurydice_borrow_ತುಂಡು_u8 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)168U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of core.result.Result
with types Eurydice_array_u8x8, core_array_TryFromSliceError

*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_8e_s
{
  core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_57_ಟ್ಯಾಗುಗಳು ಟ್ಯಾಗ್;
  ಒಕ್ಕೂಟ {
    Eurydice_array_u8x8 case_Ok;
    core_array_Try_From_ತುಂಡು_Error case_Err;
  }
  val;
}
core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_8e;

/**
This function found in impl {core::result::Result<T, E>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of core.result.unwrap_26
with types Eurydice_arr uint8_t[[$8size_t]], core_array_TryFromSliceError

*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_array_u8x8 core_ಫಲಿತಾಂಶ_unwrap_26_e0(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_8e self)
{
  ಆದರೆ (self.ಟ್ಯಾಗ್ == core_ಫಲಿತಾಂಶ_Ok)
  {
    ಹಿಂತಿರುಗಿ self.val.case_Ok;
  }
  ಇಲ್ಲದಿದ್ದರೆ
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_subslice_mut_d41(Eurydice_arr_c5 *a, core_ops_range_Range_87 r)
{
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ತುಂಡು_u8){
        .ptr = a->ದತ್ತಾಂಶ + r.ಆರಂಭ,
        .meta = r.ಕೊನೆ - r.ಆರಂಭ
      }
    );
}

/**
A monomorphic instance of Eurydice.arr
with types uint64_t
with const generics
- $24size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_22_s { uint64_t ದತ್ತಾಂಶ[24U]; } Eurydice_arr_22;

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_ff
with const generics
- $1size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_0b_s { Eurydice_arr_ff ದತ್ತಾಂಶ[1U]; } Eurydice_arr_0b;

/**
A monomorphic instance of Eurydice.arr
with types uint64_t
with const generics
- $25size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_7c_s { uint64_t ದತ್ತಾಂಶ[25U]; } Eurydice_arr_7c;

/**
A monomorphic instance of Eurydice.slice_subslice_shared
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t

*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
Eurydice_ತುಂಡು_subslice_shared_c8(Eurydice_borrow_ತುಂಡು_u8 s, core_ops_range_Range_87 r)
{
  ಹಿಂತಿರುಗಿ
    (KRML_CLITERAL(Eurydice_borrow_ತುಂಡು_u8){ .ptr = s.ptr + r.ಆರಂಭ, .meta = r.ಕೊನೆ - r.ಆರಂಭ });
}

/**
A monomorphic instance of Eurydice.arr
with types int32_t
with const generics
- $8size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_4d_s { int32_t ದತ್ತಾಂಶ[8U]; } Eurydice_arr_4d;

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types int32_t, core_ops_range_Range size_t, Eurydice_derefed_slice int32_t
with const generics
- N= 8
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_dst_ref_shared_83
Eurydice_array_ಗಮ್ಯ_subslice_shared_44(ಸ್ಥಿರಾಂಕ Eurydice_arr_4d *a, core_ops_range_Range_87 r)
{
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(Eurydice_dst_ref_shared_83){ .ptr = a->ದತ್ತಾಂಶ + r.ಆರಂಭ, .meta = r.ಕೊನೆ - r.ಆರಂಭ }
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ libcrux_secrets_mem_ವಿನಂತಿಗಳು_ct_declassify_5f(ಸ್ಥಿರಾಂಕ bool *val)
{

}

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ int32_t_x2_s
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_dst_ref_shared_83
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_fd(ಸ್ಥಿರಾಂಕ Eurydice_arr_4d *a)
{
  Eurydice_dst_ref_shared_83 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)8U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.slice_subslice_shared
with types int32_t, core_ops_range_Range size_t, Eurydice_derefed_slice int32_t

*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_dst_ref_shared_83
Eurydice_ತುಂಡು_subslice_shared_47(Eurydice_dst_ref_shared_83 s, core_ops_range_Range_87 r)
{
  ಹಿಂತಿರುಗಿ
    (KRML_CLITERAL(Eurydice_dst_ref_shared_83){ .ptr = s.ptr + r.ಆರಂಭ, .meta = r.ಕೊನೆ - r.ಆರಂಭ });
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types int32_t
with const generics
- N= 8
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_dst_ref_mut_83 Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_fd(Eurydice_arr_4d *a)
{
  Eurydice_dst_ref_mut_83 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)8U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of core.option.Option
with types Eurydice_arr_c9

*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ core_option_Option_57_s
{
  core_option_Option_45_ಟ್ಯಾಗುಗಳು ಟ್ಯಾಗ್;
  Eurydice_arr_c9 f0;
}
core_option_Option_57;

/**
A monomorphic instance of Eurydice.array_to_subslice_mut
with types uint8_t, core_ops_range_Range size_t, Eurydice_derefed_slice uint8_t
with const generics
- N= 34
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_subslice_mut_d40(Eurydice_arr_31 *a, core_ops_range_Range_87 r)
{
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ತುಂಡು_u8){
        .ptr = a->ದತ್ತಾಂಶ + r.ಆರಂಭ,
        .meta = r.ಕೊನೆ - r.ಆರಂಭ
      }
    );
}

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ uint8_t_x2_s
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_mut_borrow_ತುಂಡು_u8
Eurydice_array_ಗಮ್ಯ_subslice_mut_d4(Eurydice_arr_91 *a, core_ops_range_Range_87 r)
{
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(Eurydice_mut_borrow_ತುಂಡು_u8){
        .ptr = a->ದತ್ತಾಂಶ + r.ಆರಂಭ,
        .meta = r.ಕೊನೆ - r.ಆರಂಭ
      }
    );
}

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ libcrux_ml_kem_utils_extraction_helper_Keypair768_s
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
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_secrets_int_ಬಹಿರಂಗ_integers_declassify_d8_49(uint64_t self)
{
  ಹಿಂತಿರುಗಿ self;
}

/**
This function found in impl {libcrux_secrets::traits::Classify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.classify_27
with types uint32_t

*/
ಸ್ಥಿರ KRML_MUSTINLINE uint32_t
libcrux_secrets_int_ಬಹಿರಂಗ_integers_classify_27_df(uint32_t self)
{
  ಹಿಂತಿರುಗಿ self;
}

/**
This function found in impl {libcrux_secrets::traits::Classify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.classify_27
with types uint64_t

*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_secrets_int_ಬಹಿರಂಗ_integers_classify_27_49(uint64_t self)
{
  ಹಿಂತಿರುಗಿ self;
}

/**
This function found in impl {libcrux_secrets::traits::Declassify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.declassify_d8
with types uint16_t

*/
ಸ್ಥಿರ KRML_MUSTINLINE uint16_t
libcrux_secrets_int_ಬಹಿರಂಗ_integers_declassify_d8_de(uint16_t self)
{
  ಹಿಂತಿರುಗಿ self;
}

/**
This function found in impl {libcrux_secrets::traits::Classify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.classify_27
with types uint16_t

*/
ಸ್ಥಿರ KRML_MUSTINLINE uint16_t
libcrux_secrets_int_ಬಹಿರಂಗ_integers_classify_27_de(uint16_t self)
{
  ಹಿಂತಿರುಗಿ self;
}

/**
This function found in impl {libcrux_secrets::traits::Declassify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.declassify_d8
with types uint32_t

*/
ಸ್ಥಿರ KRML_MUSTINLINE uint32_t
libcrux_secrets_int_ಬಹಿರಂಗ_integers_declassify_d8_df(uint32_t self)
{
  ಹಿಂತಿರುಗಿ self;
}

/**
This function found in impl {libcrux_secrets::traits::Declassify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.declassify_d8
with types int32_t

*/
ಸ್ಥಿರ KRML_MUSTINLINE int32_t
libcrux_secrets_int_ಬಹಿರಂಗ_integers_declassify_d8_a8(int32_t self)
{
  ಹಿಂತಿರುಗಿ self;
}

/**
This function found in impl {libcrux_secrets::traits::Classify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.classify_27
with types int32_t

*/
ಸ್ಥಿರ KRML_MUSTINLINE int32_t libcrux_secrets_int_ಬಹಿರಂಗ_integers_classify_27_a8(int32_t self)
{
  ಹಿಂತಿರುಗಿ self;
}

/**
This function found in impl {libcrux_secrets::traits::Declassify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.declassify_d8
with types uint8_t

*/
ಸ್ಥಿರ KRML_MUSTINLINE uint8_t
libcrux_secrets_int_ಬಹಿರಂಗ_integers_declassify_d8_90(uint8_t self)
{
  ಹಿಂತಿರುಗಿ self;
}

/**
This function found in impl {libcrux_secrets::traits::Classify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.classify_27
with types int16_t

*/
ಸ್ಥಿರ KRML_MUSTINLINE int16_t libcrux_secrets_int_ಬಹಿರಂಗ_integers_classify_27_39(int16_t self)
{
  ಹಿಂತಿರುಗಿ self;
}

/**
This function found in impl {libcrux_secrets::traits::Declassify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.declassify_d8
with types int16_t

*/
ಸ್ಥಿರ KRML_MUSTINLINE int16_t
libcrux_secrets_int_ಬಹಿರಂಗ_integers_declassify_d8_39(int16_t self)
{
  ಹಿಂತಿರುಗಿ self;
}

/**
This function found in impl {libcrux_secrets::traits::Classify<T> for T}
*/
/**
A monomorphic instance of libcrux_secrets.int.public_integers.classify_27
with types uint8_t

*/
ಸ್ಥಿರ KRML_MUSTINLINE uint8_t libcrux_secrets_int_ಬಹಿರಂಗ_integers_classify_27_90(uint8_t self)
{
  ಹಿಂತಿರುಗಿ self;
}

#ಆದರೆ defined(__cplusplus)
}
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿಸು combined_core_H_DEFINED
#ಆದರೆ_ಅಂತ್ಯ /* combined_core_H */

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


#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ libcrux_sha3_portable_H
#ವ್ಯಾಖ್ಯಾನಿಸು libcrux_sha3_portable_H



#ಆದರೆ defined(__cplusplus)
ಬಾಹ್ಯ "C" {
#ಆದರೆ_ಅಂತ್ಯ


/**
A monomorphic instance of libcrux_sha3.generic_keccak.KeccakState
with types uint64_t
with const generics
- $1size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ Eurydice_arr_7c libcrux_sha3_generic_keccak_KeccakState_f3;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ libcrux_sha3_generic_keccak_KeccakState_f3 libcrux_sha3_portable_KeccakState;

/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.KeccakXofState
with types uint64_t
with const generics
- $1size_t
- $136size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ libcrux_sha3_generic_keccak_xof_KeccakXofState_8d_s
{
  Eurydice_arr_7c inner;
  Eurydice_arr_0b buf;
  ಗಾತ್ರ_t buf_len;
  bool sponge;
}
libcrux_sha3_generic_keccak_xof_KeccakXofState_8d;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
libcrux_sha3_portable_incremental_Shake256Xof;

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_zero_d2(ಶೂನ್ಯ)
{
  ಹಿಂತಿರುಗಿ 0ULL;
}

ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__veor5q_u64(
  uint64_t a,
  uint64_t b,
  uint64_t c,
  uint64_t d,
  uint64_t e
)
{
  ಹಿಂತಿರುಗಿ (((a ^ b) ^ c) ^ d) ^ e;
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor5_d2(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable__veor5q_u64(a, b, c, d, e);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 1
- RIGHT= 63
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_ಎಡ_76(uint64_t x)
{
  ಹಿಂತಿರುಗಿ core_ಅಂಕೆ_u64_rotate_ಎಡ(x, (uint32_t)1);
}

ಸ್ಥಿರ KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable__vrax1q_u64(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ a ^ libcrux_sha3_simd_portable_rotate_ಎಡ_76(b);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_rotate_left1_and_xor_d2(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable__vrax1q_u64(a, b);
}

ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vbcaxq_u64(uint64_t a, uint64_t b, uint64_t c)
{
  ಹಿಂತಿರುಗಿ a ^ (b & ~c);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_and_not_xor_d2(uint64_t a, uint64_t b, uint64_t c)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable__vbcaxq_u64(a, b, c);
}

ಸ್ಥಿರ KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable__veorq_n_u64(uint64_t a, uint64_t c)
{
  ಹಿಂತಿರುಗಿ a ^ c;
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_constant_d2(uint64_t a, uint64_t c)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable__veorq_n_u64(a, c);
}

/**
This function found in impl {libcrux_sha3::traits::KeccakItem<1usize> for u64}
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_xor_d2(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ a ^ b;
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
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_7c libcrux_sha3_generic_keccak_new_80_71(ಶೂನ್ಯ)
{
  Eurydice_arr_7c lit;
  uint64_t repeat_ಅಭಿವ್ಯಕ್ತಿ[25U];
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)25U; i++)
  {
    repeat_ಅಭಿವ್ಯಕ್ತಿ[i] = libcrux_sha3_simd_portable_zero_d2();
  }
  ಸ್ಮರಣೆ_ನಕಲು(lit.ದತ್ತಾಂಶ, repeat_ಅಭಿವ್ಯಕ್ತಿ, (ಗಾತ್ರ_t)25U * ಗಾತ್ರ (uint64_t));
  ಹಿಂತಿರುಗಿ lit;
}

/**
 Create a new SHAKE-128 state object.
*/
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_7c libcrux_sha3_portable_incremental_shake128_init(ಶೂನ್ಯ)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_generic_keccak_new_80_71();
}

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_SHA3_GENERIC_KECCAK_CONSTANTS_ROUNDCONSTANTS ((KRML_CLITERAL(Eurydice_arr_22){ .ದತ್ತಾಂಶ = { 1ULL, 32898ULL, 9223372036854808714ULL, 9223372039002292224ULL, 32907ULL, 2147483649ULL, 9223372039002292353ULL, 9223372036854808585ULL, 138ULL, 136ULL, 2147516425ULL, 2147483658ULL, 2147516555ULL, 9223372036854775947ULL, 9223372036854808713ULL, 9223372036854808579ULL, 9223372036854808578ULL, 9223372036854775936ULL, 32778ULL, 9223372039002259466ULL, 9223372039002292353ULL, 9223372036854808704ULL, 2147483649ULL, 9223372039002292232ULL } }))

/**
A monomorphic instance of libcrux_sha3.traits.get_ij
with types uint64_t
with const generics
- N= 1
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಸ್ಥಿರಾಂಕ
uint64_t
*libcrux_sha3_traits_get_ij_71(ಸ್ಥಿರಾಂಕ Eurydice_arr_7c *arr, ಗಾತ್ರ_t i, ಗಾತ್ರ_t j)
{
  ಹಿಂತಿರುಗಿ &arr->ದತ್ತಾಂಶ[(ಗಾತ್ರ_t)5U * j + i];
}

/**
A monomorphic instance of libcrux_sha3.traits.set_ij
with types uint64_t
with const generics
- N= 1
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_traits_ಗಣ_ij_71(Eurydice_arr_7c *arr, ಗಾತ್ರ_t i, ಗಾತ್ರ_t j, uint64_t ಮೌಲ್ಯ)
{
  arr->ದತ್ತಾಂಶ[(ಗಾತ್ರ_t)5U * j + i] = ಮೌಲ್ಯ;
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_block
with const generics
- RATE= 168
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_simd_portable_ತುಂಬು_ಖಂಡ_60(
  Eurydice_arr_7c *state,
  Eurydice_borrow_ತುಂಡು_u8 ಖಂಡಗಳು,
  ಗಾತ್ರ_t ಆರಂಭ
)
{
  Eurydice_arr_7c state_flat = { .ದತ್ತಾಂಶ = { 0U } };
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)168U / (ಗಾತ್ರ_t)8U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    ಗಾತ್ರ_t ಸ್ಥಾನಾಂತರ = ಆರಂಭ + (ಗಾತ್ರ_t)8U * i0;
    Eurydice_array_u8x8 arr;
    ಸ್ಮರಣೆ_ನಕಲು(arr.ದತ್ತಾಂಶ,
      Eurydice_ತುಂಡು_subslice_shared_c8(ಖಂಡಗಳು,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = ಸ್ಥಾನಾಂತರ, .ಕೊನೆ = ಸ್ಥಾನಾಂತರ + (ಗಾತ್ರ_t)8U })).ptr,
      (ಗಾತ್ರ_t)8U * ಗಾತ್ರ (uint8_t));
    Eurydice_array_u8x8
    uu____0 =
      core_ಫಲಿತಾಂಶ_unwrap_26_e0((
          KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_8e){ .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Ok, .val = { .case_Ok = arr } }
        ));
    state_flat.ದತ್ತಾಂಶ[i0] = core_ಅಂಕೆ_u64_from_le_ಬೈಟುಗಳು(uu____0);
  }
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)168U / (ಗಾತ್ರ_t)8U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    libcrux_sha3_traits_ಗಣ_ij_71(state,
      i0 / (ಗಾತ್ರ_t)5U,
      i0 % (ಗಾತ್ರ_t)5U,
      libcrux_sha3_traits_get_ij_71(state, i0 / (ಗಾತ್ರ_t)5U, i0 % (ಗಾತ್ರ_t)5U)[0U] ^
        state_flat.ದತ್ತಾಂಶ[i0]);
  }
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_last
with const generics
- RATE= 168
- DELIMITER= 31
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_simd_portable_ತುಂಬು_ಕೊನೆಯ_37(
  Eurydice_arr_7c *state,
  Eurydice_borrow_ತುಂಡು_u8 ಖಂಡಗಳು,
  ಗಾತ್ರ_t ಆರಂಭ,
  ಗಾತ್ರ_t len
)
{
  Eurydice_arr_c5 ಬಫರ್ = { .ದತ್ತಾಂಶ = { 0U } };
  Eurydice_ತುಂಡು_copy(Eurydice_array_ಗಮ್ಯ_subslice_mut_d41(&ಬಫರ್,
      (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = (ಗಾತ್ರ_t)0U, .ಕೊನೆ = len })),
    Eurydice_ತುಂಡು_subslice_shared_c8(ಖಂಡಗಳು,
      (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = ಆರಂಭ, .ಕೊನೆ = ಆರಂಭ + len })),
    uint8_t);
  ಬಫರ್.ದತ್ತಾಂಶ[len] = 31U;
  ಗಾತ್ರ_t uu____0 = (ಗಾತ್ರ_t)168U - (ಗಾತ್ರ_t)1U;
  ಬಫರ್.ದತ್ತಾಂಶ[uu____0] = (uint32_t)ಬಫರ್.ದತ್ತಾಂಶ[uu____0] | 128U;
  libcrux_sha3_simd_portable_ತುಂಬು_ಖಂಡ_60(state,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_2c(&ಬಫರ್),
    (ಗಾತ್ರ_t)0U);
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_sha3_simd_portable_ತುಂಬು_ಕೊನೆಯ_a1_37(
  Eurydice_arr_7c *self,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_dc *ಒಳಹರಿವು,
  ಗಾತ್ರ_t ಆರಂಭ,
  ಗಾತ್ರ_t len
)
{
  libcrux_sha3_simd_portable_ತುಂಬು_ಕೊನೆಯ_37(self, ಒಳಹರಿವು->ದತ್ತಾಂಶ[0U], ಆರಂಭ, len);
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಸ್ಥಿರಾಂಕ
uint64_t
*libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(ಸ್ಥಿರಾಂಕ Eurydice_arr_7c *self, ಗಾತ್ರ_t_x2 index)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_traits_get_ij_71(self, index.fst, index.snd);
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
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_84
libcrux_sha3_generic_keccak_theta_80_71(Eurydice_arr_7c *self)
{
  Eurydice_arr_84
  c =
    {
      .ದತ್ತಾಂಶ = {
        libcrux_sha3_simd_portable_xor5_d2(libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
            (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)0U, .snd = (ಗಾತ್ರ_t)0U }))[0U],
          libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
            (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)1U, .snd = (ಗಾತ್ರ_t)0U }))[0U],
          libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
            (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)2U, .snd = (ಗಾತ್ರ_t)0U }))[0U],
          libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
            (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)3U, .snd = (ಗಾತ್ರ_t)0U }))[0U],
          libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
            (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)4U, .snd = (ಗಾತ್ರ_t)0U }))[0U]),
        libcrux_sha3_simd_portable_xor5_d2(libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
            (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)0U, .snd = (ಗಾತ್ರ_t)1U }))[0U],
          libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
            (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)1U, .snd = (ಗಾತ್ರ_t)1U }))[0U],
          libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
            (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)2U, .snd = (ಗಾತ್ರ_t)1U }))[0U],
          libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
            (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)3U, .snd = (ಗಾತ್ರ_t)1U }))[0U],
          libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
            (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)4U, .snd = (ಗಾತ್ರ_t)1U }))[0U]),
        libcrux_sha3_simd_portable_xor5_d2(libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
            (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)0U, .snd = (ಗಾತ್ರ_t)2U }))[0U],
          libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
            (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)1U, .snd = (ಗಾತ್ರ_t)2U }))[0U],
          libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
            (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)2U, .snd = (ಗಾತ್ರ_t)2U }))[0U],
          libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
            (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)3U, .snd = (ಗಾತ್ರ_t)2U }))[0U],
          libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
            (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)4U, .snd = (ಗಾತ್ರ_t)2U }))[0U]),
        libcrux_sha3_simd_portable_xor5_d2(libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
            (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)0U, .snd = (ಗಾತ್ರ_t)3U }))[0U],
          libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
            (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)1U, .snd = (ಗಾತ್ರ_t)3U }))[0U],
          libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
            (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)2U, .snd = (ಗಾತ್ರ_t)3U }))[0U],
          libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
            (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)3U, .snd = (ಗಾತ್ರ_t)3U }))[0U],
          libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
            (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)4U, .snd = (ಗಾತ್ರ_t)3U }))[0U]),
        libcrux_sha3_simd_portable_xor5_d2(libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
            (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)0U, .snd = (ಗಾತ್ರ_t)4U }))[0U],
          libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
            (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)1U, .snd = (ಗಾತ್ರ_t)4U }))[0U],
          libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
            (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)2U, .snd = (ಗಾತ್ರ_t)4U }))[0U],
          libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
            (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)3U, .snd = (ಗಾತ್ರ_t)4U }))[0U],
          libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
            (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)4U, .snd = (ಗಾತ್ರ_t)4U }))[0U])
      }
    };
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(Eurydice_arr_84){
        .ದತ್ತಾಂಶ = {
          libcrux_sha3_simd_portable_rotate_left1_and_xor_d2(c.ದತ್ತಾಂಶ[((ಗಾತ್ರ_t)0U + (ಗಾತ್ರ_t)4U) %
              (ಗಾತ್ರ_t)5U],
            c.ದತ್ತಾಂಶ[((ಗಾತ್ರ_t)0U + (ಗಾತ್ರ_t)1U) % (ಗಾತ್ರ_t)5U]),
          libcrux_sha3_simd_portable_rotate_left1_and_xor_d2(c.ದತ್ತಾಂಶ[((ಗಾತ್ರ_t)1U + (ಗಾತ್ರ_t)4U) %
              (ಗಾತ್ರ_t)5U],
            c.ದತ್ತಾಂಶ[((ಗಾತ್ರ_t)1U + (ಗಾತ್ರ_t)1U) % (ಗಾತ್ರ_t)5U]),
          libcrux_sha3_simd_portable_rotate_left1_and_xor_d2(c.ದತ್ತಾಂಶ[((ಗಾತ್ರ_t)2U + (ಗಾತ್ರ_t)4U) %
              (ಗಾತ್ರ_t)5U],
            c.ದತ್ತಾಂಶ[((ಗಾತ್ರ_t)2U + (ಗಾತ್ರ_t)1U) % (ಗಾತ್ರ_t)5U]),
          libcrux_sha3_simd_portable_rotate_left1_and_xor_d2(c.ದತ್ತಾಂಶ[((ಗಾತ್ರ_t)3U + (ಗಾತ್ರ_t)4U) %
              (ಗಾತ್ರ_t)5U],
            c.ದತ್ತಾಂಶ[((ಗಾತ್ರ_t)3U + (ಗಾತ್ರ_t)1U) % (ಗಾತ್ರ_t)5U]),
          libcrux_sha3_simd_portable_rotate_left1_and_xor_d2(c.ದತ್ತಾಂಶ[((ಗಾತ್ರ_t)4U + (ಗಾತ್ರ_t)4U) %
              (ಗಾತ್ರ_t)5U],
            c.ದತ್ತಾಂಶ[((ಗಾತ್ರ_t)4U + (ಗಾತ್ರ_t)1U) % (ಗಾತ್ರ_t)5U])
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_sha3_generic_keccak_ಗಣ_80_71(Eurydice_arr_7c *self, ಗಾತ್ರ_t i, ಗಾತ್ರ_t j, uint64_t v)
{
  libcrux_sha3_traits_ಗಣ_ij_71(self, i, j, v);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 36
- RIGHT= 28
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_ಎಡ_02(uint64_t x)
{
  ಹಿಂತಿರುಗಿ core_ಅಂಕೆ_u64_rotate_ಎಡ(x, (uint32_t)36);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 36
- RIGHT= 28
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_02(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable_rotate_ಎಡ_02(a ^ b);
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
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_02(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable__vxarq_u64_02(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 3
- RIGHT= 61
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_ಎಡ_ac(uint64_t x)
{
  ಹಿಂತಿರುಗಿ core_ಅಂಕೆ_u64_rotate_ಎಡ(x, (uint32_t)3);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 3
- RIGHT= 61
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_ac(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable_rotate_ಎಡ_ac(a ^ b);
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
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_ac(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable__vxarq_u64_ac(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 41
- RIGHT= 23
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_ಎಡ_020(uint64_t x)
{
  ಹಿಂತಿರುಗಿ core_ಅಂಕೆ_u64_rotate_ಎಡ(x, (uint32_t)41);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 41
- RIGHT= 23
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_020(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable_rotate_ಎಡ_020(a ^ b);
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
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_020(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable__vxarq_u64_020(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 18
- RIGHT= 46
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_ಎಡ_a9(uint64_t x)
{
  ಹಿಂತಿರುಗಿ core_ಅಂಕೆ_u64_rotate_ಎಡ(x, (uint32_t)18);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 18
- RIGHT= 46
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_a9(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable_rotate_ಎಡ_a9(a ^ b);
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
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_a9(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable__vxarq_u64_a9(a, b);
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_generic_keccak_rho_0_80_71(Eurydice_arr_7c *self, Eurydice_arr_84 t)
{
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)0U,
    (ಗಾತ್ರ_t)0U,
    libcrux_sha3_simd_portable_xor_d2(libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
        (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)0U, .snd = (ಗಾತ್ರ_t)0U }))[0U],
      t.ದತ್ತಾಂಶ[0U]));
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)1U,
    (ಗಾತ್ರ_t)0U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_02(libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
        (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)1U, .snd = (ಗಾತ್ರ_t)0U }))[0U],
      t.ದತ್ತಾಂಶ[0U]));
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)2U,
    (ಗಾತ್ರ_t)0U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_ac(libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
        (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)2U, .snd = (ಗಾತ್ರ_t)0U }))[0U],
      t.ದತ್ತಾಂಶ[0U]));
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)3U,
    (ಗಾತ್ರ_t)0U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_020(libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
        (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)3U, .snd = (ಗಾತ್ರ_t)0U }))[0U],
      t.ದತ್ತಾಂಶ[0U]));
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)4U,
    (ಗಾತ್ರ_t)0U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_a9(libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
        (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)4U, .snd = (ಗಾತ್ರ_t)0U }))[0U],
      t.ದತ್ತಾಂಶ[0U]));
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 1
- RIGHT= 63
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_76(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable_rotate_ಎಡ_76(a ^ b);
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
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_76(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable__vxarq_u64_76(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 44
- RIGHT= 20
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_ಎಡ_58(uint64_t x)
{
  ಹಿಂತಿರುಗಿ core_ಅಂಕೆ_u64_rotate_ಎಡ(x, (uint32_t)44);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 44
- RIGHT= 20
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_58(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable_rotate_ಎಡ_58(a ^ b);
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
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_58(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable__vxarq_u64_58(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 10
- RIGHT= 54
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_ಎಡ_e0(uint64_t x)
{
  ಹಿಂತಿರುಗಿ core_ಅಂಕೆ_u64_rotate_ಎಡ(x, (uint32_t)10);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 10
- RIGHT= 54
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_e0(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable_rotate_ಎಡ_e0(a ^ b);
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
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_e0(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable__vxarq_u64_e0(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 45
- RIGHT= 19
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_ಎಡ_63(uint64_t x)
{
  ಹಿಂತಿರುಗಿ core_ಅಂಕೆ_u64_rotate_ಎಡ(x, (uint32_t)45);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 45
- RIGHT= 19
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_63(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable_rotate_ಎಡ_63(a ^ b);
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
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_63(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable__vxarq_u64_63(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 2
- RIGHT= 62
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_ಎಡ_6a(uint64_t x)
{
  ಹಿಂತಿರುಗಿ core_ಅಂಕೆ_u64_rotate_ಎಡ(x, (uint32_t)2);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 2
- RIGHT= 62
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_6a(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable_rotate_ಎಡ_6a(a ^ b);
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
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_6a(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable__vxarq_u64_6a(a, b);
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_generic_keccak_rho_1_80_71(Eurydice_arr_7c *self, Eurydice_arr_84 t)
{
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)0U,
    (ಗಾತ್ರ_t)1U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_76(libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
        (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)0U, .snd = (ಗಾತ್ರ_t)1U }))[0U],
      t.ದತ್ತಾಂಶ[1U]));
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)1U,
    (ಗಾತ್ರ_t)1U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_58(libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
        (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)1U, .snd = (ಗಾತ್ರ_t)1U }))[0U],
      t.ದತ್ತಾಂಶ[1U]));
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)2U,
    (ಗಾತ್ರ_t)1U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_e0(libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
        (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)2U, .snd = (ಗಾತ್ರ_t)1U }))[0U],
      t.ದತ್ತಾಂಶ[1U]));
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)3U,
    (ಗಾತ್ರ_t)1U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_63(libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
        (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)3U, .snd = (ಗಾತ್ರ_t)1U }))[0U],
      t.ದತ್ತಾಂಶ[1U]));
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)4U,
    (ಗಾತ್ರ_t)1U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_6a(libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
        (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)4U, .snd = (ಗಾತ್ರ_t)1U }))[0U],
      t.ದತ್ತಾಂಶ[1U]));
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 62
- RIGHT= 2
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_ಎಡ_ab(uint64_t x)
{
  ಹಿಂತಿರುಗಿ core_ಅಂಕೆ_u64_rotate_ಎಡ(x, (uint32_t)62);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 62
- RIGHT= 2
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_ab(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable_rotate_ಎಡ_ab(a ^ b);
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
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_ab(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable__vxarq_u64_ab(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 6
- RIGHT= 58
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_ಎಡ_5b(uint64_t x)
{
  ಹಿಂತಿರುಗಿ core_ಅಂಕೆ_u64_rotate_ಎಡ(x, (uint32_t)6);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 6
- RIGHT= 58
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_5b(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable_rotate_ಎಡ_5b(a ^ b);
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
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_5b(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable__vxarq_u64_5b(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 43
- RIGHT= 21
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_ಎಡ_6f(uint64_t x)
{
  ಹಿಂತಿರುಗಿ core_ಅಂಕೆ_u64_rotate_ಎಡ(x, (uint32_t)43);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 43
- RIGHT= 21
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_6f(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable_rotate_ಎಡ_6f(a ^ b);
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
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_6f(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable__vxarq_u64_6f(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 15
- RIGHT= 49
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_ಎಡ_62(uint64_t x)
{
  ಹಿಂತಿರುಗಿ core_ಅಂಕೆ_u64_rotate_ಎಡ(x, (uint32_t)15);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 15
- RIGHT= 49
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_62(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable_rotate_ಎಡ_62(a ^ b);
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
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_62(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable__vxarq_u64_62(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 61
- RIGHT= 3
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_ಎಡ_23(uint64_t x)
{
  ಹಿಂತಿರುಗಿ core_ಅಂಕೆ_u64_rotate_ಎಡ(x, (uint32_t)61);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 61
- RIGHT= 3
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_23(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable_rotate_ಎಡ_23(a ^ b);
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
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_23(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable__vxarq_u64_23(a, b);
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_generic_keccak_rho_2_80_71(Eurydice_arr_7c *self, Eurydice_arr_84 t)
{
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)0U,
    (ಗಾತ್ರ_t)2U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_ab(libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
        (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)0U, .snd = (ಗಾತ್ರ_t)2U }))[0U],
      t.ದತ್ತಾಂಶ[2U]));
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)1U,
    (ಗಾತ್ರ_t)2U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_5b(libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
        (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)1U, .snd = (ಗಾತ್ರ_t)2U }))[0U],
      t.ದತ್ತಾಂಶ[2U]));
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)2U,
    (ಗಾತ್ರ_t)2U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_6f(libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
        (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)2U, .snd = (ಗಾತ್ರ_t)2U }))[0U],
      t.ದತ್ತಾಂಶ[2U]));
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)3U,
    (ಗಾತ್ರ_t)2U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_62(libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
        (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)3U, .snd = (ಗಾತ್ರ_t)2U }))[0U],
      t.ದತ್ತಾಂಶ[2U]));
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)4U,
    (ಗಾತ್ರ_t)2U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_23(libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
        (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)4U, .snd = (ಗಾತ್ರ_t)2U }))[0U],
      t.ದತ್ತಾಂಶ[2U]));
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 28
- RIGHT= 36
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_ಎಡ_37(uint64_t x)
{
  ಹಿಂತಿರುಗಿ core_ಅಂಕೆ_u64_rotate_ಎಡ(x, (uint32_t)28);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 28
- RIGHT= 36
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_37(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable_rotate_ಎಡ_37(a ^ b);
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
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_37(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable__vxarq_u64_37(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 55
- RIGHT= 9
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_ಎಡ_bb(uint64_t x)
{
  ಹಿಂತಿರುಗಿ core_ಅಂಕೆ_u64_rotate_ಎಡ(x, (uint32_t)55);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 55
- RIGHT= 9
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_bb(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable_rotate_ಎಡ_bb(a ^ b);
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
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_bb(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable__vxarq_u64_bb(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 25
- RIGHT= 39
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_ಎಡ_b9(uint64_t x)
{
  ಹಿಂತಿರುಗಿ core_ಅಂಕೆ_u64_rotate_ಎಡ(x, (uint32_t)25);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 25
- RIGHT= 39
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_b9(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable_rotate_ಎಡ_b9(a ^ b);
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
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_b9(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable__vxarq_u64_b9(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 21
- RIGHT= 43
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_ಎಡ_54(uint64_t x)
{
  ಹಿಂತಿರುಗಿ core_ಅಂಕೆ_u64_rotate_ಎಡ(x, (uint32_t)21);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 21
- RIGHT= 43
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_54(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable_rotate_ಎಡ_54(a ^ b);
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
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_54(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable__vxarq_u64_54(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 56
- RIGHT= 8
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_ಎಡ_4c(uint64_t x)
{
  ಹಿಂತಿರುಗಿ core_ಅಂಕೆ_u64_rotate_ಎಡ(x, (uint32_t)56);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 56
- RIGHT= 8
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_4c(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable_rotate_ಎಡ_4c(a ^ b);
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
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_4c(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable__vxarq_u64_4c(a, b);
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_generic_keccak_rho_3_80_71(Eurydice_arr_7c *self, Eurydice_arr_84 t)
{
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)0U,
    (ಗಾತ್ರ_t)3U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_37(libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
        (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)0U, .snd = (ಗಾತ್ರ_t)3U }))[0U],
      t.ದತ್ತಾಂಶ[3U]));
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)1U,
    (ಗಾತ್ರ_t)3U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_bb(libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
        (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)1U, .snd = (ಗಾತ್ರ_t)3U }))[0U],
      t.ದತ್ತಾಂಶ[3U]));
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)2U,
    (ಗಾತ್ರ_t)3U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_b9(libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
        (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)2U, .snd = (ಗಾತ್ರ_t)3U }))[0U],
      t.ದತ್ತಾಂಶ[3U]));
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)3U,
    (ಗಾತ್ರ_t)3U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_54(libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
        (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)3U, .snd = (ಗಾತ್ರ_t)3U }))[0U],
      t.ದತ್ತಾಂಶ[3U]));
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)4U,
    (ಗಾತ್ರ_t)3U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_4c(libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
        (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)4U, .snd = (ಗಾತ್ರ_t)3U }))[0U],
      t.ದತ್ತಾಂಶ[3U]));
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 27
- RIGHT= 37
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_ಎಡ_ce(uint64_t x)
{
  ಹಿಂತಿರುಗಿ core_ಅಂಕೆ_u64_rotate_ಎಡ(x, (uint32_t)27);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 27
- RIGHT= 37
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_ce(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable_rotate_ಎಡ_ce(a ^ b);
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
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_ce(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable__vxarq_u64_ce(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 20
- RIGHT= 44
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_ಎಡ_77(uint64_t x)
{
  ಹಿಂತಿರುಗಿ core_ಅಂಕೆ_u64_rotate_ಎಡ(x, (uint32_t)20);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 20
- RIGHT= 44
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_77(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable_rotate_ಎಡ_77(a ^ b);
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
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_77(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable__vxarq_u64_77(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 39
- RIGHT= 25
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_ಎಡ_25(uint64_t x)
{
  ಹಿಂತಿರುಗಿ core_ಅಂಕೆ_u64_rotate_ಎಡ(x, (uint32_t)39);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 39
- RIGHT= 25
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_25(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable_rotate_ಎಡ_25(a ^ b);
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
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_25(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable__vxarq_u64_25(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 8
- RIGHT= 56
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_ಎಡ_af(uint64_t x)
{
  ಹಿಂತಿರುಗಿ core_ಅಂಕೆ_u64_rotate_ಎಡ(x, (uint32_t)8);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 8
- RIGHT= 56
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_af(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable_rotate_ಎಡ_af(a ^ b);
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
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_af(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable__vxarq_u64_af(a, b);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.rotate_left
with const generics
- LEFT= 14
- RIGHT= 50
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t libcrux_sha3_simd_portable_rotate_ಎಡ_fd(uint64_t x)
{
  ಹಿಂತಿರುಗಿ core_ಅಂಕೆ_u64_rotate_ಎಡ(x, (uint32_t)14);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable._vxarq_u64
with const generics
- LEFT= 14
- RIGHT= 50
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable__vxarq_u64_fd(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable_rotate_ಎಡ_fd(a ^ b);
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
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_sha3_simd_portable_xor_and_rotate_d2_fd(uint64_t a, uint64_t b)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_simd_portable__vxarq_u64_fd(a, b);
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_generic_keccak_rho_4_80_71(Eurydice_arr_7c *self, Eurydice_arr_84 t)
{
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)0U,
    (ಗಾತ್ರ_t)4U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_ce(libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
        (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)0U, .snd = (ಗಾತ್ರ_t)4U }))[0U],
      t.ದತ್ತಾಂಶ[4U]));
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)1U,
    (ಗಾತ್ರ_t)4U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_77(libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
        (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)1U, .snd = (ಗಾತ್ರ_t)4U }))[0U],
      t.ದತ್ತಾಂಶ[4U]));
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)2U,
    (ಗಾತ್ರ_t)4U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_25(libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
        (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)2U, .snd = (ಗಾತ್ರ_t)4U }))[0U],
      t.ದತ್ತಾಂಶ[4U]));
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)3U,
    (ಗಾತ್ರ_t)4U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_af(libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
        (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)3U, .snd = (ಗಾತ್ರ_t)4U }))[0U],
      t.ದತ್ತಾಂಶ[4U]));
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)4U,
    (ಗಾತ್ರ_t)4U,
    libcrux_sha3_simd_portable_xor_and_rotate_d2_fd(libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
        (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)4U, .snd = (ಗಾತ್ರ_t)4U }))[0U],
      t.ದತ್ತಾಂಶ[4U]));
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_generic_keccak_pi_0_80_71(Eurydice_arr_7c *self, Eurydice_arr_7c old)
{
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)1U,
    (ಗಾತ್ರ_t)0U,
    libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(&old,
      (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)0U, .snd = (ಗಾತ್ರ_t)3U }))[0U]);
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)2U,
    (ಗಾತ್ರ_t)0U,
    libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(&old,
      (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)0U, .snd = (ಗಾತ್ರ_t)1U }))[0U]);
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)3U,
    (ಗಾತ್ರ_t)0U,
    libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(&old,
      (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)0U, .snd = (ಗಾತ್ರ_t)4U }))[0U]);
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)4U,
    (ಗಾತ್ರ_t)0U,
    libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(&old,
      (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)0U, .snd = (ಗಾತ್ರ_t)2U }))[0U]);
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_generic_keccak_pi_1_80_71(Eurydice_arr_7c *self, Eurydice_arr_7c old)
{
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)0U,
    (ಗಾತ್ರ_t)1U,
    libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(&old,
      (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)1U, .snd = (ಗಾತ್ರ_t)1U }))[0U]);
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)1U,
    (ಗಾತ್ರ_t)1U,
    libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(&old,
      (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)1U, .snd = (ಗಾತ್ರ_t)4U }))[0U]);
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)2U,
    (ಗಾತ್ರ_t)1U,
    libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(&old,
      (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)1U, .snd = (ಗಾತ್ರ_t)2U }))[0U]);
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)3U,
    (ಗಾತ್ರ_t)1U,
    libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(&old,
      (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)1U, .snd = (ಗಾತ್ರ_t)0U }))[0U]);
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)4U,
    (ಗಾತ್ರ_t)1U,
    libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(&old,
      (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)1U, .snd = (ಗಾತ್ರ_t)3U }))[0U]);
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_generic_keccak_pi_2_80_71(Eurydice_arr_7c *self, Eurydice_arr_7c old)
{
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)0U,
    (ಗಾತ್ರ_t)2U,
    libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(&old,
      (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)2U, .snd = (ಗಾತ್ರ_t)2U }))[0U]);
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)1U,
    (ಗಾತ್ರ_t)2U,
    libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(&old,
      (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)2U, .snd = (ಗಾತ್ರ_t)0U }))[0U]);
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)2U,
    (ಗಾತ್ರ_t)2U,
    libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(&old,
      (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)2U, .snd = (ಗಾತ್ರ_t)3U }))[0U]);
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)3U,
    (ಗಾತ್ರ_t)2U,
    libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(&old,
      (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)2U, .snd = (ಗಾತ್ರ_t)1U }))[0U]);
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)4U,
    (ಗಾತ್ರ_t)2U,
    libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(&old,
      (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)2U, .snd = (ಗಾತ್ರ_t)4U }))[0U]);
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_generic_keccak_pi_3_80_71(Eurydice_arr_7c *self, Eurydice_arr_7c old)
{
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)0U,
    (ಗಾತ್ರ_t)3U,
    libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(&old,
      (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)3U, .snd = (ಗಾತ್ರ_t)3U }))[0U]);
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)1U,
    (ಗಾತ್ರ_t)3U,
    libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(&old,
      (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)3U, .snd = (ಗಾತ್ರ_t)1U }))[0U]);
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)2U,
    (ಗಾತ್ರ_t)3U,
    libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(&old,
      (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)3U, .snd = (ಗಾತ್ರ_t)4U }))[0U]);
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)3U,
    (ಗಾತ್ರ_t)3U,
    libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(&old,
      (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)3U, .snd = (ಗಾತ್ರ_t)2U }))[0U]);
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)4U,
    (ಗಾತ್ರ_t)3U,
    libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(&old,
      (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)3U, .snd = (ಗಾತ್ರ_t)0U }))[0U]);
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_generic_keccak_pi_4_80_71(Eurydice_arr_7c *self, Eurydice_arr_7c old)
{
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)0U,
    (ಗಾತ್ರ_t)4U,
    libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(&old,
      (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)4U, .snd = (ಗಾತ್ರ_t)4U }))[0U]);
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)1U,
    (ಗಾತ್ರ_t)4U,
    libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(&old,
      (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)4U, .snd = (ಗಾತ್ರ_t)2U }))[0U]);
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)2U,
    (ಗಾತ್ರ_t)4U,
    libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(&old,
      (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)4U, .snd = (ಗಾತ್ರ_t)0U }))[0U]);
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)3U,
    (ಗಾತ್ರ_t)4U,
    libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(&old,
      (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)4U, .snd = (ಗಾತ್ರ_t)3U }))[0U]);
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)4U,
    (ಗಾತ್ರ_t)4U,
    libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(&old,
      (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)4U, .snd = (ಗಾತ್ರ_t)1U }))[0U]);
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ libcrux_sha3_generic_keccak_pi_80_71(Eurydice_arr_7c *self)
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ libcrux_sha3_generic_keccak_chi_80_71(Eurydice_arr_7c *self)
{
  Eurydice_arr_7c old = self[0U];
  ಗಾಗಿ (ಗಾತ್ರ_t i0 = (ಗಾತ್ರ_t)0U; i0 < (ಗಾತ್ರ_t)5U; i0++)
  {
    ಗಾತ್ರ_t i1 = i0;
    ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)5U; i++)
    {
      ಗಾತ್ರ_t j = i;
      libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
        i1,
        j,
        libcrux_sha3_simd_portable_and_not_xor_d2(libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
            (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = i1, .snd = j }))[0U],
          libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(&old,
            (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = i1, .snd = (j + (ಗಾತ್ರ_t)2U) % (ಗಾತ್ರ_t)5U }))[0U],
          libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(&old,
            (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = i1, .snd = (j + (ಗಾತ್ರ_t)1U) % (ಗಾತ್ರ_t)5U }))[0U]));
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_generic_keccak_iota_80_71(Eurydice_arr_7c *self, ಗಾತ್ರ_t i)
{
  libcrux_sha3_generic_keccak_ಗಣ_80_71(self,
    (ಗಾತ್ರ_t)0U,
    (ಗಾತ್ರ_t)0U,
    libcrux_sha3_simd_portable_xor_constant_d2(libcrux_sha3_generic_keccak_ಸೂಚ್ಯಂಕ_c2_71(self,
        (KRML_CLITERAL(ಗಾತ್ರ_t_x2){ .fst = (ಗಾತ್ರ_t)0U, .snd = (ಗಾತ್ರ_t)0U }))[0U],
      LIBCRUX_SHA3_GENERIC_KECCAK_CONSTANTS_ROUNDCONSTANTS.ದತ್ತಾಂಶ[i]));
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_generic_keccak_keccakf1600_80_71(Eurydice_arr_7c *self)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)24U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_generic_keccak_absorb_final_80_bd(
  Eurydice_arr_7c *self,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_dc *ಒಳಹರಿವು,
  ಗಾತ್ರ_t ಆರಂಭ,
  ಗಾತ್ರ_t len
)
{
  libcrux_sha3_simd_portable_ತುಂಬು_ಕೊನೆಯ_a1_37(self, ಒಳಹರಿವು, ಆರಂಭ, len);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
}

/**
 Absorb
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_portable_incremental_shake128_absorb_final(
  Eurydice_arr_7c *s,
  Eurydice_borrow_ತುಂಡು_u8 data0
)
{
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_dc lvalue = { .ದತ್ತಾಂಶ = { data0 } };
  libcrux_sha3_generic_keccak_absorb_final_80_bd(s, &lvalue, (ಗಾತ್ರ_t)0U, data0.meta);
}

/**
 Create a new SHAKE-256 state object.
*/
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_7c libcrux_sha3_portable_incremental_shake256_init(ಶೂನ್ಯ)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_generic_keccak_new_80_71();
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_block
with const generics
- RATE= 136
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_simd_portable_ತುಂಬು_ಖಂಡ_b2(
  Eurydice_arr_7c *state,
  Eurydice_borrow_ತುಂಡು_u8 ಖಂಡಗಳು,
  ಗಾತ್ರ_t ಆರಂಭ
)
{
  Eurydice_arr_7c state_flat = { .ದತ್ತಾಂಶ = { 0U } };
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)136U / (ಗಾತ್ರ_t)8U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    ಗಾತ್ರ_t ಸ್ಥಾನಾಂತರ = ಆರಂಭ + (ಗಾತ್ರ_t)8U * i0;
    Eurydice_array_u8x8 arr;
    ಸ್ಮರಣೆ_ನಕಲು(arr.ದತ್ತಾಂಶ,
      Eurydice_ತುಂಡು_subslice_shared_c8(ಖಂಡಗಳು,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = ಸ್ಥಾನಾಂತರ, .ಕೊನೆ = ಸ್ಥಾನಾಂತರ + (ಗಾತ್ರ_t)8U })).ptr,
      (ಗಾತ್ರ_t)8U * ಗಾತ್ರ (uint8_t));
    Eurydice_array_u8x8
    uu____0 =
      core_ಫಲಿತಾಂಶ_unwrap_26_e0((
          KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_8e){ .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Ok, .val = { .case_Ok = arr } }
        ));
    state_flat.ದತ್ತಾಂಶ[i0] = core_ಅಂಕೆ_u64_from_le_ಬೈಟುಗಳು(uu____0);
  }
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)136U / (ಗಾತ್ರ_t)8U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    libcrux_sha3_traits_ಗಣ_ij_71(state,
      i0 / (ಗಾತ್ರ_t)5U,
      i0 % (ಗಾತ್ರ_t)5U,
      libcrux_sha3_traits_get_ij_71(state, i0 / (ಗಾತ್ರ_t)5U, i0 % (ಗಾತ್ರ_t)5U)[0U] ^
        state_flat.ದತ್ತಾಂಶ[i0]);
  }
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_last
with const generics
- RATE= 136
- DELIMITER= 31
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_simd_portable_ತುಂಬು_ಕೊನೆಯ_22(
  Eurydice_arr_7c *state,
  Eurydice_borrow_ತುಂಡು_u8 ಖಂಡಗಳು,
  ಗಾತ್ರ_t ಆರಂಭ,
  ಗಾತ್ರ_t len
)
{
  Eurydice_arr_ff ಬಫರ್ = { .ದತ್ತಾಂಶ = { 0U } };
  Eurydice_ತುಂಡು_copy(Eurydice_array_ಗಮ್ಯ_subslice_mut_d42(&ಬಫರ್,
      (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = (ಗಾತ್ರ_t)0U, .ಕೊನೆ = len })),
    Eurydice_ತುಂಡು_subslice_shared_c8(ಖಂಡಗಳು,
      (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = ಆರಂಭ, .ಕೊನೆ = ಆರಂಭ + len })),
    uint8_t);
  ಬಫರ್.ದತ್ತಾಂಶ[len] = 31U;
  ಗಾತ್ರ_t uu____0 = (ಗಾತ್ರ_t)136U - (ಗಾತ್ರ_t)1U;
  ಬಫರ್.ದತ್ತಾಂಶ[uu____0] = (uint32_t)ಬಫರ್.ದತ್ತಾಂಶ[uu____0] | 128U;
  libcrux_sha3_simd_portable_ತುಂಬು_ಖಂಡ_b2(state,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_58(&ಬಫರ್),
    (ಗಾತ್ರ_t)0U);
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_sha3_simd_portable_ತುಂಬು_ಕೊನೆಯ_a1_22(
  Eurydice_arr_7c *self,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_dc *ಒಳಹರಿವು,
  ಗಾತ್ರ_t ಆರಂಭ,
  ಗಾತ್ರ_t len
)
{
  libcrux_sha3_simd_portable_ತುಂಬು_ಕೊನೆಯ_22(self, ಒಳಹರಿವು->ದತ್ತಾಂಶ[0U], ಆರಂಭ, len);
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_generic_keccak_absorb_final_80_bd0(
  Eurydice_arr_7c *self,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_dc *ಒಳಹರಿವು,
  ಗಾತ್ರ_t ಆರಂಭ,
  ಗಾತ್ರ_t len
)
{
  libcrux_sha3_simd_portable_ತುಂಬು_ಕೊನೆಯ_a1_22(self, ಒಳಹರಿವು, ಆರಂಭ, len);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
}

/**
 Absorb some data for SHAKE-256 for the last time
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_portable_incremental_shake256_absorb_final(
  Eurydice_arr_7c *s,
  Eurydice_borrow_ತುಂಡು_u8 ದತ್ತಾಂಶ
)
{
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_dc lvalue = { .ದತ್ತಾಂಶ = { ದತ್ತಾಂಶ } };
  libcrux_sha3_generic_keccak_absorb_final_80_bd0(s, &lvalue, (ಗಾತ್ರ_t)0U, ದತ್ತಾಂಶ.meta);
}

/**
This function found in impl {libcrux_sha3::traits::Absorb<1usize> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.load_block_a1
with const generics
- RATE= 168
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_sha3_simd_portable_ತುಂಬು_ಖಂಡ_a1_60(
  Eurydice_arr_7c *self,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_dc *ಒಳಹರಿವು,
  ಗಾತ್ರ_t ಆರಂಭ
)
{
  libcrux_sha3_simd_portable_ತುಂಬು_ಖಂಡ_60(self, ಒಳಹರಿವು->ದತ್ತಾಂಶ[0U], ಆರಂಭ);
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_generic_keccak_absorb_ಖಂಡ_80_e9(
  Eurydice_arr_7c *self,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_dc *ಒಳಹರಿವು,
  ಗಾತ್ರ_t ಆರಂಭ
)
{
  libcrux_sha3_simd_portable_ತುಂಬು_ಖಂಡ_a1_60(self, ಒಳಹರಿವು, ಆರಂಭ);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.store_block
with const generics
- RATE= 168
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_simd_portable_store_ಖಂಡ_60(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_7c *s,
  Eurydice_mut_borrow_ತುಂಡು_u8 ಹೊರಹೋಗು,
  ಗಾತ್ರ_t ಆರಂಭ,
  ಗಾತ್ರ_t len
)
{
  ಗಾತ್ರ_t octets = len / (ಗಾತ್ರ_t)8U;
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < octets; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    Eurydice_array_u8x8
    ಬೈಟುಗಳು =
      core_ಅಂಕೆ_u64_ಗಮ್ಯ_le_ಬೈಟುಗಳು(libcrux_sha3_traits_get_ij_71(s,
          i0 / (ಗಾತ್ರ_t)5U,
          i0 % (ಗಾತ್ರ_t)5U)[0U]);
    ಗಾತ್ರ_t ಹೊರಹೋಗು_pos = ಆರಂಭ + (ಗಾತ್ರ_t)8U * i0;
    Eurydice_ತುಂಡು_copy(Eurydice_ತುಂಡು_subslice_mut_c8(ಹೊರಹೋಗು,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = ಹೊರಹೋಗು_pos, .ಕೊನೆ = ಹೊರಹೋಗು_pos + (ಗಾತ್ರ_t)8U })),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_6e(&ಬೈಟುಗಳು),
      uint8_t);
  }
  ಗಾತ್ರ_t ಉಳಿದ = len % (ಗಾತ್ರ_t)8U;
  ಆದರೆ (ಉಳಿದ > (ಗಾತ್ರ_t)0U)
  {
    Eurydice_array_u8x8
    ಬೈಟುಗಳು =
      core_ಅಂಕೆ_u64_ಗಮ್ಯ_le_ಬೈಟುಗಳು(libcrux_sha3_traits_get_ij_71(s,
          octets / (ಗಾತ್ರ_t)5U,
          octets % (ಗಾತ್ರ_t)5U)[0U]);
    ಗಾತ್ರ_t ಹೊರಹೋಗು_pos = ಆರಂಭ + len - ಉಳಿದ;
    Eurydice_mut_borrow_ತುಂಡು_u8
    uu____0 =
      Eurydice_ತುಂಡು_subslice_mut_c8(ಹೊರಹೋಗು,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = ಹೊರಹೋಗು_pos, .ಕೊನೆ = ಹೊರಹೋಗು_pos + ಉಳಿದ }));
    Eurydice_ತುಂಡು_copy(uu____0,
      Eurydice_array_ಗಮ್ಯ_subslice_ಗಮ್ಯ_shared_21(&ಬೈಟುಗಳು, ಉಳಿದ),
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_sha3_simd_portable_squeeze_9b_60(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_7c *self,
  Eurydice_mut_borrow_ತುಂಡು_u8 ಹೊರಹೋಗು,
  ಗಾತ್ರ_t ಆರಂಭ,
  ಗಾತ್ರ_t len
)
{
  libcrux_sha3_simd_portable_store_ಖಂಡ_60(self, ಹೊರಹೋಗು, ಆರಂಭ, len);
}

/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.keccak1
with const generics
- RATE= 168
- DELIM= 31
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_sha3_generic_keccak_portable_keccak1_37(
  Eurydice_borrow_ತುಂಡು_u8 ಒಳಹರಿವು,
  Eurydice_mut_borrow_ತುಂಡು_u8 output
)
{
  Eurydice_arr_7c s = libcrux_sha3_generic_keccak_new_80_71();
  ಗಾತ್ರ_t ಒಳಹರಿವು_len = ಒಳಹರಿವು.meta;
  ಗಾತ್ರ_t ಒಳಹರಿವು_ಖಂಡಗಳು = ಒಳಹರಿವು_len / (ಗಾತ್ರ_t)168U;
  ಗಾತ್ರ_t ಒಳಹರಿವು_rem = ಒಳಹರಿವು_len % (ಗಾತ್ರ_t)168U;
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < ಒಳಹರಿವು_ಖಂಡಗಳು; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_dc lvalue = { .ದತ್ತಾಂಶ = { ಒಳಹರಿವು } };
    libcrux_sha3_generic_keccak_absorb_ಖಂಡ_80_e9(&s, &lvalue, i0 * (ಗಾತ್ರ_t)168U);
  }
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_dc lvalue = { .ದತ್ತಾಂಶ = { ಒಳಹರಿವು } };
  libcrux_sha3_generic_keccak_absorb_final_80_bd(&s, &lvalue, ಒಳಹರಿವು_len - ಒಳಹರಿವು_rem, ಒಳಹರಿವು_rem);
  ಗಾತ್ರ_t output_len = output.meta;
  ಗಾತ್ರ_t output_ಖಂಡಗಳು = output_len / (ಗಾತ್ರ_t)168U;
  ಗಾತ್ರ_t output_rem = output_len % (ಗಾತ್ರ_t)168U;
  ಆದರೆ (output_ಖಂಡಗಳು == (ಗಾತ್ರ_t)0U)
  {
    libcrux_sha3_simd_portable_squeeze_9b_60(&s, output, (ಗಾತ್ರ_t)0U, output_len);
  }
  ಇಲ್ಲದಿದ್ದರೆ
  {
    libcrux_sha3_simd_portable_squeeze_9b_60(&s, output, (ಗಾತ್ರ_t)0U, (ಗಾತ್ರ_t)168U);
    ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)1U; i < output_ಖಂಡಗಳು; i++)
    {
      ಗಾತ್ರ_t i0 = i;
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&s);
      libcrux_sha3_simd_portable_squeeze_9b_60(&s, output, i0 * (ಗಾತ್ರ_t)168U, (ಗಾತ್ರ_t)168U);
    }
    ಆದರೆ (output_rem != (ಗಾತ್ರ_t)0U)
    {
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&s);
      libcrux_sha3_simd_portable_squeeze_9b_60(&s, output, output_len - output_rem, output_rem);
    }
  }
}

/**
 A portable SHAKE128 implementation.
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_portable_shake128(
  Eurydice_mut_borrow_ತುಂಡು_u8 digest,
  Eurydice_borrow_ತುಂಡು_u8 ದತ್ತಾಂಶ
)
{
  libcrux_sha3_generic_keccak_portable_keccak1_37(ದತ್ತಾಂಶ, digest);
}

/**
This function found in impl {libcrux_sha3::traits::Absorb<1usize> for libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.simd.portable.load_block_a1
with const generics
- RATE= 136
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_sha3_simd_portable_ತುಂಬು_ಖಂಡ_a1_b2(
  Eurydice_arr_7c *self,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_dc *ಒಳಹರಿವು,
  ಗಾತ್ರ_t ಆರಂಭ
)
{
  libcrux_sha3_simd_portable_ತುಂಬು_ಖಂಡ_b2(self, ಒಳಹರಿವು->ದತ್ತಾಂಶ[0U], ಆರಂಭ);
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_generic_keccak_absorb_ಖಂಡ_80_e90(
  Eurydice_arr_7c *self,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_dc *ಒಳಹರಿವು,
  ಗಾತ್ರ_t ಆರಂಭ
)
{
  libcrux_sha3_simd_portable_ತುಂಬು_ಖಂಡ_a1_b2(self, ಒಳಹರಿವು, ಆರಂಭ);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.store_block
with const generics
- RATE= 136
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_simd_portable_store_ಖಂಡ_b2(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_7c *s,
  Eurydice_mut_borrow_ತುಂಡು_u8 ಹೊರಹೋಗು,
  ಗಾತ್ರ_t ಆರಂಭ,
  ಗಾತ್ರ_t len
)
{
  ಗಾತ್ರ_t octets = len / (ಗಾತ್ರ_t)8U;
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < octets; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    Eurydice_array_u8x8
    ಬೈಟುಗಳು =
      core_ಅಂಕೆ_u64_ಗಮ್ಯ_le_ಬೈಟುಗಳು(libcrux_sha3_traits_get_ij_71(s,
          i0 / (ಗಾತ್ರ_t)5U,
          i0 % (ಗಾತ್ರ_t)5U)[0U]);
    ಗಾತ್ರ_t ಹೊರಹೋಗು_pos = ಆರಂಭ + (ಗಾತ್ರ_t)8U * i0;
    Eurydice_ತುಂಡು_copy(Eurydice_ತುಂಡು_subslice_mut_c8(ಹೊರಹೋಗು,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = ಹೊರಹೋಗು_pos, .ಕೊನೆ = ಹೊರಹೋಗು_pos + (ಗಾತ್ರ_t)8U })),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_6e(&ಬೈಟುಗಳು),
      uint8_t);
  }
  ಗಾತ್ರ_t ಉಳಿದ = len % (ಗಾತ್ರ_t)8U;
  ಆದರೆ (ಉಳಿದ > (ಗಾತ್ರ_t)0U)
  {
    Eurydice_array_u8x8
    ಬೈಟುಗಳು =
      core_ಅಂಕೆ_u64_ಗಮ್ಯ_le_ಬೈಟುಗಳು(libcrux_sha3_traits_get_ij_71(s,
          octets / (ಗಾತ್ರ_t)5U,
          octets % (ಗಾತ್ರ_t)5U)[0U]);
    ಗಾತ್ರ_t ಹೊರಹೋಗು_pos = ಆರಂಭ + len - ಉಳಿದ;
    Eurydice_mut_borrow_ತುಂಡು_u8
    uu____0 =
      Eurydice_ತುಂಡು_subslice_mut_c8(ಹೊರಹೋಗು,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = ಹೊರಹೋಗು_pos, .ಕೊನೆ = ಹೊರಹೋಗು_pos + ಉಳಿದ }));
    Eurydice_ತುಂಡು_copy(uu____0,
      Eurydice_array_ಗಮ್ಯ_subslice_ಗಮ್ಯ_shared_21(&ಬೈಟುಗಳು, ಉಳಿದ),
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_sha3_simd_portable_squeeze_9b_b2(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_7c *self,
  Eurydice_mut_borrow_ತುಂಡು_u8 ಹೊರಹೋಗು,
  ಗಾತ್ರ_t ಆರಂಭ,
  ಗಾತ್ರ_t len
)
{
  libcrux_sha3_simd_portable_store_ಖಂಡ_b2(self, ಹೊರಹೋಗು, ಆರಂಭ, len);
}

/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.keccak1
with const generics
- RATE= 136
- DELIM= 31
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_sha3_generic_keccak_portable_keccak1_22(
  Eurydice_borrow_ತುಂಡು_u8 ಒಳಹರಿವು,
  Eurydice_mut_borrow_ತುಂಡು_u8 output
)
{
  Eurydice_arr_7c s = libcrux_sha3_generic_keccak_new_80_71();
  ಗಾತ್ರ_t ಒಳಹರಿವು_len = ಒಳಹರಿವು.meta;
  ಗಾತ್ರ_t ಒಳಹರಿವು_ಖಂಡಗಳು = ಒಳಹರಿವು_len / (ಗಾತ್ರ_t)136U;
  ಗಾತ್ರ_t ಒಳಹರಿವು_rem = ಒಳಹರಿವು_len % (ಗಾತ್ರ_t)136U;
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < ಒಳಹರಿವು_ಖಂಡಗಳು; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_dc lvalue = { .ದತ್ತಾಂಶ = { ಒಳಹರಿವು } };
    libcrux_sha3_generic_keccak_absorb_ಖಂಡ_80_e90(&s, &lvalue, i0 * (ಗಾತ್ರ_t)136U);
  }
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_dc lvalue = { .ದತ್ತಾಂಶ = { ಒಳಹರಿವು } };
  libcrux_sha3_generic_keccak_absorb_final_80_bd0(&s, &lvalue, ಒಳಹರಿವು_len - ಒಳಹರಿವು_rem, ಒಳಹರಿವು_rem);
  ಗಾತ್ರ_t output_len = output.meta;
  ಗಾತ್ರ_t output_ಖಂಡಗಳು = output_len / (ಗಾತ್ರ_t)136U;
  ಗಾತ್ರ_t output_rem = output_len % (ಗಾತ್ರ_t)136U;
  ಆದರೆ (output_ಖಂಡಗಳು == (ಗಾತ್ರ_t)0U)
  {
    libcrux_sha3_simd_portable_squeeze_9b_b2(&s, output, (ಗಾತ್ರ_t)0U, output_len);
  }
  ಇಲ್ಲದಿದ್ದರೆ
  {
    libcrux_sha3_simd_portable_squeeze_9b_b2(&s, output, (ಗಾತ್ರ_t)0U, (ಗಾತ್ರ_t)136U);
    ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)1U; i < output_ಖಂಡಗಳು; i++)
    {
      ಗಾತ್ರ_t i0 = i;
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&s);
      libcrux_sha3_simd_portable_squeeze_9b_b2(&s, output, i0 * (ಗಾತ್ರ_t)136U, (ಗಾತ್ರ_t)136U);
    }
    ಆದರೆ (output_rem != (ಗಾತ್ರ_t)0U)
    {
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&s);
      libcrux_sha3_simd_portable_squeeze_9b_b2(&s, output, output_len - output_rem, output_rem);
    }
  }
}

/**
 A portable SHAKE256 implementation.
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_portable_shake256(
  Eurydice_mut_borrow_ತುಂಡು_u8 digest,
  Eurydice_borrow_ತುಂಡು_u8 ದತ್ತಾಂಶ
)
{
  libcrux_sha3_generic_keccak_portable_keccak1_22(ದತ್ತಾಂಶ, digest);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.squeeze_first_block_b4
with const generics
- RATE= 136
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_generic_keccak_portable_squeeze_ಮೊದಲ_ಖಂಡ_b4_b2(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_7c *self,
  Eurydice_mut_borrow_ತುಂಡು_u8 ಹೊರಹೋಗು
)
{
  libcrux_sha3_simd_portable_squeeze_9b_b2(self, ಹೊರಹೋಗು, (ಗಾತ್ರ_t)0U, (ಗಾತ್ರ_t)136U);
}

/**
 Squeeze the first SHAKE-256 block
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_portable_incremental_shake256_squeeze_ಮೊದಲ_ಖಂಡ(
  Eurydice_arr_7c *s,
  Eurydice_mut_borrow_ತುಂಡು_u8 ಹೊರಹೋಗು
)
{
  libcrux_sha3_generic_keccak_portable_squeeze_ಮೊದಲ_ಖಂಡ_b4_b2(&s[0U], ಹೊರಹೋಗು);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.squeeze_first_five_blocks_b4
with const generics
- RATE= 168
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_generic_keccak_portable_squeeze_ಮೊದಲ_five_ಖಂಡಗಳು_b4_60(
  Eurydice_arr_7c *self,
  Eurydice_mut_borrow_ತುಂಡು_u8 ಹೊರಹೋಗು
)
{
  libcrux_sha3_simd_portable_squeeze_9b_60(self, ಹೊರಹೋಗು, (ಗಾತ್ರ_t)0U, (ಗಾತ್ರ_t)168U);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
  libcrux_sha3_simd_portable_squeeze_9b_60(self, ಹೊರಹೋಗು, (ಗಾತ್ರ_t)168U, (ಗಾತ್ರ_t)168U);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
  libcrux_sha3_simd_portable_squeeze_9b_60(self, ಹೊರಹೋಗು, (ಗಾತ್ರ_t)2U * (ಗಾತ್ರ_t)168U, (ಗಾತ್ರ_t)168U);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
  libcrux_sha3_simd_portable_squeeze_9b_60(self, ಹೊರಹೋಗು, (ಗಾತ್ರ_t)3U * (ಗಾತ್ರ_t)168U, (ಗಾತ್ರ_t)168U);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
  libcrux_sha3_simd_portable_squeeze_9b_60(self, ಹೊರಹೋಗು, (ಗಾತ್ರ_t)4U * (ಗಾತ್ರ_t)168U, (ಗಾತ್ರ_t)168U);
}

/**
 Squeeze five blocks
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_portable_incremental_shake128_squeeze_ಮೊದಲ_five_ಖಂಡಗಳು(
  Eurydice_arr_7c *s,
  Eurydice_mut_borrow_ತುಂಡು_u8 out0
)
{
  libcrux_sha3_generic_keccak_portable_squeeze_ಮೊದಲ_five_ಖಂಡಗಳು_b4_60(s, out0);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.squeeze_next_block_b4
with const generics
- RATE= 168
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_generic_keccak_portable_squeeze_ಮುಂದಿನ_ಖಂಡ_b4_60(
  Eurydice_arr_7c *self,
  Eurydice_mut_borrow_ತುಂಡು_u8 ಹೊರಹೋಗು,
  ಗಾತ್ರ_t ಆರಂಭ
)
{
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
  libcrux_sha3_simd_portable_squeeze_9b_60(self, ಹೊರಹೋಗು, ಆರಂಭ, (ಗಾತ್ರ_t)168U);
}

/**
 Squeeze another block
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_portable_incremental_shake128_squeeze_ಮುಂದಿನ_ಖಂಡ(
  Eurydice_arr_7c *s,
  Eurydice_mut_borrow_ತುಂಡು_u8 out0
)
{
  libcrux_sha3_generic_keccak_portable_squeeze_ಮುಂದಿನ_ಖಂಡ_b4_60(s, out0, (ಗಾತ್ರ_t)0U);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.squeeze_next_block_b4
with const generics
- RATE= 136
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_generic_keccak_portable_squeeze_ಮುಂದಿನ_ಖಂಡ_b4_b2(
  Eurydice_arr_7c *self,
  Eurydice_mut_borrow_ತುಂಡು_u8 ಹೊರಹೋಗು,
  ಗಾತ್ರ_t ಆರಂಭ
)
{
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
  libcrux_sha3_simd_portable_squeeze_9b_b2(self, ಹೊರಹೋಗು, ಆರಂಭ, (ಗಾತ್ರ_t)136U);
}

/**
 Squeeze the next SHAKE-256 block
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_portable_incremental_shake256_squeeze_ಮುಂದಿನ_ಖಂಡ(
  Eurydice_arr_7c *s,
  Eurydice_mut_borrow_ತುಂಡು_u8 ಹೊರಹೋಗು
)
{
  libcrux_sha3_generic_keccak_portable_squeeze_ಮುಂದಿನ_ಖಂಡ_b4_b2(s, ಹೊರಹೋಗು, (ಗಾತ್ರ_t)0U);
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಗಾತ್ರ_t
libcrux_sha3_generic_keccak_xof_fill_ಬಫರ್_35_e9(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *self,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_dc *inputs
)
{
  ಗಾತ್ರ_t ಒಳಹರಿವು_len = inputs->ದತ್ತಾಂಶ->meta;
  ಗಾತ್ರ_t uu____0;
  ಆದರೆ (self->buf_len != (ಗಾತ್ರ_t)0U)
  {
    ಆದರೆ (ಒಳಹರಿವು_len >= (ಗಾತ್ರ_t)136U - self->buf_len)
    {
      ಗಾತ್ರ_t consumed = (ಗಾತ್ರ_t)136U - self->buf_len;
      ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)1U; i++)
      {
        ಗಾತ್ರ_t i0 = i;
        Eurydice_ತುಂಡು_copy(Eurydice_array_ಗಮ್ಯ_subslice_from_mut_5f(&self->buf.ದತ್ತಾಂಶ[i0],
            self->buf_len),
          Eurydice_ತುಂಡು_subslice_ಗಮ್ಯ_shared_72(inputs->ದತ್ತಾಂಶ[i0], consumed),
          uint8_t);
      }
      self->buf_len = (ಗಾತ್ರ_t)136U;
      uu____0 = consumed;
    }
    ಇಲ್ಲದಿದ್ದರೆ
    {
      uu____0 = (ಗಾತ್ರ_t)0U;
    }
  }
  ಇಲ್ಲದಿದ್ದರೆ
  {
    uu____0 = (ಗಾತ್ರ_t)0U;
  }
  ಹಿಂತಿರುಗಿ uu____0;
}

/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.buf_to_slices.closure
with const generics
- $1size_t
- $136size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಸ್ಥಿರಾಂಕ Eurydice_arr_0b *libcrux_sha3_generic_keccak_xof_buf_ಗಮ್ಯ_slices_ಆವರಣ_94;

/**
This function found in impl {core::ops::function::FnMut<(usize), &'_ ([u8])> for libcrux_sha3::generic_keccak::xof::buf_to_slices::closure<0, PARALLEL_LANES, RATE>}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.buf_to_slices.call_mut_2a
with const generics
- PARALLEL_LANES= 1
- RATE= 136
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
libcrux_sha3_generic_keccak_xof_buf_ಗಮ್ಯ_slices_call_mut_2a_81(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_0b **_,
  ಗಾತ್ರ_t tupled_ವಾದಗಳು
)
{
  ಗಾತ್ರ_t i = tupled_ವಾದಗಳು;
  ಹಿಂತಿರುಗಿ
    core_array_T_N_as_ತುಂಡು((ಗಾತ್ರ_t)136U,
      &_[0U]->ದತ್ತಾಂಶ[i],
      uint8_t,
      Eurydice_borrow_ತುಂಡು_u8);
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
libcrux_sha3_generic_keccak_xof_buf_ಗಮ್ಯ_slices_call_once_fa_81(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_0b *_,
  ಗಾತ್ರ_t _0
)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_generic_keccak_xof_buf_ಗಮ್ಯ_slices_call_mut_2a_81(&_, _0);
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
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_dc
libcrux_sha3_generic_keccak_xof_buf_ಗಮ್ಯ_slices_81(ಸ್ಥಿರಾಂಕ Eurydice_arr_0b *buf)
{
  Eurydice_arr_dc arr_struct;
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)1U; i++)
  {
    arr_struct.ದತ್ತಾಂಶ[i] = libcrux_sha3_generic_keccak_xof_buf_ಗಮ್ಯ_slices_call_mut_2a_81(&buf, i);
  }
  ಹಿಂತಿರುಗಿ arr_struct;
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಗಾತ್ರ_t
libcrux_sha3_generic_keccak_xof_absorb_ತುಂಬಿದ_35_e9(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *self,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_dc *inputs
)
{
  ಗಾತ್ರ_t consumed = libcrux_sha3_generic_keccak_xof_fill_ಬಫರ್_35_e9(self, inputs);
  ಆದರೆ (self->buf_len == (ಗಾತ್ರ_t)136U)
  {
    Eurydice_arr_dc borrowed = libcrux_sha3_generic_keccak_xof_buf_ಗಮ್ಯ_slices_81(&self->buf);
    libcrux_sha3_simd_portable_ತುಂಬು_ಖಂಡ_a1_b2(&self->inner, &borrowed, (ಗಾತ್ರ_t)0U);
    libcrux_sha3_generic_keccak_keccakf1600_80_71(&self->inner);
    self->buf_len = (ಗಾತ್ರ_t)0U;
  }
  ಗಾತ್ರ_t ಒಳಹರಿವು_ಗಮ್ಯ_consume = inputs->ದತ್ತಾಂಶ->meta - consumed;
  ಗಾತ್ರ_t ಅಂಕೆ_ಖಂಡಗಳು = ಒಳಹರಿವು_ಗಮ್ಯ_consume / (ಗಾತ್ರ_t)136U;
  ಗಾತ್ರ_t remainder = ಒಳಹರಿವು_ಗಮ್ಯ_consume % (ಗಾತ್ರ_t)136U;
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < ಅಂಕೆ_ಖಂಡಗಳು; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    ಗಾತ್ರ_t ಆರಂಭ = i0 * (ಗಾತ್ರ_t)136U + consumed;
    libcrux_sha3_simd_portable_ತುಂಬು_ಖಂಡ_a1_b2(&self->inner, inputs, ಆರಂಭ);
    libcrux_sha3_generic_keccak_keccakf1600_80_71(&self->inner);
  }
  ಹಿಂತಿರುಗಿ remainder;
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_generic_keccak_xof_absorb_35_e9(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *self,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_dc *inputs
)
{
  ಗಾತ್ರ_t remainder = libcrux_sha3_generic_keccak_xof_absorb_ತುಂಬಿದ_35_e9(self, inputs);
  ಆದರೆ (remainder > (ಗಾತ್ರ_t)0U)
  {
    ಗಾತ್ರ_t ಒಳಹರಿವು_len = inputs->ದತ್ತಾಂಶ->meta;
    ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)1U; i++)
    {
      ಗಾತ್ರ_t i0 = i;
      Eurydice_ತುಂಡು_copy(Eurydice_array_ಗಮ್ಯ_subslice_mut_d42(&self->buf.ದತ್ತಾಂಶ[i0],
          (
            KRML_CLITERAL(core_ops_range_Range_87){
              .ಆರಂಭ = self->buf_len,
              .ಕೊನೆ = self->buf_len + remainder
            }
          )),
        Eurydice_ತುಂಡು_subslice_shared_c8(inputs->ದತ್ತಾಂಶ[i0],
          (
            KRML_CLITERAL(core_ops_range_Range_87){
              .ಆರಂಭ = ಒಳಹರಿವು_len - remainder,
              .ಕೊನೆ = ಒಳಹರಿವು_len
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_sha3_portable_incremental_absorb_42(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *self,
  Eurydice_borrow_ತುಂಡು_u8 ಒಳಹರಿವು
)
{
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_dc lvalue = { .ದತ್ತಾಂಶ = { ಒಳಹರಿವು } };
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_generic_keccak_xof_absorb_final_35_bd(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *self,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_dc *inputs
)
{
  libcrux_sha3_generic_keccak_xof_absorb_35_e9(self, inputs);
  Eurydice_arr_dc borrowed = libcrux_sha3_generic_keccak_xof_buf_ಗಮ್ಯ_slices_81(&self->buf);
  libcrux_sha3_simd_portable_ತುಂಬು_ಕೊನೆಯ_a1_22(&self->inner, &borrowed, (ಗಾತ್ರ_t)0U, self->buf_len);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(&self->inner);
}

/**
 Shake256 absorb final
*/
/**
This function found in impl {libcrux_sha3::portable::incremental::Xof<136usize> for libcrux_sha3::portable::incremental::Shake256Xof}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_sha3_portable_incremental_absorb_final_42(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *self,
  Eurydice_borrow_ತುಂಡು_u8 ಒಳಹರಿವು
)
{
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_dc lvalue = { .ದತ್ತಾಂಶ = { ಒಳಹರಿವು } };
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_ff libcrux_sha3_generic_keccak_xof_zero_ಖಂಡ_35_e9(ಶೂನ್ಯ)
{
  ಹಿಂತಿರುಗಿ (KRML_CLITERAL(Eurydice_arr_ff){ .ದತ್ತಾಂಶ = { 0U } });
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
libcrux_sha3_generic_keccak_xof_new_35_e9(ಶೂನ್ಯ)
{
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d lit;
  lit.inner = libcrux_sha3_generic_keccak_new_80_71();
  Eurydice_arr_ff repeat_ಅಭಿವ್ಯಕ್ತಿ[1U];
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)1U; i++)
  {
    repeat_ಅಭಿವ್ಯಕ್ತಿ[i] = libcrux_sha3_generic_keccak_xof_zero_ಖಂಡ_35_e9();
  }
  ಸ್ಮರಣೆ_ನಕಲು(lit.buf.ದತ್ತಾಂಶ, repeat_ಅಭಿವ್ಯಕ್ತಿ, (ಗಾತ್ರ_t)1U * ಗಾತ್ರ (Eurydice_arr_ff));
  lit.buf_len = (ಗಾತ್ರ_t)0U;
  lit.sponge = false;
  ಹಿಂತಿರುಗಿ lit;
}

/**
 Shake256 new state
*/
/**
This function found in impl {libcrux_sha3::portable::incremental::Xof<136usize> for libcrux_sha3::portable::incremental::Shake256Xof}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
libcrux_sha3_portable_incremental_new_42(ಶೂನ್ಯ)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_generic_keccak_xof_new_35_e9();
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_generic_keccak_xof_squeeze_85_76(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *self,
  Eurydice_mut_borrow_ತುಂಡು_u8 ಹೊರಹೋಗು
)
{
  ಗಾತ್ರ_t ಹೊರಹೋಗು_len = ಹೊರಹೋಗು.meta;
  ಆದರೆ (!(ಹೊರಹೋಗು_len == (ಗಾತ್ರ_t)0U))
  {
    ಆದರೆ (self->sponge)
    {
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&self->inner);
    }
    ಆದರೆ (ಹೊರಹೋಗು_len > (ಗಾತ್ರ_t)0U)
    {
      ಗಾತ್ರ_t ಖಂಡಗಳು = ಹೊರಹೋಗು_len / (ಗಾತ್ರ_t)136U;
      ಗಾತ್ರ_t ಕೊನೆಯ = ಹೊರಹೋಗು_len - ಹೊರಹೋಗು_len % (ಗಾತ್ರ_t)136U;
      ಆದರೆ (ಖಂಡಗಳು == (ಗಾತ್ರ_t)0U)
      {
        libcrux_sha3_simd_portable_squeeze_9b_b2(&self->inner, ಹೊರಹೋಗು, (ಗಾತ್ರ_t)0U, ಹೊರಹೋಗು_len);
      }
      ಇಲ್ಲದಿದ್ದರೆ
      {
        libcrux_sha3_simd_portable_squeeze_9b_b2(&self->inner, ಹೊರಹೋಗು, (ಗಾತ್ರ_t)0U, (ಗಾತ್ರ_t)136U);
        ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)1U; i < ಖಂಡಗಳು; i++)
        {
          ಗಾತ್ರ_t i0 = i;
          libcrux_sha3_generic_keccak_keccakf1600_80_71(&self->inner);
          libcrux_sha3_simd_portable_squeeze_9b_b2(&self->inner,
            ಹೊರಹೋಗು,
            i0 * (ಗಾತ್ರ_t)136U,
            (ಗಾತ್ರ_t)136U);
        }
        ಆದರೆ (ಕೊನೆಯ < ಹೊರಹೋಗು_len)
        {
          libcrux_sha3_generic_keccak_keccakf1600_80_71(&self->inner);
          libcrux_sha3_simd_portable_squeeze_9b_b2(&self->inner, ಹೊರಹೋಗು, ಕೊನೆಯ, ಹೊರಹೋಗು_len - ಕೊನೆಯ);
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_sha3_portable_incremental_squeeze_42(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *self,
  Eurydice_mut_borrow_ತುಂಡು_u8 ಹೊರಹೋಗು
)
{
  libcrux_sha3_generic_keccak_xof_squeeze_85_76(self, ಹೊರಹೋಗು);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_block
with const generics
- RATE= 72
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_simd_portable_ತುಂಬು_ಖಂಡ_c6(
  Eurydice_arr_7c *state,
  Eurydice_borrow_ತುಂಡು_u8 ಖಂಡಗಳು,
  ಗಾತ್ರ_t ಆರಂಭ
)
{
  Eurydice_arr_7c state_flat = { .ದತ್ತಾಂಶ = { 0U } };
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)72U / (ಗಾತ್ರ_t)8U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    ಗಾತ್ರ_t ಸ್ಥಾನಾಂತರ = ಆರಂಭ + (ಗಾತ್ರ_t)8U * i0;
    Eurydice_array_u8x8 arr;
    ಸ್ಮರಣೆ_ನಕಲು(arr.ದತ್ತಾಂಶ,
      Eurydice_ತುಂಡು_subslice_shared_c8(ಖಂಡಗಳು,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = ಸ್ಥಾನಾಂತರ, .ಕೊನೆ = ಸ್ಥಾನಾಂತರ + (ಗಾತ್ರ_t)8U })).ptr,
      (ಗಾತ್ರ_t)8U * ಗಾತ್ರ (uint8_t));
    Eurydice_array_u8x8
    uu____0 =
      core_ಫಲಿತಾಂಶ_unwrap_26_e0((
          KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_8e){ .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Ok, .val = { .case_Ok = arr } }
        ));
    state_flat.ದತ್ತಾಂಶ[i0] = core_ಅಂಕೆ_u64_from_le_ಬೈಟುಗಳು(uu____0);
  }
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)72U / (ಗಾತ್ರ_t)8U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    libcrux_sha3_traits_ಗಣ_ij_71(state,
      i0 / (ಗಾತ್ರ_t)5U,
      i0 % (ಗಾತ್ರ_t)5U,
      libcrux_sha3_traits_get_ij_71(state, i0 / (ಗಾತ್ರ_t)5U, i0 % (ಗಾತ್ರ_t)5U)[0U] ^
        state_flat.ದತ್ತಾಂಶ[i0]);
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_sha3_simd_portable_ತುಂಬು_ಖಂಡ_a1_c6(
  Eurydice_arr_7c *self,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_dc *ಒಳಹರಿವು,
  ಗಾತ್ರ_t ಆರಂಭ
)
{
  libcrux_sha3_simd_portable_ತುಂಬು_ಖಂಡ_c6(self, ಒಳಹರಿವು->ದತ್ತಾಂಶ[0U], ಆರಂಭ);
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_generic_keccak_absorb_ಖಂಡ_80_e91(
  Eurydice_arr_7c *self,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_dc *ಒಳಹರಿವು,
  ಗಾತ್ರ_t ಆರಂಭ
)
{
  libcrux_sha3_simd_portable_ತುಂಬು_ಖಂಡ_a1_c6(self, ಒಳಹರಿವು, ಆರಂಭ);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_last
with const generics
- RATE= 72
- DELIMITER= 6
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_simd_portable_ತುಂಬು_ಕೊನೆಯ_dc(
  Eurydice_arr_7c *state,
  Eurydice_borrow_ತುಂಡು_u8 ಖಂಡಗಳು,
  ಗಾತ್ರ_t ಆರಂಭ,
  ಗಾತ್ರ_t len
)
{
  Eurydice_arr_ab ಬಫರ್ = { .ದತ್ತಾಂಶ = { 0U } };
  Eurydice_ತುಂಡು_copy(Eurydice_array_ಗಮ್ಯ_subslice_mut_d43(&ಬಫರ್,
      (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = (ಗಾತ್ರ_t)0U, .ಕೊನೆ = len })),
    Eurydice_ತುಂಡು_subslice_shared_c8(ಖಂಡಗಳು,
      (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = ಆರಂಭ, .ಕೊನೆ = ಆರಂಭ + len })),
    uint8_t);
  ಬಫರ್.ದತ್ತಾಂಶ[len] = 6U;
  ಗಾತ್ರ_t uu____0 = (ಗಾತ್ರ_t)72U - (ಗಾತ್ರ_t)1U;
  ಬಫರ್.ದತ್ತಾಂಶ[uu____0] = (uint32_t)ಬಫರ್.ದತ್ತಾಂಶ[uu____0] | 128U;
  libcrux_sha3_simd_portable_ತುಂಬು_ಖಂಡ_c6(state,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_e2(&ಬಫರ್),
    (ಗಾತ್ರ_t)0U);
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_sha3_simd_portable_ತುಂಬು_ಕೊನೆಯ_a1_dc(
  Eurydice_arr_7c *self,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_dc *ಒಳಹರಿವು,
  ಗಾತ್ರ_t ಆರಂಭ,
  ಗಾತ್ರ_t len
)
{
  libcrux_sha3_simd_portable_ತುಂಬು_ಕೊನೆಯ_dc(self, ಒಳಹರಿವು->ದತ್ತಾಂಶ[0U], ಆರಂಭ, len);
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_generic_keccak_absorb_final_80_bd1(
  Eurydice_arr_7c *self,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_dc *ಒಳಹರಿವು,
  ಗಾತ್ರ_t ಆರಂಭ,
  ಗಾತ್ರ_t len
)
{
  libcrux_sha3_simd_portable_ತುಂಬು_ಕೊನೆಯ_a1_dc(self, ಒಳಹರಿವು, ಆರಂಭ, len);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.store_block
with const generics
- RATE= 72
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_simd_portable_store_ಖಂಡ_c6(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_7c *s,
  Eurydice_mut_borrow_ತುಂಡು_u8 ಹೊರಹೋಗು,
  ಗಾತ್ರ_t ಆರಂಭ,
  ಗಾತ್ರ_t len
)
{
  ಗಾತ್ರ_t octets = len / (ಗಾತ್ರ_t)8U;
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < octets; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    Eurydice_array_u8x8
    ಬೈಟುಗಳು =
      core_ಅಂಕೆ_u64_ಗಮ್ಯ_le_ಬೈಟುಗಳು(libcrux_sha3_traits_get_ij_71(s,
          i0 / (ಗಾತ್ರ_t)5U,
          i0 % (ಗಾತ್ರ_t)5U)[0U]);
    ಗಾತ್ರ_t ಹೊರಹೋಗು_pos = ಆರಂಭ + (ಗಾತ್ರ_t)8U * i0;
    Eurydice_ತುಂಡು_copy(Eurydice_ತುಂಡು_subslice_mut_c8(ಹೊರಹೋಗು,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = ಹೊರಹೋಗು_pos, .ಕೊನೆ = ಹೊರಹೋಗು_pos + (ಗಾತ್ರ_t)8U })),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_6e(&ಬೈಟುಗಳು),
      uint8_t);
  }
  ಗಾತ್ರ_t ಉಳಿದ = len % (ಗಾತ್ರ_t)8U;
  ಆದರೆ (ಉಳಿದ > (ಗಾತ್ರ_t)0U)
  {
    Eurydice_array_u8x8
    ಬೈಟುಗಳು =
      core_ಅಂಕೆ_u64_ಗಮ್ಯ_le_ಬೈಟುಗಳು(libcrux_sha3_traits_get_ij_71(s,
          octets / (ಗಾತ್ರ_t)5U,
          octets % (ಗಾತ್ರ_t)5U)[0U]);
    ಗಾತ್ರ_t ಹೊರಹೋಗು_pos = ಆರಂಭ + len - ಉಳಿದ;
    Eurydice_mut_borrow_ತುಂಡು_u8
    uu____0 =
      Eurydice_ತುಂಡು_subslice_mut_c8(ಹೊರಹೋಗು,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = ಹೊರಹೋಗು_pos, .ಕೊನೆ = ಹೊರಹೋಗು_pos + ಉಳಿದ }));
    Eurydice_ತುಂಡು_copy(uu____0,
      Eurydice_array_ಗಮ್ಯ_subslice_ಗಮ್ಯ_shared_21(&ಬೈಟುಗಳು, ಉಳಿದ),
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_sha3_simd_portable_squeeze_9b_c6(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_7c *self,
  Eurydice_mut_borrow_ತುಂಡು_u8 ಹೊರಹೋಗು,
  ಗಾತ್ರ_t ಆರಂಭ,
  ಗಾತ್ರ_t len
)
{
  libcrux_sha3_simd_portable_store_ಖಂಡ_c6(self, ಹೊರಹೋಗು, ಆರಂಭ, len);
}

/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.keccak1
with const generics
- RATE= 72
- DELIM= 6
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_sha3_generic_keccak_portable_keccak1_dc(
  Eurydice_borrow_ತುಂಡು_u8 ಒಳಹರಿವು,
  Eurydice_mut_borrow_ತುಂಡು_u8 output
)
{
  Eurydice_arr_7c s = libcrux_sha3_generic_keccak_new_80_71();
  ಗಾತ್ರ_t ಒಳಹರಿವು_len = ಒಳಹರಿವು.meta;
  ಗಾತ್ರ_t ಒಳಹರಿವು_ಖಂಡಗಳು = ಒಳಹರಿವು_len / (ಗಾತ್ರ_t)72U;
  ಗಾತ್ರ_t ಒಳಹರಿವು_rem = ಒಳಹರಿವು_len % (ಗಾತ್ರ_t)72U;
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < ಒಳಹರಿವು_ಖಂಡಗಳು; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_dc lvalue = { .ದತ್ತಾಂಶ = { ಒಳಹರಿವು } };
    libcrux_sha3_generic_keccak_absorb_ಖಂಡ_80_e91(&s, &lvalue, i0 * (ಗಾತ್ರ_t)72U);
  }
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_dc lvalue = { .ದತ್ತಾಂಶ = { ಒಳಹರಿವು } };
  libcrux_sha3_generic_keccak_absorb_final_80_bd1(&s, &lvalue, ಒಳಹರಿವು_len - ಒಳಹರಿವು_rem, ಒಳಹರಿವು_rem);
  ಗಾತ್ರ_t output_len = output.meta;
  ಗಾತ್ರ_t output_ಖಂಡಗಳು = output_len / (ಗಾತ್ರ_t)72U;
  ಗಾತ್ರ_t output_rem = output_len % (ಗಾತ್ರ_t)72U;
  ಆದರೆ (output_ಖಂಡಗಳು == (ಗಾತ್ರ_t)0U)
  {
    libcrux_sha3_simd_portable_squeeze_9b_c6(&s, output, (ಗಾತ್ರ_t)0U, output_len);
  }
  ಇಲ್ಲದಿದ್ದರೆ
  {
    libcrux_sha3_simd_portable_squeeze_9b_c6(&s, output, (ಗಾತ್ರ_t)0U, (ಗಾತ್ರ_t)72U);
    ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)1U; i < output_ಖಂಡಗಳು; i++)
    {
      ಗಾತ್ರ_t i0 = i;
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&s);
      libcrux_sha3_simd_portable_squeeze_9b_c6(&s, output, i0 * (ಗಾತ್ರ_t)72U, (ಗಾತ್ರ_t)72U);
    }
    ಆದರೆ (output_rem != (ಗಾತ್ರ_t)0U)
    {
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&s);
      libcrux_sha3_simd_portable_squeeze_9b_c6(&s, output, output_len - output_rem, output_rem);
    }
  }
}

/**
 A portable SHA3 512 implementation.
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_portable_sha512(
  Eurydice_mut_borrow_ತುಂಡು_u8 digest,
  Eurydice_borrow_ತುಂಡು_u8 ದತ್ತಾಂಶ
)
{
  libcrux_sha3_generic_keccak_portable_keccak1_dc(ದತ್ತಾಂಶ, digest);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_last
with const generics
- RATE= 136
- DELIMITER= 6
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_simd_portable_ತುಂಬು_ಕೊನೆಯ_220(
  Eurydice_arr_7c *state,
  Eurydice_borrow_ತುಂಡು_u8 ಖಂಡಗಳು,
  ಗಾತ್ರ_t ಆರಂಭ,
  ಗಾತ್ರ_t len
)
{
  Eurydice_arr_ff ಬಫರ್ = { .ದತ್ತಾಂಶ = { 0U } };
  Eurydice_ತುಂಡು_copy(Eurydice_array_ಗಮ್ಯ_subslice_mut_d42(&ಬಫರ್,
      (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = (ಗಾತ್ರ_t)0U, .ಕೊನೆ = len })),
    Eurydice_ತುಂಡು_subslice_shared_c8(ಖಂಡಗಳು,
      (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = ಆರಂಭ, .ಕೊನೆ = ಆರಂಭ + len })),
    uint8_t);
  ಬಫರ್.ದತ್ತಾಂಶ[len] = 6U;
  ಗಾತ್ರ_t uu____0 = (ಗಾತ್ರ_t)136U - (ಗಾತ್ರ_t)1U;
  ಬಫರ್.ದತ್ತಾಂಶ[uu____0] = (uint32_t)ಬಫರ್.ದತ್ತಾಂಶ[uu____0] | 128U;
  libcrux_sha3_simd_portable_ತುಂಬು_ಖಂಡ_b2(state,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_58(&ಬಫರ್),
    (ಗಾತ್ರ_t)0U);
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_sha3_simd_portable_ತುಂಬು_ಕೊನೆಯ_a1_220(
  Eurydice_arr_7c *self,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_dc *ಒಳಹರಿವು,
  ಗಾತ್ರ_t ಆರಂಭ,
  ಗಾತ್ರ_t len
)
{
  libcrux_sha3_simd_portable_ತುಂಬು_ಕೊನೆಯ_220(self, ಒಳಹರಿವು->ದತ್ತಾಂಶ[0U], ಆರಂಭ, len);
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_generic_keccak_absorb_final_80_bd2(
  Eurydice_arr_7c *self,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_dc *ಒಳಹರಿವು,
  ಗಾತ್ರ_t ಆರಂಭ,
  ಗಾತ್ರ_t len
)
{
  libcrux_sha3_simd_portable_ತುಂಬು_ಕೊನೆಯ_a1_220(self, ಒಳಹರಿವು, ಆರಂಭ, len);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
}

/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.keccak1
with const generics
- RATE= 136
- DELIM= 6
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_sha3_generic_keccak_portable_keccak1_220(
  Eurydice_borrow_ತುಂಡು_u8 ಒಳಹರಿವು,
  Eurydice_mut_borrow_ತುಂಡು_u8 output
)
{
  Eurydice_arr_7c s = libcrux_sha3_generic_keccak_new_80_71();
  ಗಾತ್ರ_t ಒಳಹರಿವು_len = ಒಳಹರಿವು.meta;
  ಗಾತ್ರ_t ಒಳಹರಿವು_ಖಂಡಗಳು = ಒಳಹರಿವು_len / (ಗಾತ್ರ_t)136U;
  ಗಾತ್ರ_t ಒಳಹರಿವು_rem = ಒಳಹರಿವು_len % (ಗಾತ್ರ_t)136U;
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < ಒಳಹರಿವು_ಖಂಡಗಳು; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_dc lvalue = { .ದತ್ತಾಂಶ = { ಒಳಹರಿವು } };
    libcrux_sha3_generic_keccak_absorb_ಖಂಡ_80_e90(&s, &lvalue, i0 * (ಗಾತ್ರ_t)136U);
  }
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_dc lvalue = { .ದತ್ತಾಂಶ = { ಒಳಹರಿವು } };
  libcrux_sha3_generic_keccak_absorb_final_80_bd2(&s, &lvalue, ಒಳಹರಿವು_len - ಒಳಹರಿವು_rem, ಒಳಹರಿವು_rem);
  ಗಾತ್ರ_t output_len = output.meta;
  ಗಾತ್ರ_t output_ಖಂಡಗಳು = output_len / (ಗಾತ್ರ_t)136U;
  ಗಾತ್ರ_t output_rem = output_len % (ಗಾತ್ರ_t)136U;
  ಆದರೆ (output_ಖಂಡಗಳು == (ಗಾತ್ರ_t)0U)
  {
    libcrux_sha3_simd_portable_squeeze_9b_b2(&s, output, (ಗಾತ್ರ_t)0U, output_len);
  }
  ಇಲ್ಲದಿದ್ದರೆ
  {
    libcrux_sha3_simd_portable_squeeze_9b_b2(&s, output, (ಗಾತ್ರ_t)0U, (ಗಾತ್ರ_t)136U);
    ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)1U; i < output_ಖಂಡಗಳು; i++)
    {
      ಗಾತ್ರ_t i0 = i;
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&s);
      libcrux_sha3_simd_portable_squeeze_9b_b2(&s, output, i0 * (ಗಾತ್ರ_t)136U, (ಗಾತ್ರ_t)136U);
    }
    ಆದರೆ (output_rem != (ಗಾತ್ರ_t)0U)
    {
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&s);
      libcrux_sha3_simd_portable_squeeze_9b_b2(&s, output, output_len - output_rem, output_rem);
    }
  }
}

/**
 A portable SHA3 256 implementation.
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_portable_sha256(
  Eurydice_mut_borrow_ತುಂಡು_u8 digest,
  Eurydice_borrow_ತುಂಡು_u8 ದತ್ತಾಂಶ
)
{
  libcrux_sha3_generic_keccak_portable_keccak1_220(ದತ್ತಾಂಶ, digest);
}

/**
This function found in impl {libcrux_sha3::generic_keccak::KeccakState<u64, 1usize>[core::marker::Sized<u64>, libcrux_sha3::simd::portable::{libcrux_sha3::traits::KeccakItem<1usize> for u64}]}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.squeeze_first_three_blocks_b4
with const generics
- RATE= 168
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_generic_keccak_portable_squeeze_ಮೊದಲ_three_ಖಂಡಗಳು_b4_60(
  Eurydice_arr_7c *self,
  Eurydice_mut_borrow_ತುಂಡು_u8 ಹೊರಹೋಗು
)
{
  libcrux_sha3_simd_portable_squeeze_9b_60(self, ಹೊರಹೋಗು, (ಗಾತ್ರ_t)0U, (ಗಾತ್ರ_t)168U);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
  libcrux_sha3_simd_portable_squeeze_9b_60(self, ಹೊರಹೋಗು, (ಗಾತ್ರ_t)168U, (ಗಾತ್ರ_t)168U);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
  libcrux_sha3_simd_portable_squeeze_9b_60(self, ಹೊರಹೋಗು, (ಗಾತ್ರ_t)2U * (ಗಾತ್ರ_t)168U, (ಗಾತ್ರ_t)168U);
}

/**
 Squeeze three blocks
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_portable_incremental_shake128_squeeze_ಮೊದಲ_three_ಖಂಡಗಳು(
  Eurydice_arr_7c *s,
  Eurydice_mut_borrow_ತುಂಡು_u8 out0
)
{
  libcrux_sha3_generic_keccak_portable_squeeze_ಮೊದಲ_three_ಖಂಡಗಳು_b4_60(s, out0);
}

#ವ್ಯಾಖ್ಯಾನಿಸು libcrux_sha3_Algorithm_Sha224 1
#ವ್ಯಾಖ್ಯಾನಿಸು libcrux_sha3_Algorithm_Sha256 2
#ವ್ಯಾಖ್ಯಾನಿಸು libcrux_sha3_Algorithm_Sha384 3
#ವ್ಯಾಖ್ಯಾನಿಸು libcrux_sha3_Algorithm_Sha512 4

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ uint8_t libcrux_sha3_Algorithm;

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_SHA3_SHA3_224_DIGEST_ಗಾತ್ರ ((ಗಾತ್ರ_t)28U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_SHA3_SHA3_256_DIGEST_ಗಾತ್ರ ((ಗಾತ್ರ_t)32U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_SHA3_SHA3_384_DIGEST_ಗಾತ್ರ ((ಗಾತ್ರ_t)48U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_SHA3_SHA3_512_DIGEST_ಗಾತ್ರ ((ಗಾತ್ರ_t)64U)

/**
 Returns the output size of a digest.
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಗಾತ್ರ_t libcrux_sha3_digest_ಗಾತ್ರ(libcrux_sha3_Algorithm ಬಹುಲಕ)
{
  ಆಯ್ಕೆ (ಬಹುಲಕ)
  {
    ಸ್ಥಿತಿ libcrux_sha3_Algorithm_Sha224:
      {
        ನಿಲ್ಲಿಸು;
      }
    ಸ್ಥಿತಿ libcrux_sha3_Algorithm_Sha256:
      {
        ಹಿಂತಿರುಗಿ LIBCRUX_SHA3_SHA3_256_DIGEST_ಗಾತ್ರ;
      }
    ಸ್ಥಿತಿ libcrux_sha3_Algorithm_Sha384:
      {
        ಹಿಂತಿರುಗಿ LIBCRUX_SHA3_SHA3_384_DIGEST_ಗಾತ್ರ;
      }
    ಸ್ಥಿತಿ libcrux_sha3_Algorithm_Sha512:
      {
        ಹಿಂತಿರುಗಿ LIBCRUX_SHA3_SHA3_512_DIGEST_ಗಾತ್ರ;
      }
    ಪೂರ್ವನಿಯೋಜಿತ:
      {
        KRML_HOST_EPRINTF("KaRaMeL incomplete match at %s:%d\n", __FILE__, __LINE__);
        KRML_HOST_EXIT(253U);
      }
  }
  ಹಿಂತಿರುಗಿ LIBCRUX_SHA3_SHA3_224_DIGEST_ಗಾತ್ರ;
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_block
with const generics
- RATE= 144
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_simd_portable_ತುಂಬು_ಖಂಡ_9e(
  Eurydice_arr_7c *state,
  Eurydice_borrow_ತುಂಡು_u8 ಖಂಡಗಳು,
  ಗಾತ್ರ_t ಆರಂಭ
)
{
  Eurydice_arr_7c state_flat = { .ದತ್ತಾಂಶ = { 0U } };
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)144U / (ಗಾತ್ರ_t)8U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    ಗಾತ್ರ_t ಸ್ಥಾನಾಂತರ = ಆರಂಭ + (ಗಾತ್ರ_t)8U * i0;
    Eurydice_array_u8x8 arr;
    ಸ್ಮರಣೆ_ನಕಲು(arr.ದತ್ತಾಂಶ,
      Eurydice_ತುಂಡು_subslice_shared_c8(ಖಂಡಗಳು,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = ಸ್ಥಾನಾಂತರ, .ಕೊನೆ = ಸ್ಥಾನಾಂತರ + (ಗಾತ್ರ_t)8U })).ptr,
      (ಗಾತ್ರ_t)8U * ಗಾತ್ರ (uint8_t));
    Eurydice_array_u8x8
    uu____0 =
      core_ಫಲಿತಾಂಶ_unwrap_26_e0((
          KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_8e){ .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Ok, .val = { .case_Ok = arr } }
        ));
    state_flat.ದತ್ತಾಂಶ[i0] = core_ಅಂಕೆ_u64_from_le_ಬೈಟುಗಳು(uu____0);
  }
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)144U / (ಗಾತ್ರ_t)8U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    libcrux_sha3_traits_ಗಣ_ij_71(state,
      i0 / (ಗಾತ್ರ_t)5U,
      i0 % (ಗಾತ್ರ_t)5U,
      libcrux_sha3_traits_get_ij_71(state, i0 / (ಗಾತ್ರ_t)5U, i0 % (ಗಾತ್ರ_t)5U)[0U] ^
        state_flat.ದತ್ತಾಂಶ[i0]);
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_sha3_simd_portable_ತುಂಬು_ಖಂಡ_a1_9e(
  Eurydice_arr_7c *self,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_dc *ಒಳಹರಿವು,
  ಗಾತ್ರ_t ಆರಂಭ
)
{
  libcrux_sha3_simd_portable_ತುಂಬು_ಖಂಡ_9e(self, ಒಳಹರಿವು->ದತ್ತಾಂಶ[0U], ಆರಂಭ);
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_generic_keccak_absorb_ಖಂಡ_80_e92(
  Eurydice_arr_7c *self,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_dc *ಒಳಹರಿವು,
  ಗಾತ್ರ_t ಆರಂಭ
)
{
  libcrux_sha3_simd_portable_ತುಂಬು_ಖಂಡ_a1_9e(self, ಒಳಹರಿವು, ಆರಂಭ);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_last
with const generics
- RATE= 144
- DELIMITER= 6
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_simd_portable_ತುಂಬು_ಕೊನೆಯ_3a(
  Eurydice_arr_7c *state,
  Eurydice_borrow_ತುಂಡು_u8 ಖಂಡಗಳು,
  ಗಾತ್ರ_t ಆರಂಭ,
  ಗಾತ್ರ_t len
)
{
  Eurydice_arr_f4 ಬಫರ್ = { .ದತ್ತಾಂಶ = { 0U } };
  Eurydice_ತುಂಡು_copy(Eurydice_array_ಗಮ್ಯ_subslice_mut_d44(&ಬಫರ್,
      (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = (ಗಾತ್ರ_t)0U, .ಕೊನೆ = len })),
    Eurydice_ತುಂಡು_subslice_shared_c8(ಖಂಡಗಳು,
      (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = ಆರಂಭ, .ಕೊನೆ = ಆರಂಭ + len })),
    uint8_t);
  ಬಫರ್.ದತ್ತಾಂಶ[len] = 6U;
  ಗಾತ್ರ_t uu____0 = (ಗಾತ್ರ_t)144U - (ಗಾತ್ರ_t)1U;
  ಬಫರ್.ದತ್ತಾಂಶ[uu____0] = (uint32_t)ಬಫರ್.ದತ್ತಾಂಶ[uu____0] | 128U;
  libcrux_sha3_simd_portable_ತುಂಬು_ಖಂಡ_9e(state,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_38(&ಬಫರ್),
    (ಗಾತ್ರ_t)0U);
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_sha3_simd_portable_ತುಂಬು_ಕೊನೆಯ_a1_3a(
  Eurydice_arr_7c *self,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_dc *ಒಳಹರಿವು,
  ಗಾತ್ರ_t ಆರಂಭ,
  ಗಾತ್ರ_t len
)
{
  libcrux_sha3_simd_portable_ತುಂಬು_ಕೊನೆಯ_3a(self, ಒಳಹರಿವು->ದತ್ತಾಂಶ[0U], ಆರಂಭ, len);
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_generic_keccak_absorb_final_80_bd3(
  Eurydice_arr_7c *self,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_dc *ಒಳಹರಿವು,
  ಗಾತ್ರ_t ಆರಂಭ,
  ಗಾತ್ರ_t len
)
{
  libcrux_sha3_simd_portable_ತುಂಬು_ಕೊನೆಯ_a1_3a(self, ಒಳಹರಿವು, ಆರಂಭ, len);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.store_block
with const generics
- RATE= 144
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_simd_portable_store_ಖಂಡ_9e(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_7c *s,
  Eurydice_mut_borrow_ತುಂಡು_u8 ಹೊರಹೋಗು,
  ಗಾತ್ರ_t ಆರಂಭ,
  ಗಾತ್ರ_t len
)
{
  ಗಾತ್ರ_t octets = len / (ಗಾತ್ರ_t)8U;
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < octets; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    Eurydice_array_u8x8
    ಬೈಟುಗಳು =
      core_ಅಂಕೆ_u64_ಗಮ್ಯ_le_ಬೈಟುಗಳು(libcrux_sha3_traits_get_ij_71(s,
          i0 / (ಗಾತ್ರ_t)5U,
          i0 % (ಗಾತ್ರ_t)5U)[0U]);
    ಗಾತ್ರ_t ಹೊರಹೋಗು_pos = ಆರಂಭ + (ಗಾತ್ರ_t)8U * i0;
    Eurydice_ತುಂಡು_copy(Eurydice_ತುಂಡು_subslice_mut_c8(ಹೊರಹೋಗು,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = ಹೊರಹೋಗು_pos, .ಕೊನೆ = ಹೊರಹೋಗು_pos + (ಗಾತ್ರ_t)8U })),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_6e(&ಬೈಟುಗಳು),
      uint8_t);
  }
  ಗಾತ್ರ_t ಉಳಿದ = len % (ಗಾತ್ರ_t)8U;
  ಆದರೆ (ಉಳಿದ > (ಗಾತ್ರ_t)0U)
  {
    Eurydice_array_u8x8
    ಬೈಟುಗಳು =
      core_ಅಂಕೆ_u64_ಗಮ್ಯ_le_ಬೈಟುಗಳು(libcrux_sha3_traits_get_ij_71(s,
          octets / (ಗಾತ್ರ_t)5U,
          octets % (ಗಾತ್ರ_t)5U)[0U]);
    ಗಾತ್ರ_t ಹೊರಹೋಗು_pos = ಆರಂಭ + len - ಉಳಿದ;
    Eurydice_mut_borrow_ತುಂಡು_u8
    uu____0 =
      Eurydice_ತುಂಡು_subslice_mut_c8(ಹೊರಹೋಗು,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = ಹೊರಹೋಗು_pos, .ಕೊನೆ = ಹೊರಹೋಗು_pos + ಉಳಿದ }));
    Eurydice_ತುಂಡು_copy(uu____0,
      Eurydice_array_ಗಮ್ಯ_subslice_ಗಮ್ಯ_shared_21(&ಬೈಟುಗಳು, ಉಳಿದ),
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_sha3_simd_portable_squeeze_9b_9e(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_7c *self,
  Eurydice_mut_borrow_ತುಂಡು_u8 ಹೊರಹೋಗು,
  ಗಾತ್ರ_t ಆರಂಭ,
  ಗಾತ್ರ_t len
)
{
  libcrux_sha3_simd_portable_store_ಖಂಡ_9e(self, ಹೊರಹೋಗು, ಆರಂಭ, len);
}

/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.keccak1
with const generics
- RATE= 144
- DELIM= 6
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_sha3_generic_keccak_portable_keccak1_3a(
  Eurydice_borrow_ತುಂಡು_u8 ಒಳಹರಿವು,
  Eurydice_mut_borrow_ತುಂಡು_u8 output
)
{
  Eurydice_arr_7c s = libcrux_sha3_generic_keccak_new_80_71();
  ಗಾತ್ರ_t ಒಳಹರಿವು_len = ಒಳಹರಿವು.meta;
  ಗಾತ್ರ_t ಒಳಹರಿವು_ಖಂಡಗಳು = ಒಳಹರಿವು_len / (ಗಾತ್ರ_t)144U;
  ಗಾತ್ರ_t ಒಳಹರಿವು_rem = ಒಳಹರಿವು_len % (ಗಾತ್ರ_t)144U;
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < ಒಳಹರಿವು_ಖಂಡಗಳು; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_dc lvalue = { .ದತ್ತಾಂಶ = { ಒಳಹರಿವು } };
    libcrux_sha3_generic_keccak_absorb_ಖಂಡ_80_e92(&s, &lvalue, i0 * (ಗಾತ್ರ_t)144U);
  }
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_dc lvalue = { .ದತ್ತಾಂಶ = { ಒಳಹರಿವು } };
  libcrux_sha3_generic_keccak_absorb_final_80_bd3(&s, &lvalue, ಒಳಹರಿವು_len - ಒಳಹರಿವು_rem, ಒಳಹರಿವು_rem);
  ಗಾತ್ರ_t output_len = output.meta;
  ಗಾತ್ರ_t output_ಖಂಡಗಳು = output_len / (ಗಾತ್ರ_t)144U;
  ಗಾತ್ರ_t output_rem = output_len % (ಗಾತ್ರ_t)144U;
  ಆದರೆ (output_ಖಂಡಗಳು == (ಗಾತ್ರ_t)0U)
  {
    libcrux_sha3_simd_portable_squeeze_9b_9e(&s, output, (ಗಾತ್ರ_t)0U, output_len);
  }
  ಇಲ್ಲದಿದ್ದರೆ
  {
    libcrux_sha3_simd_portable_squeeze_9b_9e(&s, output, (ಗಾತ್ರ_t)0U, (ಗಾತ್ರ_t)144U);
    ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)1U; i < output_ಖಂಡಗಳು; i++)
    {
      ಗಾತ್ರ_t i0 = i;
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&s);
      libcrux_sha3_simd_portable_squeeze_9b_9e(&s, output, i0 * (ಗಾತ್ರ_t)144U, (ಗಾತ್ರ_t)144U);
    }
    ಆದರೆ (output_rem != (ಗಾತ್ರ_t)0U)
    {
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&s);
      libcrux_sha3_simd_portable_squeeze_9b_9e(&s, output, output_len - output_rem, output_rem);
    }
  }
}

/**
 A portable SHA3 224 implementation.
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_portable_sha224(
  Eurydice_mut_borrow_ತುಂಡು_u8 digest,
  Eurydice_borrow_ತುಂಡು_u8 ದತ್ತಾಂಶ
)
{
  libcrux_sha3_generic_keccak_portable_keccak1_3a(ದತ್ತಾಂಶ, digest);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_block
with const generics
- RATE= 104
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_simd_portable_ತುಂಬು_ಖಂಡ_53(
  Eurydice_arr_7c *state,
  Eurydice_borrow_ತುಂಡು_u8 ಖಂಡಗಳು,
  ಗಾತ್ರ_t ಆರಂಭ
)
{
  Eurydice_arr_7c state_flat = { .ದತ್ತಾಂಶ = { 0U } };
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)104U / (ಗಾತ್ರ_t)8U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    ಗಾತ್ರ_t ಸ್ಥಾನಾಂತರ = ಆರಂಭ + (ಗಾತ್ರ_t)8U * i0;
    Eurydice_array_u8x8 arr;
    ಸ್ಮರಣೆ_ನಕಲು(arr.ದತ್ತಾಂಶ,
      Eurydice_ತುಂಡು_subslice_shared_c8(ಖಂಡಗಳು,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = ಸ್ಥಾನಾಂತರ, .ಕೊನೆ = ಸ್ಥಾನಾಂತರ + (ಗಾತ್ರ_t)8U })).ptr,
      (ಗಾತ್ರ_t)8U * ಗಾತ್ರ (uint8_t));
    Eurydice_array_u8x8
    uu____0 =
      core_ಫಲಿತಾಂಶ_unwrap_26_e0((
          KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_8e){ .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Ok, .val = { .case_Ok = arr } }
        ));
    state_flat.ದತ್ತಾಂಶ[i0] = core_ಅಂಕೆ_u64_from_le_ಬೈಟುಗಳು(uu____0);
  }
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)104U / (ಗಾತ್ರ_t)8U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    libcrux_sha3_traits_ಗಣ_ij_71(state,
      i0 / (ಗಾತ್ರ_t)5U,
      i0 % (ಗಾತ್ರ_t)5U,
      libcrux_sha3_traits_get_ij_71(state, i0 / (ಗಾತ್ರ_t)5U, i0 % (ಗಾತ್ರ_t)5U)[0U] ^
        state_flat.ದತ್ತಾಂಶ[i0]);
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_sha3_simd_portable_ತುಂಬು_ಖಂಡ_a1_53(
  Eurydice_arr_7c *self,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_dc *ಒಳಹರಿವು,
  ಗಾತ್ರ_t ಆರಂಭ
)
{
  libcrux_sha3_simd_portable_ತುಂಬು_ಖಂಡ_53(self, ಒಳಹರಿವು->ದತ್ತಾಂಶ[0U], ಆರಂಭ);
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_generic_keccak_absorb_ಖಂಡ_80_e93(
  Eurydice_arr_7c *self,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_dc *ಒಳಹರಿವು,
  ಗಾತ್ರ_t ಆರಂಭ
)
{
  libcrux_sha3_simd_portable_ತುಂಬು_ಖಂಡ_a1_53(self, ಒಳಹರಿವು, ಆರಂಭ);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.load_last
with const generics
- RATE= 104
- DELIMITER= 6
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_simd_portable_ತುಂಬು_ಕೊನೆಯ_dc0(
  Eurydice_arr_7c *state,
  Eurydice_borrow_ತುಂಡು_u8 ಖಂಡಗಳು,
  ಗಾತ್ರ_t ಆರಂಭ,
  ಗಾತ್ರ_t len
)
{
  Eurydice_arr_c4 ಬಫರ್ = { .ದತ್ತಾಂಶ = { 0U } };
  Eurydice_ತುಂಡು_copy(Eurydice_array_ಗಮ್ಯ_subslice_mut_d45(&ಬಫರ್,
      (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = (ಗಾತ್ರ_t)0U, .ಕೊನೆ = len })),
    Eurydice_ತುಂಡು_subslice_shared_c8(ಖಂಡಗಳು,
      (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = ಆರಂಭ, .ಕೊನೆ = ಆರಂಭ + len })),
    uint8_t);
  ಬಫರ್.ದತ್ತಾಂಶ[len] = 6U;
  ಗಾತ್ರ_t uu____0 = (ಗಾತ್ರ_t)104U - (ಗಾತ್ರ_t)1U;
  ಬಫರ್.ದತ್ತಾಂಶ[uu____0] = (uint32_t)ಬಫರ್.ದತ್ತಾಂಶ[uu____0] | 128U;
  libcrux_sha3_simd_portable_ತುಂಬು_ಖಂಡ_53(state,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_72(&ಬಫರ್),
    (ಗಾತ್ರ_t)0U);
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_sha3_simd_portable_ತುಂಬು_ಕೊನೆಯ_a1_dc0(
  Eurydice_arr_7c *self,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_dc *ಒಳಹರಿವು,
  ಗಾತ್ರ_t ಆರಂಭ,
  ಗಾತ್ರ_t len
)
{
  libcrux_sha3_simd_portable_ತುಂಬು_ಕೊನೆಯ_dc0(self, ಒಳಹರಿವು->ದತ್ತಾಂಶ[0U], ಆರಂಭ, len);
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_generic_keccak_absorb_final_80_bd4(
  Eurydice_arr_7c *self,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_dc *ಒಳಹರಿವು,
  ಗಾತ್ರ_t ಆರಂಭ,
  ಗಾತ್ರ_t len
)
{
  libcrux_sha3_simd_portable_ತುಂಬು_ಕೊನೆಯ_a1_dc0(self, ಒಳಹರಿವು, ಆರಂಭ, len);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(self);
}

/**
A monomorphic instance of libcrux_sha3.simd.portable.store_block
with const generics
- RATE= 104
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_simd_portable_store_ಖಂಡ_53(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_7c *s,
  Eurydice_mut_borrow_ತುಂಡು_u8 ಹೊರಹೋಗು,
  ಗಾತ್ರ_t ಆರಂಭ,
  ಗಾತ್ರ_t len
)
{
  ಗಾತ್ರ_t octets = len / (ಗಾತ್ರ_t)8U;
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < octets; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    Eurydice_array_u8x8
    ಬೈಟುಗಳು =
      core_ಅಂಕೆ_u64_ಗಮ್ಯ_le_ಬೈಟುಗಳು(libcrux_sha3_traits_get_ij_71(s,
          i0 / (ಗಾತ್ರ_t)5U,
          i0 % (ಗಾತ್ರ_t)5U)[0U]);
    ಗಾತ್ರ_t ಹೊರಹೋಗು_pos = ಆರಂಭ + (ಗಾತ್ರ_t)8U * i0;
    Eurydice_ತುಂಡು_copy(Eurydice_ತುಂಡು_subslice_mut_c8(ಹೊರಹೋಗು,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = ಹೊರಹೋಗು_pos, .ಕೊನೆ = ಹೊರಹೋಗು_pos + (ಗಾತ್ರ_t)8U })),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_6e(&ಬೈಟುಗಳು),
      uint8_t);
  }
  ಗಾತ್ರ_t ಉಳಿದ = len % (ಗಾತ್ರ_t)8U;
  ಆದರೆ (ಉಳಿದ > (ಗಾತ್ರ_t)0U)
  {
    Eurydice_array_u8x8
    ಬೈಟುಗಳು =
      core_ಅಂಕೆ_u64_ಗಮ್ಯ_le_ಬೈಟುಗಳು(libcrux_sha3_traits_get_ij_71(s,
          octets / (ಗಾತ್ರ_t)5U,
          octets % (ಗಾತ್ರ_t)5U)[0U]);
    ಗಾತ್ರ_t ಹೊರಹೋಗು_pos = ಆರಂಭ + len - ಉಳಿದ;
    Eurydice_mut_borrow_ತುಂಡು_u8
    uu____0 =
      Eurydice_ತುಂಡು_subslice_mut_c8(ಹೊರಹೋಗು,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = ಹೊರಹೋಗು_pos, .ಕೊನೆ = ಹೊರಹೋಗು_pos + ಉಳಿದ }));
    Eurydice_ತುಂಡು_copy(uu____0,
      Eurydice_array_ಗಮ್ಯ_subslice_ಗಮ್ಯ_shared_21(&ಬೈಟುಗಳು, ಉಳಿದ),
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_sha3_simd_portable_squeeze_9b_53(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_7c *self,
  Eurydice_mut_borrow_ತುಂಡು_u8 ಹೊರಹೋಗು,
  ಗಾತ್ರ_t ಆರಂಭ,
  ಗಾತ್ರ_t len
)
{
  libcrux_sha3_simd_portable_store_ಖಂಡ_53(self, ಹೊರಹೋಗು, ಆರಂಭ, len);
}

/**
A monomorphic instance of libcrux_sha3.generic_keccak.portable.keccak1
with const generics
- RATE= 104
- DELIM= 6
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_sha3_generic_keccak_portable_keccak1_dc0(
  Eurydice_borrow_ತುಂಡು_u8 ಒಳಹರಿವು,
  Eurydice_mut_borrow_ತುಂಡು_u8 output
)
{
  Eurydice_arr_7c s = libcrux_sha3_generic_keccak_new_80_71();
  ಗಾತ್ರ_t ಒಳಹರಿವು_len = ಒಳಹರಿವು.meta;
  ಗಾತ್ರ_t ಒಳಹರಿವು_ಖಂಡಗಳು = ಒಳಹರಿವು_len / (ಗಾತ್ರ_t)104U;
  ಗಾತ್ರ_t ಒಳಹರಿವು_rem = ಒಳಹರಿವು_len % (ಗಾತ್ರ_t)104U;
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < ಒಳಹರಿವು_ಖಂಡಗಳು; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_dc lvalue = { .ದತ್ತಾಂಶ = { ಒಳಹರಿವು } };
    libcrux_sha3_generic_keccak_absorb_ಖಂಡ_80_e93(&s, &lvalue, i0 * (ಗಾತ್ರ_t)104U);
  }
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_dc lvalue = { .ದತ್ತಾಂಶ = { ಒಳಹರಿವು } };
  libcrux_sha3_generic_keccak_absorb_final_80_bd4(&s, &lvalue, ಒಳಹರಿವು_len - ಒಳಹರಿವು_rem, ಒಳಹರಿವು_rem);
  ಗಾತ್ರ_t output_len = output.meta;
  ಗಾತ್ರ_t output_ಖಂಡಗಳು = output_len / (ಗಾತ್ರ_t)104U;
  ಗಾತ್ರ_t output_rem = output_len % (ಗಾತ್ರ_t)104U;
  ಆದರೆ (output_ಖಂಡಗಳು == (ಗಾತ್ರ_t)0U)
  {
    libcrux_sha3_simd_portable_squeeze_9b_53(&s, output, (ಗಾತ್ರ_t)0U, output_len);
  }
  ಇಲ್ಲದಿದ್ದರೆ
  {
    libcrux_sha3_simd_portable_squeeze_9b_53(&s, output, (ಗಾತ್ರ_t)0U, (ಗಾತ್ರ_t)104U);
    ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)1U; i < output_ಖಂಡಗಳು; i++)
    {
      ಗಾತ್ರ_t i0 = i;
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&s);
      libcrux_sha3_simd_portable_squeeze_9b_53(&s, output, i0 * (ಗಾತ್ರ_t)104U, (ಗಾತ್ರ_t)104U);
    }
    ಆದರೆ (output_rem != (ಗಾತ್ರ_t)0U)
    {
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&s);
      libcrux_sha3_simd_portable_squeeze_9b_53(&s, output, output_len - output_rem, output_rem);
    }
  }
}

/**
 A portable SHA3 384 implementation.
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_portable_sha384(
  Eurydice_mut_borrow_ತುಂಡು_u8 digest,
  Eurydice_borrow_ತುಂಡು_u8 ದತ್ತಾಂಶ
)
{
  libcrux_sha3_generic_keccak_portable_keccak1_dc0(ದತ್ತಾಂಶ, digest);
}

/**
 SHA3 224

 Preconditions:
 - `digest.len() == 28`
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_sha3_sha224_ema(Eurydice_mut_borrow_ತುಂಡು_u8 digest, Eurydice_borrow_ತುಂಡು_u8 payload)
{
  libcrux_sha3_portable_sha224(digest, payload);
}

/**
 SHA3 224
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_a2 libcrux_sha3_sha224(Eurydice_borrow_ತುಂಡು_u8 ದತ್ತಾಂಶ)
{
  Eurydice_arr_a2 ಹೊರಹೋಗು = { .ದತ್ತಾಂಶ = { 0U } };
  libcrux_sha3_sha224_ema(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_5e(&ಹೊರಹೋಗು), ದತ್ತಾಂಶ);
  ಹಿಂತಿರುಗಿ ಹೊರಹೋಗು;
}

/**
 SHA3 256
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_sha3_sha256_ema(Eurydice_mut_borrow_ತುಂಡು_u8 digest, Eurydice_borrow_ತುಂಡು_u8 payload)
{
  libcrux_sha3_portable_sha256(digest, payload);
}

/**
 SHA3 256
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_ec libcrux_sha3_sha256(Eurydice_borrow_ತುಂಡು_u8 ದತ್ತಾಂಶ)
{
  Eurydice_arr_ec ಹೊರಹೋಗು = { .ದತ್ತಾಂಶ = { 0U } };
  libcrux_sha3_sha256_ema(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_01(&ಹೊರಹೋಗು), ದತ್ತಾಂಶ);
  ಹಿಂತಿರುಗಿ ಹೊರಹೋಗು;
}

/**
 SHA3 384
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_sha3_sha384_ema(Eurydice_mut_borrow_ತುಂಡು_u8 digest, Eurydice_borrow_ತುಂಡು_u8 payload)
{
  libcrux_sha3_portable_sha384(digest, payload);
}

/**
 SHA3 384
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_65 libcrux_sha3_sha384(Eurydice_borrow_ತುಂಡು_u8 ದತ್ತಾಂಶ)
{
  Eurydice_arr_65 ಹೊರಹೋಗು = { .ದತ್ತಾಂಶ = { 0U } };
  libcrux_sha3_sha384_ema(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_9f(&ಹೊರಹೋಗು), ದತ್ತಾಂಶ);
  ಹಿಂತಿರುಗಿ ಹೊರಹೋಗು;
}

/**
 SHA3 512
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_sha3_sha512_ema(Eurydice_mut_borrow_ತುಂಡು_u8 digest, Eurydice_borrow_ತುಂಡು_u8 payload)
{
  libcrux_sha3_portable_sha512(digest, payload);
}

/**
 SHA3 512
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_c7 libcrux_sha3_sha512(Eurydice_borrow_ತುಂಡು_u8 ದತ್ತಾಂಶ)
{
  Eurydice_arr_c7 ಹೊರಹೋಗು = { .ದತ್ತಾಂಶ = { 0U } };
  libcrux_sha3_sha512_ema(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_17(&ಹೊರಹೋಗು), ದತ್ತಾಂಶ);
  ಹಿಂತಿರುಗಿ ಹೊರಹೋಗು;
}

/**
 SHAKE 128

 Writes `out.len()` bytes.
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_sha3_shake128_ema(Eurydice_mut_borrow_ತುಂಡು_u8 ಹೊರಹೋಗು, Eurydice_borrow_ತುಂಡು_u8 ದತ್ತಾಂಶ)
{
  libcrux_sha3_portable_shake128(ಹೊರಹೋಗು, ದತ್ತಾಂಶ);
}

/**
 SHAKE 256

 Writes `out.len()` bytes.
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_sha3_shake256_ema(Eurydice_mut_borrow_ತುಂಡು_u8 ಹೊರಹೋಗು, Eurydice_borrow_ತುಂಡು_u8 ದತ್ತಾಂಶ)
{
  libcrux_sha3_portable_shake256(ಹೊರಹೋಗು, ದತ್ತಾಂಶ);
}

/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.KeccakXofState
with types uint64_t
with const generics
- $1size_t
- $168size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ libcrux_sha3_generic_keccak_xof_KeccakXofState_55_s
{
  Eurydice_arr_7c inner;
  Eurydice_arr_88 buf;
  ಗಾತ್ರ_t buf_len;
  bool sponge;
}
libcrux_sha3_generic_keccak_xof_KeccakXofState_55;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ libcrux_sha3_generic_keccak_xof_KeccakXofState_55
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಗಾತ್ರ_t
libcrux_sha3_generic_keccak_xof_fill_ಬಫರ್_35_e90(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_55 *self,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_dc *inputs
)
{
  ಗಾತ್ರ_t ಒಳಹರಿವು_len = inputs->ದತ್ತಾಂಶ->meta;
  ಗಾತ್ರ_t uu____0;
  ಆದರೆ (self->buf_len != (ಗಾತ್ರ_t)0U)
  {
    ಆದರೆ (ಒಳಹರಿವು_len >= (ಗಾತ್ರ_t)168U - self->buf_len)
    {
      ಗಾತ್ರ_t consumed = (ಗಾತ್ರ_t)168U - self->buf_len;
      ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)1U; i++)
      {
        ಗಾತ್ರ_t i0 = i;
        Eurydice_ತುಂಡು_copy(Eurydice_array_ಗಮ್ಯ_subslice_from_mut_5f0(&self->buf.ದತ್ತಾಂಶ[i0],
            self->buf_len),
          Eurydice_ತುಂಡು_subslice_ಗಮ್ಯ_shared_72(inputs->ದತ್ತಾಂಶ[i0], consumed),
          uint8_t);
      }
      self->buf_len = (ಗಾತ್ರ_t)168U;
      uu____0 = consumed;
    }
    ಇಲ್ಲದಿದ್ದರೆ
    {
      uu____0 = (ಗಾತ್ರ_t)0U;
    }
  }
  ಇಲ್ಲದಿದ್ದರೆ
  {
    uu____0 = (ಗಾತ್ರ_t)0U;
  }
  ಹಿಂತಿರುಗಿ uu____0;
}

/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.buf_to_slices.closure
with const generics
- $1size_t
- $168size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಸ್ಥಿರಾಂಕ Eurydice_arr_88 *libcrux_sha3_generic_keccak_xof_buf_ಗಮ್ಯ_slices_ಆವರಣ_48;

/**
This function found in impl {core::ops::function::FnMut<(usize), &'_ ([u8])> for libcrux_sha3::generic_keccak::xof::buf_to_slices::closure<0, PARALLEL_LANES, RATE>}
*/
/**
A monomorphic instance of libcrux_sha3.generic_keccak.xof.buf_to_slices.call_mut_2a
with const generics
- PARALLEL_LANES= 1
- RATE= 168
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
libcrux_sha3_generic_keccak_xof_buf_ಗಮ್ಯ_slices_call_mut_2a_810(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_88 **_,
  ಗಾತ್ರ_t tupled_ವಾದಗಳು
)
{
  ಗಾತ್ರ_t i = tupled_ವಾದಗಳು;
  ಹಿಂತಿರುಗಿ
    core_array_T_N_as_ತುಂಡು((ಗಾತ್ರ_t)168U,
      &_[0U]->ದತ್ತಾಂಶ[i],
      uint8_t,
      Eurydice_borrow_ತುಂಡು_u8);
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
libcrux_sha3_generic_keccak_xof_buf_ಗಮ್ಯ_slices_call_once_fa_810(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_88 *_,
  ಗಾತ್ರ_t _0
)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_generic_keccak_xof_buf_ಗಮ್ಯ_slices_call_mut_2a_810(&_, _0);
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
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_dc
libcrux_sha3_generic_keccak_xof_buf_ಗಮ್ಯ_slices_810(ಸ್ಥಿರಾಂಕ Eurydice_arr_88 *buf)
{
  Eurydice_arr_dc arr_struct;
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)1U; i++)
  {
    arr_struct.ದತ್ತಾಂಶ[i] = libcrux_sha3_generic_keccak_xof_buf_ಗಮ್ಯ_slices_call_mut_2a_810(&buf, i);
  }
  ಹಿಂತಿರುಗಿ arr_struct;
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಗಾತ್ರ_t
libcrux_sha3_generic_keccak_xof_absorb_ತುಂಬಿದ_35_e90(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_55 *self,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_dc *inputs
)
{
  ಗಾತ್ರ_t consumed = libcrux_sha3_generic_keccak_xof_fill_ಬಫರ್_35_e90(self, inputs);
  ಆದರೆ (self->buf_len == (ಗಾತ್ರ_t)168U)
  {
    Eurydice_arr_dc borrowed = libcrux_sha3_generic_keccak_xof_buf_ಗಮ್ಯ_slices_810(&self->buf);
    libcrux_sha3_simd_portable_ತುಂಬು_ಖಂಡ_a1_60(&self->inner, &borrowed, (ಗಾತ್ರ_t)0U);
    libcrux_sha3_generic_keccak_keccakf1600_80_71(&self->inner);
    self->buf_len = (ಗಾತ್ರ_t)0U;
  }
  ಗಾತ್ರ_t ಒಳಹರಿವು_ಗಮ್ಯ_consume = inputs->ದತ್ತಾಂಶ->meta - consumed;
  ಗಾತ್ರ_t ಅಂಕೆ_ಖಂಡಗಳು = ಒಳಹರಿವು_ಗಮ್ಯ_consume / (ಗಾತ್ರ_t)168U;
  ಗಾತ್ರ_t remainder = ಒಳಹರಿವು_ಗಮ್ಯ_consume % (ಗಾತ್ರ_t)168U;
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < ಅಂಕೆ_ಖಂಡಗಳು; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    ಗಾತ್ರ_t ಆರಂಭ = i0 * (ಗಾತ್ರ_t)168U + consumed;
    libcrux_sha3_simd_portable_ತುಂಬು_ಖಂಡ_a1_60(&self->inner, inputs, ಆರಂಭ);
    libcrux_sha3_generic_keccak_keccakf1600_80_71(&self->inner);
  }
  ಹಿಂತಿರುಗಿ remainder;
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_generic_keccak_xof_absorb_35_e90(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_55 *self,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_dc *inputs
)
{
  ಗಾತ್ರ_t remainder = libcrux_sha3_generic_keccak_xof_absorb_ತುಂಬಿದ_35_e90(self, inputs);
  ಆದರೆ (remainder > (ಗಾತ್ರ_t)0U)
  {
    ಗಾತ್ರ_t ಒಳಹರಿವು_len = inputs->ದತ್ತಾಂಶ->meta;
    ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)1U; i++)
    {
      ಗಾತ್ರ_t i0 = i;
      Eurydice_ತುಂಡು_copy(Eurydice_array_ಗಮ್ಯ_subslice_mut_d41(&self->buf.ದತ್ತಾಂಶ[i0],
          (
            KRML_CLITERAL(core_ops_range_Range_87){
              .ಆರಂಭ = self->buf_len,
              .ಕೊನೆ = self->buf_len + remainder
            }
          )),
        Eurydice_ತುಂಡು_subslice_shared_c8(inputs->ದತ್ತಾಂಶ[i0],
          (
            KRML_CLITERAL(core_ops_range_Range_87){
              .ಆರಂಭ = ಒಳಹರಿವು_len - remainder,
              .ಕೊನೆ = ಒಳಹರಿವು_len
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_sha3_portable_incremental_absorb_26(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_55 *self,
  Eurydice_borrow_ತುಂಡು_u8 ಒಳಹರಿವು
)
{
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_dc lvalue = { .ದತ್ತಾಂಶ = { ಒಳಹರಿವು } };
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_generic_keccak_xof_absorb_final_35_bd0(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_55 *self,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_dc *inputs
)
{
  libcrux_sha3_generic_keccak_xof_absorb_35_e90(self, inputs);
  Eurydice_arr_dc borrowed = libcrux_sha3_generic_keccak_xof_buf_ಗಮ್ಯ_slices_810(&self->buf);
  libcrux_sha3_simd_portable_ತುಂಬು_ಕೊನೆಯ_a1_37(&self->inner, &borrowed, (ಗಾತ್ರ_t)0U, self->buf_len);
  libcrux_sha3_generic_keccak_keccakf1600_80_71(&self->inner);
}

/**
This function found in impl {libcrux_sha3::portable::incremental::Xof<168usize> for libcrux_sha3::portable::incremental::Shake128Xof}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_sha3_portable_incremental_absorb_final_26(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_55 *self,
  Eurydice_borrow_ತುಂಡು_u8 ಒಳಹರಿವು
)
{
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_dc lvalue = { .ದತ್ತಾಂಶ = { ಒಳಹರಿವು } };
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_c5 libcrux_sha3_generic_keccak_xof_zero_ಖಂಡ_35_e90(ಶೂನ್ಯ)
{
  ಹಿಂತಿರುಗಿ (KRML_CLITERAL(Eurydice_arr_c5){ .ದತ್ತಾಂಶ = { 0U } });
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ libcrux_sha3_generic_keccak_xof_KeccakXofState_55
libcrux_sha3_generic_keccak_xof_new_35_e90(ಶೂನ್ಯ)
{
  libcrux_sha3_generic_keccak_xof_KeccakXofState_55 lit;
  lit.inner = libcrux_sha3_generic_keccak_new_80_71();
  Eurydice_arr_c5 repeat_ಅಭಿವ್ಯಕ್ತಿ[1U];
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)1U; i++)
  {
    repeat_ಅಭಿವ್ಯಕ್ತಿ[i] = libcrux_sha3_generic_keccak_xof_zero_ಖಂಡ_35_e90();
  }
  ಸ್ಮರಣೆ_ನಕಲು(lit.buf.ದತ್ತಾಂಶ, repeat_ಅಭಿವ್ಯಕ್ತಿ, (ಗಾತ್ರ_t)1U * ಗಾತ್ರ (Eurydice_arr_c5));
  lit.buf_len = (ಗಾತ್ರ_t)0U;
  lit.sponge = false;
  ಹಿಂತಿರುಗಿ lit;
}

/**
This function found in impl {libcrux_sha3::portable::incremental::Xof<168usize> for libcrux_sha3::portable::incremental::Shake128Xof}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ libcrux_sha3_generic_keccak_xof_KeccakXofState_55
libcrux_sha3_portable_incremental_new_26(ಶೂನ್ಯ)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_generic_keccak_xof_new_35_e90();
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_sha3_generic_keccak_xof_squeeze_85_2a(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_55 *self,
  Eurydice_mut_borrow_ತುಂಡು_u8 ಹೊರಹೋಗು
)
{
  ಗಾತ್ರ_t ಹೊರಹೋಗು_len = ಹೊರಹೋಗು.meta;
  ಆದರೆ (!(ಹೊರಹೋಗು_len == (ಗಾತ್ರ_t)0U))
  {
    ಆದರೆ (self->sponge)
    {
      libcrux_sha3_generic_keccak_keccakf1600_80_71(&self->inner);
    }
    ಆದರೆ (ಹೊರಹೋಗು_len > (ಗಾತ್ರ_t)0U)
    {
      ಗಾತ್ರ_t ಖಂಡಗಳು = ಹೊರಹೋಗು_len / (ಗಾತ್ರ_t)168U;
      ಗಾತ್ರ_t ಕೊನೆಯ = ಹೊರಹೋಗು_len - ಹೊರಹೋಗು_len % (ಗಾತ್ರ_t)168U;
      ಆದರೆ (ಖಂಡಗಳು == (ಗಾತ್ರ_t)0U)
      {
        libcrux_sha3_simd_portable_squeeze_9b_60(&self->inner, ಹೊರಹೋಗು, (ಗಾತ್ರ_t)0U, ಹೊರಹೋಗು_len);
      }
      ಇಲ್ಲದಿದ್ದರೆ
      {
        libcrux_sha3_simd_portable_squeeze_9b_60(&self->inner, ಹೊರಹೋಗು, (ಗಾತ್ರ_t)0U, (ಗಾತ್ರ_t)168U);
        ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)1U; i < ಖಂಡಗಳು; i++)
        {
          ಗಾತ್ರ_t i0 = i;
          libcrux_sha3_generic_keccak_keccakf1600_80_71(&self->inner);
          libcrux_sha3_simd_portable_squeeze_9b_60(&self->inner,
            ಹೊರಹೋಗು,
            i0 * (ಗಾತ್ರ_t)168U,
            (ಗಾತ್ರ_t)168U);
        }
        ಆದರೆ (ಕೊನೆಯ < ಹೊರಹೋಗು_len)
        {
          libcrux_sha3_generic_keccak_keccakf1600_80_71(&self->inner);
          libcrux_sha3_simd_portable_squeeze_9b_60(&self->inner, ಹೊರಹೋಗು, ಕೊನೆಯ, ಹೊರಹೋಗು_len - ಕೊನೆಯ);
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_sha3_portable_incremental_squeeze_26(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_55 *self,
  Eurydice_mut_borrow_ತುಂಡು_u8 ಹೊರಹೋಗು
)
{
  libcrux_sha3_generic_keccak_xof_squeeze_85_2a(self, ಹೊರಹೋಗು);
}

/**
This function found in impl {core::clone::Clone for libcrux_sha3::portable::KeccakState}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_7c libcrux_sha3_portable_clone_fe(ಸ್ಥಿರಾಂಕ Eurydice_arr_7c *self)
{
  ಹಿಂತಿರುಗಿ self[0U];
}

/**
This function found in impl {core::clone::Clone for libcrux_sha3::Algorithm}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ libcrux_sha3_Algorithm libcrux_sha3_clone_e6(ಸ್ಥಿರಾಂಕ libcrux_sha3_Algorithm *self)
{
  ಹಿಂತಿರುಗಿ self[0U];
}

/**
This function found in impl {core::convert::From<libcrux_sha3::Algorithm> for u32}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ uint32_t libcrux_sha3_from_6c(libcrux_sha3_Algorithm v)
{
  ಆಯ್ಕೆ (v)
  {
    ಸ್ಥಿತಿ libcrux_sha3_Algorithm_Sha224:
      {
        ನಿಲ್ಲಿಸು;
      }
    ಸ್ಥಿತಿ libcrux_sha3_Algorithm_Sha256:
      {
        ಹಿಂತಿರುಗಿ 2U;
      }
    ಸ್ಥಿತಿ libcrux_sha3_Algorithm_Sha384:
      {
        ಹಿಂತಿರುಗಿ 3U;
      }
    ಸ್ಥಿತಿ libcrux_sha3_Algorithm_Sha512:
      {
        ಹಿಂತಿರುಗಿ 4U;
      }
    ಪೂರ್ವನಿಯೋಜಿತ:
      {
        KRML_HOST_EPRINTF("KaRaMeL incomplete match at %s:%d\n", __FILE__, __LINE__);
        KRML_HOST_EXIT(253U);
      }
  }
  ಹಿಂತಿರುಗಿ 1U;
}

/**
A monomorphic instance of Eurydice.arr
with types libcrux_sha3_portable_KeccakState
with const generics
- $3size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_1b0_s { Eurydice_arr_7c ದತ್ತಾಂಶ[3U]; } Eurydice_arr_1b0;

#ಆದರೆ defined(__cplusplus)
}
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿಸು libcrux_sha3_portable_H_DEFINED
#ಆದರೆ_ಅಂತ್ಯ /* libcrux_sha3_portable_H */

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


#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ libcrux_mlkem_core_H
#ವ್ಯಾಖ್ಯಾನಿಸು libcrux_mlkem_core_H



#ಆದರೆ defined(__cplusplus)
ಬಾಹ್ಯ "C" {
#ಆದರೆ_ಅಂತ್ಯ


#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_ಗಾತ್ರ ((ಗಾತ್ರ_t)32U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_KEM_CONSTANTS_ಬಿಟ್ಟುಗಳು_ಪ್ರತಿ_COEFFICIENT ((ಗಾತ್ರ_t)12U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_ಒಳ_RING_ELEMENT ((ಗಾತ್ರ_t)256U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_KEM_CONSTANTS_ಬಿಟ್ಟುಗಳು_ಪ್ರತಿ_RING_ELEMENT (LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_ಒಳ_RING_ELEMENT * (ಗಾತ್ರ_t)12U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_KEM_CONSTANTS_ಬೈಟುಗಳು_ಪ್ರತಿ_RING_ELEMENT (LIBCRUX_ML_KEM_CONSTANTS_ಬಿಟ್ಟುಗಳು_ಪ್ರತಿ_RING_ELEMENT / (ಗಾತ್ರ_t)8U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_KEM_CONSTANTS_CPA_PKE_ಕೀಲಿ_GENERATION_ಬೀಜ_ಗಾತ್ರ ((ಗಾತ್ರ_t)32U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_KEM_CONSTANTS_G_DIGEST_ಗಾತ್ರ ((ಗಾತ್ರ_t)64U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_KEM_CONSTANTS_H_DIGEST_ಗಾತ್ರ ((ಗಾತ್ರ_t)32U)

/**
 K * BITS_PER_RING_ELEMENT / 8

 [eurydice] Note that we can't use const generics here because that breaks
            C extraction with eurydice.
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಗಾತ್ರ_t libcrux_ml_kem_constants_ranked_ಬೈಟುಗಳು_ಪ್ರತಿ_ring_element(ಗಾತ್ರ_t rank)
{
  ಹಿಂತಿರುಗಿ rank * LIBCRUX_ML_KEM_CONSTANTS_ಬಿಟ್ಟುಗಳು_ಪ್ರತಿ_RING_ELEMENT / (ಗಾತ್ರ_t)8U;
}

/**
This function found in impl {libcrux_secrets::int::CastOps for i16}
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint8_t libcrux_secrets_int_as_u8_f5(int16_t self)
{
  ಹಿಂತಿರುಗಿ
    libcrux_secrets_int_ಬಹಿರಂಗ_integers_classify_27_90((uint8_t)libcrux_secrets_int_ಬಹಿರಂಗ_integers_declassify_d8_39(self));
}

/**
This function found in impl {libcrux_secrets::int::CastOps for u8}
*/
ಸ್ಥಿರ KRML_MUSTINLINE int16_t libcrux_secrets_int_as_i16_59(uint8_t self)
{
  ಹಿಂತಿರುಗಿ
    libcrux_secrets_int_ಬಹಿರಂಗ_integers_classify_27_39((int16_t)(uint32_t)libcrux_secrets_int_ಬಹಿರಂಗ_integers_declassify_d8_90(self));
}

/**
This function found in impl {libcrux_secrets::int::CastOps for i16}
*/
ಸ್ಥಿರ KRML_MUSTINLINE int32_t libcrux_secrets_int_as_i32_f5(int16_t self)
{
  ಹಿಂತಿರುಗಿ
    libcrux_secrets_int_ಬಹಿರಂಗ_integers_classify_27_a8((int32_t)libcrux_secrets_int_ಬಹಿರಂಗ_integers_declassify_d8_39(self));
}

/**
This function found in impl {libcrux_secrets::int::CastOps for i32}
*/
ಸ್ಥಿರ KRML_MUSTINLINE int16_t libcrux_secrets_int_as_i16_36(int32_t self)
{
  ಹಿಂತಿರುಗಿ
    libcrux_secrets_int_ಬಹಿರಂಗ_integers_classify_27_39((int16_t)libcrux_secrets_int_ಬಹಿರಂಗ_integers_declassify_d8_a8(self));
}

/**
This function found in impl {libcrux_secrets::int::CastOps for u32}
*/
ಸ್ಥಿರ KRML_MUSTINLINE int32_t libcrux_secrets_int_as_i32_b8(uint32_t self)
{
  ಹಿಂತಿರುಗಿ
    libcrux_secrets_int_ಬಹಿರಂಗ_integers_classify_27_a8((int32_t)libcrux_secrets_int_ಬಹಿರಂಗ_integers_declassify_d8_df(self));
}

/**
This function found in impl {libcrux_secrets::int::CastOps for i16}
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint16_t libcrux_secrets_int_as_u16_f5(int16_t self)
{
  ಹಿಂತಿರುಗಿ
    libcrux_secrets_int_ಬಹಿರಂಗ_integers_classify_27_de((uint16_t)libcrux_secrets_int_ಬಹಿರಂಗ_integers_declassify_d8_39(self));
}

/**
This function found in impl {libcrux_secrets::int::CastOps for u16}
*/
ಸ್ಥಿರ KRML_MUSTINLINE int16_t libcrux_secrets_int_as_i16_ca(uint16_t self)
{
  ಹಿಂತಿರುಗಿ
    libcrux_secrets_int_ಬಹಿರಂಗ_integers_classify_27_39((int16_t)(uint32_t)libcrux_secrets_int_ಬಹಿರಂಗ_integers_declassify_d8_de(self));
}

/**
This function found in impl {libcrux_secrets::int::CastOps for u16}
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint64_t libcrux_secrets_int_as_u64_ca(uint16_t self)
{
  ಹಿಂತಿರುಗಿ
    libcrux_secrets_int_ಬಹಿರಂಗ_integers_classify_27_49((uint64_t)(uint32_t)libcrux_secrets_int_ಬಹಿರಂಗ_integers_declassify_d8_de(self));
}

/**
This function found in impl {libcrux_secrets::int::CastOps for u64}
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint32_t libcrux_secrets_int_as_u32_a3(uint64_t self)
{
  ಹಿಂತಿರುಗಿ
    libcrux_secrets_int_ಬಹಿರಂಗ_integers_classify_27_df((uint32_t)libcrux_secrets_int_ಬಹಿರಂಗ_integers_declassify_d8_49(self));
}

/**
This function found in impl {libcrux_secrets::int::CastOps for u32}
*/
ಸ್ಥಿರ KRML_MUSTINLINE int16_t libcrux_secrets_int_as_i16_b8(uint32_t self)
{
  ಹಿಂತಿರುಗಿ
    libcrux_secrets_int_ಬಹಿರಂಗ_integers_classify_27_39((int16_t)libcrux_secrets_int_ಬಹಿರಂಗ_integers_declassify_d8_df(self));
}

/**
This function found in impl {libcrux_secrets::int::CastOps for i16}
*/
ಸ್ಥಿರ KRML_MUSTINLINE int16_t libcrux_secrets_int_as_i16_f5(int16_t self)
{
  ಹಿಂತಿರುಗಿ
    libcrux_secrets_int_ಬಹಿರಂಗ_integers_classify_27_39(libcrux_secrets_int_ಬಹಿರಂಗ_integers_declassify_d8_39(self));
}

/**
 Pad the `slice` with `0`s at the end.
*/
/**
A monomorphic instance of libcrux_ml_kem.utils.into_padded_array
with const generics
- LEN= 32
*/
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_ec
libcrux_ml_kem_utils_into_padded_array_ce(Eurydice_borrow_ತುಂಡು_u8 ತುಂಡು)
{
  Eurydice_arr_ec ಹೊರಹೋಗು = { .ದತ್ತಾಂಶ = { 0U } };
  Eurydice_ತುಂಡು_copy(Eurydice_array_ಗಮ್ಯ_subslice_mut_d46(&ಹೊರಹೋಗು,
      (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = (ಗಾತ್ರ_t)0U, .ಕೊನೆ = ತುಂಡು.meta })),
    ತುಂಡು,
    uint8_t);
  ಹಿಂತಿರುಗಿ ಹೊರಹೋಗು;
}

/**
This function found in impl {core::default::Default for libcrux_ml_kem::types::MlKemPrivateKey<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.default_d3
with const generics
- SIZE= 2400
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_7d libcrux_ml_kem_types_default_d3_79(ಶೂನ್ಯ)
{
  ಹಿಂತಿರುಗಿ (KRML_CLITERAL(Eurydice_arr_7d){ .ದತ್ತಾಂಶ = { 0U } });
}

/**
This function found in impl {core::convert::From<[u8; SIZE]> for libcrux_ml_kem::types::MlKemPublicKey<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.from_51
with const generics
- SIZE= 1184
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_5f libcrux_ml_kem_types_from_51_3d(Eurydice_arr_5f ಮೌಲ್ಯ)
{
  ಹಿಂತಿರುಗಿ ಮೌಲ್ಯ;
}

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ libcrux_ml_kem_mlkem768_Ml_Kem768_ಕೀಲಿ_Pair_s
{
  Eurydice_arr_7d sk;
  Eurydice_arr_5f pk;
}
libcrux_ml_kem_mlkem768_Ml_Kem768_ಕೀಲಿ_Pair;

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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ libcrux_ml_kem_mlkem768_Ml_Kem768_ಕೀಲಿ_Pair
libcrux_ml_kem_types_from_17_bc(Eurydice_arr_7d sk, Eurydice_arr_5f pk)
{
  ಹಿಂತಿರುಗಿ (KRML_CLITERAL(libcrux_ml_kem_mlkem768_Ml_Kem768_ಕೀಲಿ_Pair){ .sk = sk, .pk = pk });
}

/**
This function found in impl {core::convert::From<[u8; SIZE]> for libcrux_ml_kem::types::MlKemPrivateKey<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.from_b2
with const generics
- SIZE= 2400
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_7d libcrux_ml_kem_types_from_b2_79(Eurydice_arr_7d ಮೌಲ್ಯ)
{
  ಹಿಂತಿರುಗಿ ಮೌಲ್ಯ;
}

/**
A monomorphic instance of n-tuple
with types libcrux_ml_kem_mlkem768_MlKem768Ciphertext, Eurydice_arr_ec

*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ tuple_f4_s
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_2b libcrux_ml_kem_types_from_19_52(Eurydice_arr_2b ಮೌಲ್ಯ)
{
  ಹಿಂತಿರುಗಿ ಮೌಲ್ಯ;
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಸ್ಥಿರಾಂಕ
Eurydice_arr_5f
*libcrux_ml_kem_types_as_ತುಂಡು_e6_3d(ಸ್ಥಿರಾಂಕ Eurydice_arr_5f *self)
{
  ಹಿಂತಿರುಗಿ self;
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಸ್ಥಿರಾಂಕ
Eurydice_arr_2b
*libcrux_ml_kem_types_as_ತುಂಡು_a9_52(ಸ್ಥಿರಾಂಕ Eurydice_arr_2b *self)
{
  ಹಿಂತಿರುಗಿ self;
}

/**
A monomorphic instance of libcrux_ml_kem.utils.prf_input_inc
with const generics
- K= 3
*/
ಸ್ಥಿರ KRML_MUSTINLINE uint8_t
libcrux_ml_kem_utils_prf_ಒಳಹರಿವು_inc_78(Eurydice_arr_fd *prf_inputs, uint8_t domain_separator)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)3U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    prf_inputs->ದತ್ತಾಂಶ[i0].ದತ್ತಾಂಶ[32U] = domain_separator;
    domain_separator = (uint32_t)domain_separator + 1U;
  }
  ಹಿಂತಿರುಗಿ domain_separator;
}

/**
 Pad the `slice` with `0`s at the end.
*/
/**
A monomorphic instance of libcrux_ml_kem.utils.into_padded_array
with const generics
- LEN= 33
*/
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_fa0
libcrux_ml_kem_utils_into_padded_array_29(Eurydice_borrow_ತುಂಡು_u8 ತುಂಡು)
{
  Eurydice_arr_fa0 ಹೊರಹೋಗು = { .ದತ್ತಾಂಶ = { 0U } };
  Eurydice_ತುಂಡು_copy(Eurydice_array_ಗಮ್ಯ_subslice_mut_d412(&ಹೊರಹೋಗು,
      (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = (ಗಾತ್ರ_t)0U, .ಕೊನೆ = ತುಂಡು.meta })),
    ತುಂಡು,
    uint8_t);
  ಹಿಂತಿರುಗಿ ಹೊರಹೋಗು;
}

/**
 Pad the `slice` with `0`s at the end.
*/
/**
A monomorphic instance of libcrux_ml_kem.utils.into_padded_array
with const generics
- LEN= 34
*/
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_31
libcrux_ml_kem_utils_into_padded_array_de(Eurydice_borrow_ತುಂಡು_u8 ತುಂಡು)
{
  Eurydice_arr_31 ಹೊರಹೋಗು = { .ದತ್ತಾಂಶ = { 0U } };
  Eurydice_ತುಂಡು_copy(Eurydice_array_ಗಮ್ಯ_subslice_mut_d40(&ಹೊರಹೋಗು,
      (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = (ಗಾತ್ರ_t)0U, .ಕೊನೆ = ತುಂಡು.meta })),
    ತುಂಡು,
    uint8_t);
  ಹಿಂತಿರುಗಿ ಹೊರಹೋಗು;
}

/**
This function found in impl {core::convert::AsRef<[u8]> for libcrux_ml_kem::types::MlKemCiphertext<SIZE>}
*/
/**
A monomorphic instance of libcrux_ml_kem.types.as_ref_c1
with const generics
- SIZE= 1088
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
libcrux_ml_kem_types_as_ref_c1_52(ಸ್ಥಿರಾಂಕ Eurydice_arr_2b *self)
{
  ಹಿಂತಿರುಗಿ Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_06(self);
}

/**
 Pad the `slice` with `0`s at the end.
*/
/**
A monomorphic instance of libcrux_ml_kem.utils.into_padded_array
with const generics
- LEN= 1120
*/
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_af
libcrux_ml_kem_utils_into_padded_array_66(Eurydice_borrow_ತುಂಡು_u8 ತುಂಡು)
{
  Eurydice_arr_af ಹೊರಹೋಗು = { .ದತ್ತಾಂಶ = { 0U } };
  Eurydice_ತುಂಡು_copy(Eurydice_array_ಗಮ್ಯ_subslice_mut_d411(&ಹೊರಹೋಗು,
      (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = (ಗಾತ್ರ_t)0U, .ಕೊನೆ = ತುಂಡು.meta })),
    ತುಂಡು,
    uint8_t);
  ಹಿಂತಿರುಗಿ ಹೊರಹೋಗು;
}

/**
 Pad the `slice` with `0`s at the end.
*/
/**
A monomorphic instance of libcrux_ml_kem.utils.into_padded_array
with const generics
- LEN= 64
*/
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_c7
libcrux_ml_kem_utils_into_padded_array_c9(Eurydice_borrow_ತುಂಡು_u8 ತುಂಡು)
{
  Eurydice_arr_c7 ಹೊರಹೋಗು = { .ದತ್ತಾಂಶ = { 0U } };
  Eurydice_ತುಂಡು_copy(Eurydice_array_ಗಮ್ಯ_subslice_mut_d410(&ಹೊರಹೋಗು,
      (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = (ಗಾತ್ರ_t)0U, .ಕೊನೆ = ತುಂಡು.meta })),
    ತುಂಡು,
    uint8_t);
  ಹಿಂತಿರುಗಿ ಹೊರಹೋಗು;
}

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_borrow_ತುಂಡು_u8_x4_s
{
  Eurydice_borrow_ತುಂಡು_u8 fst;
  Eurydice_borrow_ತುಂಡು_u8 snd;
  Eurydice_borrow_ತುಂಡು_u8 thd;
  Eurydice_borrow_ತುಂಡು_u8 f3;
}
Eurydice_borrow_ತುಂಡು_u8_x4;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_borrow_ತುಂಡು_u8_x2_s
{
  Eurydice_borrow_ತುಂಡು_u8 fst;
  Eurydice_borrow_ತುಂಡು_u8 snd;
}
Eurydice_borrow_ತುಂಡು_u8_x2;

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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8_x4
libcrux_ml_kem_types_unpack_ಖಾಸಗಿ_ಕೀಲಿ_64(Eurydice_borrow_ತುಂಡು_u8 ಖಾಸಗಿ_ಕೀಲಿ)
{
  Eurydice_borrow_ತುಂಡು_u8_x2
  uu____0 =
    Eurydice_ತುಂಡು_ವಿಭಜಿಸು_at(ಖಾಸಗಿ_ಕೀಲಿ,
      (ಗಾತ್ರ_t)1152U,
      uint8_t,
      Eurydice_borrow_ತುಂಡು_u8_x2);
  Eurydice_borrow_ತುಂಡು_u8 ind_cpa_secret_ಕೀಲಿ = uu____0.fst;
  Eurydice_borrow_ತುಂಡು_u8 secret_key0 = uu____0.snd;
  Eurydice_borrow_ತುಂಡು_u8_x2
  uu____1 =
    Eurydice_ತುಂಡು_ವಿಭಜಿಸು_at(secret_key0,
      (ಗಾತ್ರ_t)1184U,
      uint8_t,
      Eurydice_borrow_ತುಂಡು_u8_x2);
  Eurydice_borrow_ತುಂಡು_u8 ind_cpa_ಬಹಿರಂಗ_ಕೀಲಿ = uu____1.fst;
  Eurydice_borrow_ತುಂಡು_u8 secret_ಕೀಲಿ = uu____1.snd;
  Eurydice_borrow_ತುಂಡು_u8_x2
  uu____2 =
    Eurydice_ತುಂಡು_ವಿಭಜಿಸು_at(secret_ಕೀಲಿ,
      LIBCRUX_ML_KEM_CONSTANTS_H_DIGEST_ಗಾತ್ರ,
      uint8_t,
      Eurydice_borrow_ತುಂಡು_u8_x2);
  Eurydice_borrow_ತುಂಡು_u8 ind_cpa_ಬಹಿರಂಗ_ಕೀಲಿ_hash = uu____2.fst;
  Eurydice_borrow_ತುಂಡು_u8 implicit_rejection_ಮೌಲ್ಯ = uu____2.snd;
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(Eurydice_borrow_ತುಂಡು_u8_x4){
        .fst = ind_cpa_secret_ಕೀಲಿ,
        .snd = ind_cpa_ಬಹಿರಂಗ_ಕೀಲಿ,
        .thd = ind_cpa_ಬಹಿರಂಗ_ಕೀಲಿ_hash,
        .f3 = implicit_rejection_ಮೌಲ್ಯ
      }
    );
}

#ಆದರೆ defined(__cplusplus)
}
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿಸು libcrux_mlkem_core_H_DEFINED
#ಆದರೆ_ಅಂತ್ಯ /* libcrux_mlkem_core_H */

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


#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ libcrux_mldsa_core_H
#ವ್ಯಾಖ್ಯಾನಿಸು libcrux_mldsa_core_H



#ಆದರೆ defined(__cplusplus)
ಬಾಹ್ಯ "C" {
#ಆದರೆ_ಅಂತ್ಯ


#ವ್ಯಾಖ್ಯಾನಿಸು libcrux_ml_dsa_constants_Eta_Two 2
#ವ್ಯಾಖ್ಯಾನಿಸು libcrux_ml_dsa_constants_Eta_Four 4

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ uint8_t libcrux_ml_dsa_constants_Eta;

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_SIMD_TRAITS_COEFFICIENTS_ಒಳ_SIMD_UNIT ((ಗಾತ್ರ_t)8U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_SIMD_TRAITS_SIMD_UNITS_ಒಳ_RING_ELEMENT ((ಗಾತ್ರ_t)32U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_ಬಿಟ್ಟುಗಳು_ಒಳ_ಅಧೋ_PART_ದ_T ((ಗಾತ್ರ_t)13U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_ಕ್ಷೇತ್ರ_MODULUS_MINUS_ONE_ಬಿಟ್_ಉದ್ದಳತೆ ((ಗಾತ್ರ_t)23U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_ಬಿಟ್ಟುಗಳು_ಒಳ_ಊರ್ಧ್ವ_PART_ದ_T (LIBCRUX_ML_DSA_CONSTANTS_ಕ್ಷೇತ್ರ_MODULUS_MINUS_ONE_ಬಿಟ್_ಉದ್ದಳತೆ - LIBCRUX_ML_DSA_CONSTANTS_ಬಿಟ್ಟುಗಳು_ಒಳ_ಅಧೋ_PART_ದ_T)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_ಬೈಟುಗಳು_FOR_VERIFICATION_ಕೀಲಿ_HASH ((ಗಾತ್ರ_t)64U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_ಒಳ_RING_ELEMENT ((ಗಾತ್ರ_t)256U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_CONTEXT_MAX_LEN ((ಗಾತ್ರ_t)255U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_ಕ್ಷೇತ್ರ_MODULUS (8380417)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_GAMMA2_V261_888 (261888)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_GAMMA2_V95_232 (95232)

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ int32_t libcrux_ml_dsa_constants_Gamma2;

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_ಕೀಲಿ_GENERATION_RANDOMNESS_ಗಾತ್ರ ((ಗಾತ್ರ_t)32U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_ಮುಖವಾಡ_ಬೀಜ_ಗಾತ್ರ ((ಗಾತ್ರ_t)64U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_ಸಂದೇಶ_REPRESENTATIVE_ಗಾತ್ರ ((ಗಾತ್ರ_t)64U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_REJECTION_SAMPLE_BOUND_SIGN ((ಗಾತ್ರ_t)814U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_ದ_T0_S_ಗಾತ್ರ (LIBCRUX_ML_DSA_CONSTANTS_ಬಿಟ್ಟುಗಳು_ಒಳ_ಅಧೋ_PART_ದ_T * LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_ಒಳ_RING_ELEMENT / (ಗಾತ್ರ_t)8U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_ದ_T1_S_ಗಾತ್ರ (LIBCRUX_ML_DSA_CONSTANTS_ಬಿಟ್ಟುಗಳು_ಒಳ_ಊರ್ಧ್ವ_PART_ದ_T * LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_ಒಳ_RING_ELEMENT / (ಗಾತ್ರ_t)8U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_ಬೀಜ_FOR_A_ಗಾತ್ರ ((ಗಾತ್ರ_t)32U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_ಬೀಜ_FOR_ERROR_VECTORS_ಗಾತ್ರ ((ಗಾತ್ರ_t)64U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_ಬೀಜ_FOR_SIGNING_ಗಾತ್ರ ((ಗಾತ್ರ_t)32U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_SIGNING_RANDOMNESS_ಗಾತ್ರ ((ಗಾತ್ರ_t)32U)

ಸ್ಥಿರ ಸಾಲೊಳಗೆ int32_t
libcrux_ml_dsa_constants_beta(
  ಗಾತ್ರ_t ones_ಒಳ_verifier_challenge,
  libcrux_ml_dsa_constants_Eta eta
)
{
  ಗಾತ್ರ_t eta_val;
  ಆಯ್ಕೆ (eta)
  {
    ಸ್ಥಿತಿ libcrux_ml_dsa_constants_Eta_Two:
      {
        eta_val = (ಗಾತ್ರ_t)2U;
        ನಿಲ್ಲಿಸು;
      }
    ಸ್ಥಿತಿ libcrux_ml_dsa_constants_Eta_Four:
      {
        eta_val = (ಗಾತ್ರ_t)4U;
        ನಿಲ್ಲಿಸು;
      }
    ಪೂರ್ವನಿಯೋಜಿತ:
      {
        KRML_HOST_EPRINTF("KaRaMeL incomplete match at %s:%d\n", __FILE__, __LINE__);
        KRML_HOST_EXIT(253U);
      }
  }
  ಹಿಂತಿರುಗಿ (int32_t)(ones_ಒಳ_verifier_challenge * eta_val);
}

ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಗಾತ್ರ_t
libcrux_ml_dsa_constants_commitment_ring_element_ಗಾತ್ರ(ಗಾತ್ರ_t ಬಿಟ್ಟುಗಳು_ಪ್ರತಿ_commitment_coefficient)
{
  ಹಿಂತಿರುಗಿ
    ಬಿಟ್ಟುಗಳು_ಪ್ರತಿ_commitment_coefficient * LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_ಒಳ_RING_ELEMENT /
      (ಗಾತ್ರ_t)8U;
}

ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಗಾತ್ರ_t
libcrux_ml_dsa_constants_commitment_ಸದಿಶ_ಗಾತ್ರ(
  ಗಾತ್ರ_t ಬಿಟ್ಟುಗಳು_ಪ್ರತಿ_commitment_coefficient,
  ಗಾತ್ರ_t ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_a
)
{
  ಹಿಂತಿರುಗಿ
    libcrux_ml_dsa_constants_commitment_ring_element_ಗಾತ್ರ(ಬಿಟ್ಟುಗಳು_ಪ್ರತಿ_commitment_coefficient) *
      ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_a;
}

ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಗಾತ್ರ_t
libcrux_ml_dsa_constants_error_ring_element_ಗಾತ್ರ(ಗಾತ್ರ_t ಬಿಟ್ಟುಗಳು_ಪ್ರತಿ_error_coefficient)
{
  ಹಿಂತಿರುಗಿ
    ಬಿಟ್ಟುಗಳು_ಪ್ರತಿ_error_coefficient * LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_ಒಳ_RING_ELEMENT / (ಗಾತ್ರ_t)8U;
}

ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಗಾತ್ರ_t
libcrux_ml_dsa_constants_gamma1_ring_element_ಗಾತ್ರ(ಗಾತ್ರ_t ಬಿಟ್ಟುಗಳು_ಪ್ರತಿ_gamma1_coefficient)
{
  ಹಿಂತಿರುಗಿ
    ಬಿಟ್ಟುಗಳು_ಪ್ರತಿ_gamma1_coefficient * LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_ಒಳ_RING_ELEMENT /
      (ಗಾತ್ರ_t)8U;
}

ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಗಾತ್ರ_t
libcrux_ml_dsa_constants_signature_ಗಾತ್ರ(
  ಗಾತ್ರ_t ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_a,
  ಗಾತ್ರ_t columns_ಒಳ_a,
  ಗಾತ್ರ_t max_ones_ಒಳ_hint,
  ಗಾತ್ರ_t commitment_hash_ಗಾತ್ರ,
  ಗಾತ್ರ_t ಬಿಟ್ಟುಗಳು_ಪ್ರತಿ_gamma1_coefficient
)
{
  ಹಿಂತಿರುಗಿ
    commitment_hash_ಗಾತ್ರ +
      columns_ಒಳ_a * libcrux_ml_dsa_constants_gamma1_ring_element_ಗಾತ್ರ(ಬಿಟ್ಟುಗಳು_ಪ್ರತಿ_gamma1_coefficient)
    + max_ones_ಒಳ_hint
    + ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_a;
}

ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಗಾತ್ರ_t
libcrux_ml_dsa_constants_signing_ಕೀಲಿ_ಗಾತ್ರ(
  ಗಾತ್ರ_t ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_a,
  ಗಾತ್ರ_t columns_ಒಳ_a,
  ಗಾತ್ರ_t error_ring_element_ಗಾತ್ರ
)
{
  ಹಿಂತಿರುಗಿ
    LIBCRUX_ML_DSA_CONSTANTS_ಬೀಜ_FOR_A_ಗಾತ್ರ + LIBCRUX_ML_DSA_CONSTANTS_ಬೀಜ_FOR_SIGNING_ಗಾತ್ರ +
      LIBCRUX_ML_DSA_CONSTANTS_ಬೈಟುಗಳು_FOR_VERIFICATION_ಕೀಲಿ_HASH
    + (ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_a + columns_ಒಳ_a) * error_ring_element_ಗಾತ್ರ
    + ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_a * LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_ದ_T0_S_ಗಾತ್ರ;
}

ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಗಾತ್ರ_t libcrux_ml_dsa_constants_verification_ಕೀಲಿ_ಗಾತ್ರ(ಗಾತ್ರ_t ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_a)
{
  ಹಿಂತಿರುಗಿ
    LIBCRUX_ML_DSA_CONSTANTS_ಬೀಜ_FOR_A_ಗಾತ್ರ +
      LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_ಒಳ_RING_ELEMENT * ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_a *
        (LIBCRUX_ML_DSA_CONSTANTS_ಕ್ಷೇತ್ರ_MODULUS_MINUS_ONE_ಬಿಟ್_ಉದ್ದಳತೆ -
          LIBCRUX_ML_DSA_CONSTANTS_ಬಿಟ್ಟುಗಳು_ಒಳ_ಅಧೋ_PART_ದ_T)
      / (ಗಾತ್ರ_t)8U;
}

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ಬಿಟ್ಟುಗಳು_ಪ್ರತಿ_COMMITMENT_COEFFICIENT ((ಗಾತ್ರ_t)6U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ಬಿಟ್ಟುಗಳು_ಪ್ರತಿ_ERROR_COEFFICIENT ((ಗಾತ್ರ_t)3U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ಬಿಟ್ಟುಗಳು_ಪ್ರತಿ_GAMMA1_COEFFICIENT ((ಗಾತ್ರ_t)18U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_ಒಳ_A ((ಗಾತ್ರ_t)4U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COMMITMENT_HASH_ಗಾತ್ರ ((ಗಾತ್ರ_t)32U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ETA (libcrux_ml_dsa_constants_Eta_Two)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_GAMMA1_EXPONENT ((ಗಾತ್ರ_t)17U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_GAMMA2 ((LIBCRUX_ML_DSA_CONSTANTS_ಕ್ಷೇತ್ರ_MODULUS - 1) / 88)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_MAX_ONES_ಒಳ_HINT ((ಗಾತ್ರ_t)80U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ONES_ಒಳ_VERIFIER_CHALLENGE ((ಗಾತ್ರ_t)39U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A ((ಗಾತ್ರ_t)4U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ಬಿಟ್ಟುಗಳು_ಪ್ರತಿ_COMMITMENT_COEFFICIENT ((ಗಾತ್ರ_t)4U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ಬಿಟ್ಟುಗಳು_ಪ್ರತಿ_ERROR_COEFFICIENT ((ಗಾತ್ರ_t)4U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ಬಿಟ್ಟುಗಳು_ಪ್ರತಿ_GAMMA1_COEFFICIENT ((ಗಾತ್ರ_t)20U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_ಒಳ_A ((ಗಾತ್ರ_t)5U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COMMITMENT_HASH_ಗಾತ್ರ ((ಗಾತ್ರ_t)48U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ETA (libcrux_ml_dsa_constants_Eta_Four)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA1_EXPONENT ((ಗಾತ್ರ_t)19U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA2 ((LIBCRUX_ML_DSA_CONSTANTS_ಕ್ಷೇತ್ರ_MODULUS - 1) / 32)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_MAX_ONES_ಒಳ_HINT ((ಗಾತ್ರ_t)55U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ONES_ಒಳ_VERIFIER_CHALLENGE ((ಗಾತ್ರ_t)49U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A ((ಗಾತ್ರ_t)6U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ಬಿಟ್ಟುಗಳು_ಪ್ರತಿ_COMMITMENT_COEFFICIENT ((ಗಾತ್ರ_t)4U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ಬಿಟ್ಟುಗಳು_ಪ್ರತಿ_ERROR_COEFFICIENT ((ಗಾತ್ರ_t)3U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ಬಿಟ್ಟುಗಳು_ಪ್ರತಿ_GAMMA1_COEFFICIENT ((ಗಾತ್ರ_t)20U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_ಒಳ_A ((ಗಾತ್ರ_t)7U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COMMITMENT_HASH_ಗಾತ್ರ ((ಗಾತ್ರ_t)64U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ETA (libcrux_ml_dsa_constants_Eta_Two)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_GAMMA1_EXPONENT ((ಗಾತ್ರ_t)19U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_GAMMA2 ((LIBCRUX_ML_DSA_CONSTANTS_ಕ್ಷೇತ್ರ_MODULUS - 1) / 32)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_MAX_ONES_ಒಳ_HINT ((ಗಾತ್ರ_t)75U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ONES_ಒಳ_VERIFIER_CHALLENGE ((ಗಾತ್ರ_t)60U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A ((ಗಾತ್ರ_t)8U)

/**
This function found in impl {core::clone::Clone for libcrux_ml_dsa::constants::Eta}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ libcrux_ml_dsa_constants_Eta
libcrux_ml_dsa_constants_clone_54(ಸ್ಥಿರಾಂಕ libcrux_ml_dsa_constants_Eta *self)
{
  ಹಿಂತಿರುಗಿ self[0U];
}

ಸ್ಥಿರ KRML_MUSTINLINE ಗಾತ್ರ_t
libcrux_ml_dsa_encoding_error_chunk_ಗಾತ್ರ(libcrux_ml_dsa_constants_Eta eta)
{
  ಆಯ್ಕೆ (eta)
  {
    ಸ್ಥಿತಿ libcrux_ml_dsa_constants_Eta_Two:
      {
        ನಿಲ್ಲಿಸು;
      }
    ಸ್ಥಿತಿ libcrux_ml_dsa_constants_Eta_Four:
      {
        ಹಿಂತಿರುಗಿ (ಗಾತ್ರ_t)4U;
      }
    ಪೂರ್ವನಿಯೋಜಿತ:
      {
        KRML_HOST_EPRINTF("KaRaMeL incomplete match at %s:%d\n", __FILE__, __LINE__);
        KRML_HOST_EXIT(253U);
      }
  }
  ಹಿಂತಿರುಗಿ (ಗಾತ್ರ_t)3U;
}

#ವ್ಯಾಖ್ಯಾನಿಸು libcrux_ml_dsa_types_VerificationError_MalformedHintError 0
#ವ್ಯಾಖ್ಯಾನಿಸು libcrux_ml_dsa_types_VerificationError_SignerResponseExceedsBoundError 1
#ವ್ಯಾಖ್ಯಾನಿಸು libcrux_ml_dsa_types_Verification_Error_Commitment_Hashes_Dont_ಹೊಂದಿಕೆ_Error 2
#ವ್ಯಾಖ್ಯಾನಿಸು libcrux_ml_dsa_types_VerificationError_VerificationContextTooLongError 3

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ uint8_t libcrux_ml_dsa_types_VerificationError;

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_encoding_signature_ಗಣ_hint(
  Eurydice_dst_ref_mut_20 ಹೊರಹೋಗು_hint,
  ಗಾತ್ರ_t i,
  ಗಾತ್ರ_t j
)
{
  ಹೊರಹೋಗು_hint.ptr[i].ದತ್ತಾಂಶ[j] = 1;
}

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_ENCODING_T0_OUTPUT_ಬೈಟುಗಳು_ಪ್ರತಿ_SIMD_UNIT ((ಗಾತ್ರ_t)13U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_ENCODING_T1_DESERIALIZE_ಕಿಟಕಿ ((ಗಾತ್ರ_t)10U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_ENCODING_T1_SERIALIZE_OUTPUT_ಬೈಟುಗಳು_ಪ್ರತಿ_SIMD_UNIT ((ಗಾತ್ರ_t)10U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_HASH_FUNCTIONS_SHAKE128_ಖಂಡ_ಗಾತ್ರ ((ಗಾತ್ರ_t)168U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_HASH_FUNCTIONS_SHAKE128_FIVE_ಖಂಡಗಳು_ಗಾತ್ರ (LIBCRUX_ML_DSA_HASH_FUNCTIONS_SHAKE128_ಖಂಡ_ಗಾತ್ರ * (ಗಾತ್ರ_t)5U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_HASH_FUNCTIONS_SHAKE256_ಖಂಡ_ಗಾತ್ರ ((ಗಾತ್ರ_t)136U)

ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_91
libcrux_ml_dsa_sample_ಕೂಡಿಸು_error_domain_separator(
  Eurydice_borrow_ತುಂಡು_u8 ತುಂಡು,
  uint16_t domain_separator
)
{
  Eurydice_arr_91 ಹೊರಹೋಗು = { .ದತ್ತಾಂಶ = { 0U } };
  Eurydice_ತುಂಡು_copy(Eurydice_array_ಗಮ್ಯ_subslice_mut_d4(&ಹೊರಹೋಗು,
      (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = (ಗಾತ್ರ_t)0U, .ಕೊನೆ = ತುಂಡು.meta })),
    ತುಂಡು,
    uint8_t);
  ಹೊರಹೋಗು.ದತ್ತಾಂಶ[64U] = (uint8_t)(uint32_t)domain_separator;
  ಹೊರಹೋಗು.ದತ್ತಾಂಶ[65U] = (uint8_t)((uint32_t)domain_separator >> 8U & 0xFFFFU);
  ಹಿಂತಿರುಗಿ ಹೊರಹೋಗು;
}

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_ERROR_RING_ELEMENT_ಗಾತ್ರ (libcrux_ml_dsa_constants_error_ring_element_ಗಾತ್ರ(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ಬಿಟ್ಟುಗಳು_ಪ್ರತಿ_ERROR_COEFFICIENT))

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_SIMD_TRAITS_ಕ್ಷೇತ್ರ_MODULUS (8380417)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_SIMD_TRAITS_INVERSE_ದ_MODULUS_MOD_MONTGOMERY_R (58728449ULL)

ಸ್ಥಿರ ಸಾಲೊಳಗೆ uint8_t_x2
libcrux_ml_dsa_sample_sample_ಮೇಲೆ_ಗಮ್ಯ_four_ring_elements_flat_xy(ಗಾತ್ರ_t index, ಗಾತ್ರ_t ಅಗಲ)
{
  ಹಿಂತಿರುಗಿ
    (KRML_CLITERAL(uint8_t_x2){ .fst = (uint8_t)(index / ಅಗಲ), .snd = (uint8_t)(index % ಅಗಲ) });
}

ಸ್ಥಿರ KRML_MUSTINLINE uint16_t libcrux_ml_dsa_sample_generate_domain_separator(uint8_t_x2 _)
{
  uint8_t ಅಡ್ಡಸಾಲು = _.fst;
  uint8_t ಸ್ತಂಭ = _.snd;
  ಹಿಂತಿರುಗಿ (uint32_t)(uint16_t)(uint32_t)ಸ್ತಂಭ | (uint32_t)(uint16_t)(uint32_t)ಅಡ್ಡಸಾಲು << 8U;
}

ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_31
libcrux_ml_dsa_sample_ಕೂಡಿಸು_domain_separator(Eurydice_borrow_ತುಂಡು_u8 ತುಂಡು, uint8_t_x2 indices)
{
  Eurydice_arr_31 ಹೊರಹೋಗು = { .ದತ್ತಾಂಶ = { 0U } };
  Eurydice_ತುಂಡು_copy(Eurydice_array_ಗಮ್ಯ_subslice_mut_d40(&ಹೊರಹೋಗು,
      (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = (ಗಾತ್ರ_t)0U, .ಕೊನೆ = ತುಂಡು.meta })),
    ತುಂಡು,
    uint8_t);
  uint16_t domain_separator = libcrux_ml_dsa_sample_generate_domain_separator(indices);
  ಹೊರಹೋಗು.ದತ್ತಾಂಶ[32U] = (uint8_t)(uint32_t)domain_separator;
  ಹೊರಹೋಗು.ದತ್ತಾಂಶ[33U] = (uint8_t)((uint32_t)domain_separator >> 8U & 0xFFFFU);
  ಹಿಂತಿರುಗಿ ಹೊರಹೋಗು;
}

#ವ್ಯಾಖ್ಯಾನಿಸು libcrux_ml_dsa_types_SigningError_RejectionSamplingError 0
#ವ್ಯಾಖ್ಯಾನಿಸು libcrux_ml_dsa_types_SigningError_ContextTooLongError 1

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ uint8_t libcrux_ml_dsa_types_SigningError;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ libcrux_ml_dsa_pre_hash_DomainSeparationContext_s
{
  Eurydice_borrow_ತುಂಡು_u8 context;
  core_option_Option_57 pre_hash_oid;
}
libcrux_ml_dsa_pre_hash_DomainSeparationContext;

#ವ್ಯಾಖ್ಯಾನಿಸು libcrux_ml_dsa_pre_hash_DomainSeparationError_ContextTooLongError 0

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ uint8_t libcrux_ml_dsa_pre_hash_DomainSeparationError;

/**
A monomorphic instance of core.result.Result
with types libcrux_ml_dsa_pre_hash_DomainSeparationContext, libcrux_ml_dsa_pre_hash_DomainSeparationError

*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_a8_s
{
  core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_57_ಟ್ಯಾಗುಗಳು ಟ್ಯಾಗ್;
  ಒಕ್ಕೂಟ {
    libcrux_ml_dsa_pre_hash_DomainSeparationContext case_Ok;
    libcrux_ml_dsa_pre_hash_DomainSeparationError case_Err;
  }
  val;
}
core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_a8;

/**
 `context` must be at most 255 bytes long.
*/
/**
This function found in impl {libcrux_ml_dsa::pre_hash::DomainSeparationContext<'a>}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_a8
libcrux_ml_dsa_pre_hash_new_88(
  Eurydice_borrow_ತುಂಡು_u8 context,
  core_option_Option_57 pre_hash_oid
)
{
  ಆದರೆ (!(context.meta > LIBCRUX_ML_DSA_CONSTANTS_CONTEXT_MAX_LEN))
  {
    ಹಿಂತಿರುಗಿ
      (
        KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_a8){
          .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Ok,
          .val = { .case_Ok = { .context = context, .pre_hash_oid = pre_hash_oid } }
        }
      );
  }
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_a8){
        .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Err,
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಸ್ಥಿರಾಂಕ
core_option_Option_57
*libcrux_ml_dsa_pre_hash_pre_hash_oid_88(
  ಸ್ಥಿರಾಂಕ libcrux_ml_dsa_pre_hash_DomainSeparationContext *self
)
{
  ಹಿಂತಿರುಗಿ &self->pre_hash_oid;
}

/**
 Returns the context, guaranteed to be at most 255 bytes long.
*/
/**
This function found in impl {libcrux_ml_dsa::pre_hash::DomainSeparationContext<'a>}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_borrow_ತುಂಡು_u8
libcrux_ml_dsa_pre_hash_context_88(ಸ್ಥಿರಾಂಕ libcrux_ml_dsa_pre_hash_DomainSeparationContext *self)
{
  ಹಿಂತಿರುಗಿ self->context;
}

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_COMMITMENT_RING_ELEMENT_ಗಾತ್ರ (libcrux_ml_dsa_constants_commitment_ring_element_ಗಾತ್ರ(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ಬಿಟ್ಟುಗಳು_ಪ್ರತಿ_COMMITMENT_COEFFICIENT))

ಸ್ಥಿರ KRML_MUSTINLINE bool
libcrux_ml_dsa_sample_inside_ಹೊರಹೋಗು_shuffle(
  Eurydice_borrow_ತುಂಡು_u8 randomness,
  ಗಾತ್ರ_t *ಹೊರಹೋಗು_ಸೂಚ್ಯಂಕ,
  uint64_t *signs,
  Eurydice_arr_6c *ಫಲಿತಾಂಶ
)
{
  bool ಮುಗಿದ = false;
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < randomness.meta; i++)
  {
    ಗಾತ್ರ_t _cloop_j = i;
    ಸ್ಥಿರಾಂಕ uint8_t *byte = &randomness.ptr[_cloop_j];
    ಆದರೆ (!ಮುಗಿದ)
    {
      ಗಾತ್ರ_t sample_at = (ಗಾತ್ರ_t)(uint32_t)byte[0U];
      ಆದರೆ (sample_at <= ಹೊರಹೋಗು_ಸೂಚ್ಯಂಕ[0U])
      {
        ಫಲಿತಾಂಶ->ದತ್ತಾಂಶ[ಹೊರಹೋಗು_ಸೂಚ್ಯಂಕ[0U]] = ಫಲಿತಾಂಶ->ದತ್ತಾಂಶ[sample_at];
        ಹೊರಹೋಗು_ಸೂಚ್ಯಂಕ[0U]++;
        ಫಲಿತಾಂಶ->ದತ್ತಾಂಶ[sample_at] = 1 - 2 * (int32_t)(signs[0U] & 1ULL);
        signs[0U] >>= 1U;
      }
      ಮುಗಿದ = ಹೊರಹೋಗು_ಸೂಚ್ಯಂಕ[0U] == (ಗಾತ್ರ_t)256U;
    }
  }
  ಹಿಂತಿರುಗಿ ಮುಗಿದ;
}

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_BETA (libcrux_ml_dsa_constants_beta(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ONES_ಒಳ_VERIFIER_CHALLENGE, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ETA))

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_GAMMA1_RING_ELEMENT_ಗಾತ್ರ (libcrux_ml_dsa_constants_gamma1_ring_element_ಗಾತ್ರ(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ಬಿಟ್ಟುಗಳು_ಪ್ರತಿ_GAMMA1_COEFFICIENT))

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_PRE_HASH_SHAKE128_OID ((KRML_CLITERAL(Eurydice_arr_c9){ .ದತ್ತಾಂಶ = { 6U, 9U, 96U, 134U, 72U, 1U, 101U, 3U, 4U, 2U, 11U } }))

/**
This function found in impl {libcrux_ml_dsa::pre_hash::PreHash for libcrux_ml_dsa::pre_hash::SHAKE128_PH}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_c9 libcrux_ml_dsa_pre_hash_oid_30(ಶೂನ್ಯ)
{
  ಹಿಂತಿರುಗಿ LIBCRUX_ML_DSA_PRE_HASH_SHAKE128_OID;
}

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_VERIFICATION_ಕೀಲಿ_ಗಾತ್ರ (libcrux_ml_dsa_constants_verification_ಕೀಲಿ_ಗಾತ್ರ(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A))

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_SIGNATURE_ಗಾತ್ರ (libcrux_ml_dsa_constants_signature_ಗಾತ್ರ(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_ಒಳ_A, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_MAX_ONES_ಒಳ_HINT, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COMMITMENT_HASH_ಗಾತ್ರ, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ಬಿಟ್ಟುಗಳು_ಪ್ರತಿ_GAMMA1_COEFFICIENT))

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ Eurydice_arr_4d libcrux_ml_dsa_simd_portable_ಸದಿಶ_type_Coefficients;

ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_4d libcrux_ml_dsa_simd_portable_ಸದಿಶ_type_zero(ಶೂನ್ಯ)
{
  ಹಿಂತಿರುಗಿ (KRML_CLITERAL(Eurydice_arr_4d){ .ದತ್ತಾಂಶ = { 0U } });
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_4d libcrux_ml_dsa_simd_portable_zero_65(ಶೂನ್ಯ)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_dsa_simd_portable_ಸದಿಶ_type_zero();
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_ಸದಿಶ_type_from_coefficient_array(
  Eurydice_dst_ref_shared_83 array,
  Eurydice_arr_4d *ಹೊರಹೋಗು
)
{
  Eurydice_ತುಂಡು_copy(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_fd(ಹೊರಹೋಗು),
    Eurydice_ತುಂಡು_subslice_shared_47(array,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .ಆರಂಭ = (ಗಾತ್ರ_t)0U,
          .ಕೊನೆ = LIBCRUX_ML_DSA_SIMD_TRAITS_COEFFICIENTS_ಒಳ_SIMD_UNIT
        }
      )),
    int32_t);
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_from_coefficient_array_65(
  Eurydice_dst_ref_shared_83 array,
  Eurydice_arr_4d *ಹೊರಹೋಗು
)
{
  libcrux_ml_dsa_simd_portable_ಸದಿಶ_type_from_coefficient_array(array, ಹೊರಹೋಗು);
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_ಸದಿಶ_type_ಗಮ್ಯ_coefficient_array(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_4d *ಮೌಲ್ಯ,
  Eurydice_dst_ref_mut_83 ಹೊರಹೋಗು
)
{
  Eurydice_ತುಂಡು_copy(ಹೊರಹೋಗು, Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_fd(ಮೌಲ್ಯ), int32_t);
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_ಗಮ್ಯ_coefficient_array_65(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_4d *ಮೌಲ್ಯ,
  Eurydice_dst_ref_mut_83 ಹೊರಹೋಗು
)
{
  libcrux_ml_dsa_simd_portable_ಸದಿಶ_type_ಗಮ್ಯ_coefficient_array(ಮೌಲ್ಯ, ಹೊರಹೋಗು);
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_arithmetic_ಕೂಡಿಸು(Eurydice_arr_4d *lhs, ಸ್ಥಿರಾಂಕ Eurydice_arr_4d *rhs)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)8U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    ಗಾತ್ರ_t uu____0 = i0;
    lhs->ದತ್ತಾಂಶ[uu____0] += rhs->ದತ್ತಾಂಶ[i0];
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_ಕೂಡಿಸು_65(Eurydice_arr_4d *lhs, ಸ್ಥಿರಾಂಕ Eurydice_arr_4d *rhs)
{
  libcrux_ml_dsa_simd_portable_arithmetic_ಕೂಡಿಸು(lhs, rhs);
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_arithmetic_ಕಳೆ(
  Eurydice_arr_4d *lhs,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_4d *rhs
)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)8U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    ಗಾತ್ರ_t uu____0 = i0;
    lhs->ದತ್ತಾಂಶ[uu____0] -= rhs->ದತ್ತಾಂಶ[i0];
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_ಕಳೆ_65(Eurydice_arr_4d *lhs, ಸ್ಥಿರಾಂಕ Eurydice_arr_4d *rhs)
{
  libcrux_ml_dsa_simd_portable_arithmetic_ಕಳೆ(lhs, rhs);
}

ಸ್ಥಿರ KRML_MUSTINLINE bool
libcrux_ml_dsa_simd_portable_arithmetic_infinity_norm_exceeds(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_4d *simd_unit,
  int32_t bound
)
{
  bool ಫಲಿತಾಂಶ = false;
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)8U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    int32_t coefficient = simd_unit->ದತ್ತಾಂಶ[i0];
    int32_t sign = coefficient >> 31U;
    int32_t normalized = coefficient - (sign & 2 * coefficient);
    bool uu____0;
    ಆದರೆ (ಫಲಿತಾಂಶ)
    {
      uu____0 = true;
    }
    ಇಲ್ಲದಿದ್ದರೆ
    {
      uu____0 = normalized >= bound;
    }
    ಫಲಿತಾಂಶ = uu____0;
  }
  ಹಿಂತಿರುಗಿ ಫಲಿತಾಂಶ;
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ bool
libcrux_ml_dsa_simd_portable_infinity_norm_exceeds_65(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_4d *simd_unit,
  int32_t bound
)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_dsa_simd_portable_arithmetic_infinity_norm_exceeds(simd_unit, bound);
}

ಸ್ಥಿರ KRML_MUSTINLINE int32_t_x2
libcrux_ml_dsa_simd_portable_arithmetic_decompose_element(int32_t gamma2, int32_t r)
{
  int32_t r0 = r + (r >> 31U & LIBCRUX_ML_DSA_SIMD_TRAITS_ಕ್ಷೇತ್ರ_MODULUS);
  int32_t ceil_ದ_r_by_128 = (r0 + 127) >> 7U;
  int32_t r1;
  ಆಯ್ಕೆ (gamma2)
  {
    ಸ್ಥಿತಿ 95232:
      {
        int32_t ಫಲಿತಾಂಶ = (ceil_ದ_r_by_128 * 11275 + (int32_t)((uint32_t)1 << 23U)) >> 24U;
        int32_t ಫಲಿತಾಂಶ_0 = (ಫಲಿತಾಂಶ ^ (43 - ಫಲಿತಾಂಶ) >> 31U) & ಫಲಿತಾಂಶ;
        r1 = ಫಲಿತಾಂಶ_0;
        ನಿಲ್ಲಿಸು;
      }
    ಸ್ಥಿತಿ 261888:
      {
        int32_t ಫಲಿತಾಂಶ = (ceil_ದ_r_by_128 * 1025 + (int32_t)((uint32_t)1 << 21U)) >> 22U;
        int32_t ಫಲಿತಾಂಶ_0 = ಫಲಿತಾಂಶ & 15;
        r1 = ಫಲಿತಾಂಶ_0;
        ನಿಲ್ಲಿಸು;
      }
    ಪೂರ್ವನಿಯೋಜಿತ:
      {
        KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __FILE__, __LINE__, "panic!");
        KRML_HOST_EXIT(255U);
      }
  }
  int32_t alpha = gamma2 * 2;
  int32_t r00 = r0 - r1 * alpha;
  r00 -=
    ((LIBCRUX_ML_DSA_SIMD_TRAITS_ಕ್ಷೇತ್ರ_MODULUS - 1) / 2 - r00) >> 31U &
      LIBCRUX_ML_DSA_SIMD_TRAITS_ಕ್ಷೇತ್ರ_MODULUS;
  ಹಿಂತಿರುಗಿ (KRML_CLITERAL(int32_t_x2){ .fst = r00, .snd = r1 });
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_arithmetic_decompose(
  int32_t gamma2,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_4d *simd_unit,
  Eurydice_arr_4d *ಕೆಳಗಿನ,
  Eurydice_arr_4d *ಮೇಲಿನ
)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)8U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    int32_t_x2
    uu____0 =
      libcrux_ml_dsa_simd_portable_arithmetic_decompose_element(gamma2,
        simd_unit->ದತ್ತಾಂಶ[i0]);
    int32_t uu____1 = uu____0.snd;
    ಕೆಳಗಿನ->ದತ್ತಾಂಶ[i0] = uu____0.fst;
    ಮೇಲಿನ->ದತ್ತಾಂಶ[i0] = uu____1;
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_decompose_65(
  int32_t gamma2,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_4d *simd_unit,
  Eurydice_arr_4d *ಕೆಳಗಿನ,
  Eurydice_arr_4d *ಮೇಲಿನ
)
{
  libcrux_ml_dsa_simd_portable_arithmetic_decompose(gamma2, simd_unit, ಕೆಳಗಿನ, ಮೇಲಿನ);
}

ಸ್ಥಿರ KRML_MUSTINLINE int32_t
libcrux_ml_dsa_simd_portable_arithmetic_compute_one_hint(
  int32_t ಕೆಳಗಿನ,
  int32_t ಮೇಲಿನ,
  int32_t gamma2
)
{
  int32_t uu____0;
  ಆದರೆ (ಕೆಳಗಿನ > gamma2)
  {
    uu____0 = 1;
  }
  ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ಕೆಳಗಿನ < -gamma2)
  {
    uu____0 = 1;
  }
  ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ಕೆಳಗಿನ == -gamma2)
  {
    ಆದರೆ (ಮೇಲಿನ != 0)
    {
      uu____0 = 1;
    }
    ಇಲ್ಲದಿದ್ದರೆ
    {
      uu____0 = 0;
    }
  }
  ಇಲ್ಲದಿದ್ದರೆ
  {
    uu____0 = 0;
  }
  ಹಿಂತಿರುಗಿ uu____0;
}

ಸ್ಥಿರ KRML_MUSTINLINE ಗಾತ್ರ_t
libcrux_ml_dsa_simd_portable_arithmetic_compute_hint(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_4d *ಕೆಳಗಿನ,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_4d *ಮೇಲಿನ,
  int32_t gamma2,
  Eurydice_arr_4d *hint
)
{
  ಗಾತ್ರ_t one_hints_ಎಣಿಕೆ = (ಗಾತ್ರ_t)0U;
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)8U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    hint->ದತ್ತಾಂಶ[i0] =
      libcrux_ml_dsa_simd_portable_arithmetic_compute_one_hint(ಕೆಳಗಿನ->ದತ್ತಾಂಶ[i0],
        ಮೇಲಿನ->ದತ್ತಾಂಶ[i0],
        gamma2);
    one_hints_ಎಣಿಕೆ += (ಗಾತ್ರ_t)hint->ದತ್ತಾಂಶ[i0];
  }
  ಹಿಂತಿರುಗಿ one_hints_ಎಣಿಕೆ;
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಗಾತ್ರ_t
libcrux_ml_dsa_simd_portable_compute_hint_65(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_4d *ಕೆಳಗಿನ,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_4d *ಮೇಲಿನ,
  int32_t gamma2,
  Eurydice_arr_4d *hint
)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_dsa_simd_portable_arithmetic_compute_hint(ಕೆಳಗಿನ, ಮೇಲಿನ, gamma2, hint);
}

ಸ್ಥಿರ KRML_MUSTINLINE int32_t
libcrux_ml_dsa_simd_portable_arithmetic_use_one_hint(int32_t gamma2, int32_t r, int32_t hint)
{
  int32_t_x2 uu____0 = libcrux_ml_dsa_simd_portable_arithmetic_decompose_element(gamma2, r);
  int32_t r0 = uu____0.fst;
  int32_t r1 = uu____0.snd;
  int32_t uu____1;
  ಆದರೆ (!(hint == 0))
  {
    ಆಯ್ಕೆ (gamma2)
    {
      ಸ್ಥಿತಿ 95232:
        {
          ಆದರೆ (r0 > 0)
          {
            ಆದರೆ (r1 == 43)
            {
              uu____1 = 0;
            }
            ಇಲ್ಲದಿದ್ದರೆ
            {
              uu____1 = r1 + hint;
            }
          }
          ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (r1 == 0)
          {
            uu____1 = 43;
          }
          ಇಲ್ಲದಿದ್ದರೆ
          {
            uu____1 = r1 - hint;
          }
          ನಿಲ್ಲಿಸು;
        }
      ಸ್ಥಿತಿ 261888:
        {
          ಆದರೆ (r0 > 0)
          {
            uu____1 = (r1 + hint) & 15;
          }
          ಇಲ್ಲದಿದ್ದರೆ
          {
            uu____1 = (r1 - hint) & 15;
          }
          ನಿಲ್ಲಿಸು;
        }
      ಪೂರ್ವನಿಯೋಜಿತ:
        {
          KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __FILE__, __LINE__, "panic!");
          KRML_HOST_EXIT(255U);
        }
    }
    ಹಿಂತಿರುಗಿ uu____1;
  }
  ಹಿಂತಿರುಗಿ r1;
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_arithmetic_use_hint(
  int32_t gamma2,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_4d *simd_unit,
  Eurydice_arr_4d *hint
)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)8U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    int32_t
    uu____0 =
      libcrux_ml_dsa_simd_portable_arithmetic_use_one_hint(gamma2,
        simd_unit->ದತ್ತಾಂಶ[i0],
        hint->ದತ್ತಾಂಶ[i0]);
    hint->ದತ್ತಾಂಶ[i0] = uu____0;
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_use_hint_65(
  int32_t gamma2,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_4d *simd_unit,
  Eurydice_arr_4d *hint
)
{
  libcrux_ml_dsa_simd_portable_arithmetic_use_hint(gamma2, simd_unit, hint);
}

ಸ್ಥಿರ KRML_MUSTINLINE uint64_t
libcrux_ml_dsa_simd_portable_arithmetic_get_n_ಕನಿಷ್ಠ_significant_ಬಿಟ್ಟುಗಳು(uint8_t n, uint64_t ಮೌಲ್ಯ)
{
  ಹಿಂತಿರುಗಿ ಮೌಲ್ಯ & ((1ULL << (uint32_t)n) - 1ULL);
}

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_SIMD_PORTABLE_ARITHMETIC_MONTGOMERY_ಸರಿಸು (32U)

ಸ್ಥಿರ KRML_MUSTINLINE int32_t
libcrux_ml_dsa_simd_portable_arithmetic_montgomery_reduce_element(int64_t ಮೌಲ್ಯ)
{
  uint64_t
  t =
    libcrux_ml_dsa_simd_portable_arithmetic_get_n_ಕನಿಷ್ಠ_significant_ಬಿಟ್ಟುಗಳು(LIBCRUX_ML_DSA_SIMD_PORTABLE_ARITHMETIC_MONTGOMERY_ಸರಿಸು,
      (uint64_t)ಮೌಲ್ಯ)
    * LIBCRUX_ML_DSA_SIMD_TRAITS_INVERSE_ದ_MODULUS_MOD_MONTGOMERY_R;
  int32_t
  k =
    (int32_t)libcrux_ml_dsa_simd_portable_arithmetic_get_n_ಕನಿಷ್ಠ_significant_ಬಿಟ್ಟುಗಳು(LIBCRUX_ML_DSA_SIMD_PORTABLE_ARITHMETIC_MONTGOMERY_ಸರಿಸು,
      t);
  int64_t k_times_modulus = (int64_t)k * (int64_t)LIBCRUX_ML_DSA_SIMD_TRAITS_ಕ್ಷೇತ್ರ_MODULUS;
  int32_t
  c =
    (int32_t)(k_times_modulus >> (uint32_t)LIBCRUX_ML_DSA_SIMD_PORTABLE_ARITHMETIC_MONTGOMERY_ಸರಿಸು);
  int32_t
  ಮೌಲ್ಯ_ಮೇಲಿನ =
    (int32_t)(ಮೌಲ್ಯ >> (uint32_t)LIBCRUX_ML_DSA_SIMD_PORTABLE_ARITHMETIC_MONTGOMERY_ಸರಿಸು);
  ಹಿಂತಿರುಗಿ ಮೌಲ್ಯ_ಮೇಲಿನ - c;
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply(
  Eurydice_arr_4d *lhs,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_4d *rhs
)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)8U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    lhs->ದತ್ತಾಂಶ[i0] =
      libcrux_ml_dsa_simd_portable_arithmetic_montgomery_reduce_element((int64_t)lhs->ದತ್ತಾಂಶ[i0] *
          (int64_t)rhs->ದತ್ತಾಂಶ[i0]);
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_montgomery_multiply_65(
  Eurydice_arr_4d *lhs,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_4d *rhs
)
{
  libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply(lhs, rhs);
}

ಸ್ಥಿರ KRML_MUSTINLINE int32_t
libcrux_ml_dsa_simd_portable_arithmetic_barrett_reduce_element(int32_t fe)
{
  int32_t quotient = (fe + (int32_t)((uint32_t)1 << 22U)) >> 23U;
  ಹಿಂತಿರುಗಿ fe - quotient * LIBCRUX_ML_DSA_SIMD_TRAITS_ಕ್ಷೇತ್ರ_MODULUS;
}

ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_arithmetic_barrett_reduce_simd_unit(Eurydice_arr_4d *simd_unit)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)8U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    simd_unit->ದತ್ತಾಂಶ[i0] =
      libcrux_ml_dsa_simd_portable_arithmetic_barrett_reduce_element(simd_unit->ದತ್ತಾಂಶ[i0]);
  }
}

ಸ್ಥಿರ KRML_MUSTINLINE int32_t_x2
libcrux_ml_dsa_simd_portable_arithmetic_power2round_element(int32_t t)
{
  int32_t t2 = t + (t >> 31U & LIBCRUX_ML_DSA_SIMD_TRAITS_ಕ್ಷೇತ್ರ_MODULUS);
  int32_t
  t1 =
    (t2 - 1 +
      (int32_t)((uint32_t)1 <<
        (uint32_t)(LIBCRUX_ML_DSA_CONSTANTS_ಬಿಟ್ಟುಗಳು_ಒಳ_ಅಧೋ_PART_ದ_T - (ಗಾತ್ರ_t)1U)))
    >> (uint32_t)LIBCRUX_ML_DSA_CONSTANTS_ಬಿಟ್ಟುಗಳು_ಒಳ_ಅಧೋ_PART_ದ_T;
  int32_t
  t0 = t2 - (int32_t)((uint32_t)t1 << (uint32_t)LIBCRUX_ML_DSA_CONSTANTS_ಬಿಟ್ಟುಗಳು_ಒಳ_ಅಧೋ_PART_ದ_T);
  ಹಿಂತಿರುಗಿ (KRML_CLITERAL(int32_t_x2){ .fst = t0, .snd = t1 });
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_arithmetic_power2round(Eurydice_arr_4d *t0, Eurydice_arr_4d *t1)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)8U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    int32_t_x2 uu____0 = libcrux_ml_dsa_simd_portable_arithmetic_power2round_element(t0->ದತ್ತಾಂಶ[i0]);
    int32_t uu____1 = uu____0.snd;
    t0->ದತ್ತಾಂಶ[i0] = uu____0.fst;
    t1->ದತ್ತಾಂಶ[i0] = uu____1;
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_power2round_65(Eurydice_arr_4d *t0, Eurydice_arr_4d *t1)
{
  libcrux_ml_dsa_simd_portable_arithmetic_power2round(t0, t1);
}

ಸ್ಥಿರ KRML_MUSTINLINE ಗಾತ್ರ_t
libcrux_ml_dsa_simd_portable_sample_rejection_sample_less_than_ಕ್ಷೇತ್ರ_modulus(
  Eurydice_borrow_ತುಂಡು_u8 randomness,
  Eurydice_dst_ref_mut_83 ಹೊರಹೋಗು
)
{
  ಗಾತ್ರ_t sampled = (ಗಾತ್ರ_t)0U;
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < randomness.meta / (ಗಾತ್ರ_t)3U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    int32_t b0 = (int32_t)(uint32_t)randomness.ptr[i0 * (ಗಾತ್ರ_t)3U];
    int32_t b1 = (int32_t)(uint32_t)randomness.ptr[i0 * (ಗಾತ್ರ_t)3U + (ಗಾತ್ರ_t)1U];
    int32_t b2 = (int32_t)(uint32_t)randomness.ptr[i0 * (ಗಾತ್ರ_t)3U + (ಗಾತ್ರ_t)2U];
    int32_t
    coefficient = (((int32_t)((uint32_t)b2 << 16U) | (int32_t)((uint32_t)b1 << 8U)) | b0) & 8388607;
    ಆದರೆ (coefficient < LIBCRUX_ML_DSA_CONSTANTS_ಕ್ಷೇತ್ರ_MODULUS)
    {
      ಹೊರಹೋಗು.ptr[sampled] = coefficient;
      sampled++;
    }
  }
  ಹಿಂತಿರುಗಿ sampled;
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಗಾತ್ರ_t
libcrux_ml_dsa_simd_portable_rejection_sample_less_than_ಕ್ಷೇತ್ರ_modulus_65(
  Eurydice_borrow_ತುಂಡು_u8 randomness,
  Eurydice_dst_ref_mut_83 ಹೊರಹೋಗು
)
{
  ಹಿಂತಿರುಗಿ
    libcrux_ml_dsa_simd_portable_sample_rejection_sample_less_than_ಕ್ಷೇತ್ರ_modulus(randomness,
      ಹೊರಹೋಗು);
}

ಸ್ಥಿರ KRML_MUSTINLINE ಗಾತ್ರ_t
libcrux_ml_dsa_simd_portable_sample_rejection_sample_less_than_eta_equals_2(
  Eurydice_borrow_ತುಂಡು_u8 randomness,
  Eurydice_dst_ref_mut_83 ಹೊರಹೋಗು
)
{
  ಗಾತ್ರ_t sampled = (ಗಾತ್ರ_t)0U;
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < randomness.meta; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    uint8_t byte = randomness.ptr[i0];
    uint8_t try_0 = (uint32_t)byte & 15U;
    uint8_t try_1 = (uint32_t)byte >> 4U;
    bool try_0_comp = try_0 < 15U;
    bool try_1_comp = try_1 < 15U;
    ಆದರೆ (try_0_comp)
    {
      int32_t try_00 = (int32_t)(uint32_t)try_0;
      int32_t try_0_mod_5 = try_00 - (try_00 * 26 >> 7U) * 5;
      ಹೊರಹೋಗು.ptr[sampled] = 2 - try_0_mod_5;
      sampled++;
    }
    ಆದರೆ (try_1_comp)
    {
      int32_t try_10 = (int32_t)(uint32_t)try_1;
      int32_t try_1_mod_5 = try_10 - (try_10 * 26 >> 7U) * 5;
      ಹೊರಹೋಗು.ptr[sampled] = 2 - try_1_mod_5;
      sampled++;
    }
  }
  ಹಿಂತಿರುಗಿ sampled;
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಗಾತ್ರ_t
libcrux_ml_dsa_simd_portable_rejection_sample_less_than_eta_equals_2_65(
  Eurydice_borrow_ತುಂಡು_u8 randomness,
  Eurydice_dst_ref_mut_83 ಹೊರಹೋಗು
)
{
  ಹಿಂತಿರುಗಿ
    libcrux_ml_dsa_simd_portable_sample_rejection_sample_less_than_eta_equals_2(randomness,
      ಹೊರಹೋಗು);
}

ಸ್ಥಿರ KRML_MUSTINLINE ಗಾತ್ರ_t
libcrux_ml_dsa_simd_portable_sample_rejection_sample_less_than_eta_equals_4(
  Eurydice_borrow_ತುಂಡು_u8 randomness,
  Eurydice_dst_ref_mut_83 ಹೊರಹೋಗು
)
{
  ಗಾತ್ರ_t sampled = (ಗಾತ್ರ_t)0U;
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < randomness.meta; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    uint8_t byte = randomness.ptr[i0];
    uint8_t try_0 = (uint32_t)byte & 15U;
    uint8_t try_1 = (uint32_t)byte >> 4U;
    bool try_0_comp = try_0 < 9U;
    bool try_1_comp = try_1 < 9U;
    ಆದರೆ (try_0_comp)
    {
      ಹೊರಹೋಗು.ptr[sampled] = 4 - (int32_t)(uint32_t)try_0;
      sampled++;
    }
    ಆದರೆ (try_1_comp)
    {
      ಹೊರಹೋಗು.ptr[sampled] = 4 - (int32_t)(uint32_t)try_1;
      sampled++;
    }
  }
  ಹಿಂತಿರುಗಿ sampled;
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಗಾತ್ರ_t
libcrux_ml_dsa_simd_portable_rejection_sample_less_than_eta_equals_4_65(
  Eurydice_borrow_ತುಂಡು_u8 randomness,
  Eurydice_dst_ref_mut_83 ಹೊರಹೋಗು
)
{
  ಹಿಂತಿರುಗಿ
    libcrux_ml_dsa_simd_portable_sample_rejection_sample_less_than_eta_equals_4(randomness,
      ಹೊರಹೋಗು);
}

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_SERIALIZE_WHEN_GAMMA1_IS_2_POW_19_GAMMA1 ((int32_t)((uint32_t)1 << 19U))

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_encoding_gamma1_serialize_when_gamma1_is_2_pow_19(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_ತುಂಡು_u8 serialized
)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)8U / (ಗಾತ್ರ_t)2U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    Eurydice_dst_ref_shared_83
    coefficients =
      Eurydice_array_ಗಮ್ಯ_subslice_shared_44(simd_unit,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ಆರಂಭ = i0 * (ಗಾತ್ರ_t)2U,
            .ಕೊನೆ = i0 * (ಗಾತ್ರ_t)2U + (ಗಾತ್ರ_t)2U
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
    serialized.ptr[(ಗಾತ್ರ_t)5U * i0] = (uint8_t)coefficient0;
    serialized.ptr[(ಗಾತ್ರ_t)5U * i0 + (ಗಾತ್ರ_t)1U] = (uint8_t)(coefficient0 >> 8U);
    serialized.ptr[(ಗಾತ್ರ_t)5U * i0 + (ಗಾತ್ರ_t)2U] = (uint8_t)(coefficient0 >> 16U);
    ಗಾತ್ರ_t uu____0 = (ಗಾತ್ರ_t)5U * i0 + (ಗಾತ್ರ_t)2U;
    serialized.ptr[uu____0] =
      (uint32_t)serialized.ptr[uu____0] | (uint32_t)(uint8_t)(int32_t)((uint32_t)coefficient1 << 4U);
    serialized.ptr[(ಗಾತ್ರ_t)5U * i0 + (ಗಾತ್ರ_t)3U] = (uint8_t)(coefficient1 >> 4U);
    serialized.ptr[(ಗಾತ್ರ_t)5U * i0 + (ಗಾತ್ರ_t)4U] = (uint8_t)(coefficient1 >> 12U);
  }
}

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_SERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1 ((int32_t)((uint32_t)1 << 17U))

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_encoding_gamma1_serialize_when_gamma1_is_2_pow_17(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_ತುಂಡು_u8 serialized
)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)8U / (ಗಾತ್ರ_t)4U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    Eurydice_dst_ref_shared_83
    coefficients =
      Eurydice_array_ಗಮ್ಯ_subslice_shared_44(simd_unit,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ಆರಂಭ = i0 * (ಗಾತ್ರ_t)4U,
            .ಕೊನೆ = i0 * (ಗಾತ್ರ_t)4U + (ಗಾತ್ರ_t)4U
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
    serialized.ptr[(ಗಾತ್ರ_t)9U * i0] = (uint8_t)coefficient0;
    serialized.ptr[(ಗಾತ್ರ_t)9U * i0 + (ಗಾತ್ರ_t)1U] = (uint8_t)(coefficient0 >> 8U);
    serialized.ptr[(ಗಾತ್ರ_t)9U * i0 + (ಗಾತ್ರ_t)2U] = (uint8_t)(coefficient0 >> 16U);
    ಗಾತ್ರ_t uu____0 = (ಗಾತ್ರ_t)9U * i0 + (ಗಾತ್ರ_t)2U;
    serialized.ptr[uu____0] =
      (uint32_t)serialized.ptr[uu____0] | (uint32_t)(uint8_t)(int32_t)((uint32_t)coefficient1 << 2U);
    serialized.ptr[(ಗಾತ್ರ_t)9U * i0 + (ಗಾತ್ರ_t)3U] = (uint8_t)(coefficient1 >> 6U);
    serialized.ptr[(ಗಾತ್ರ_t)9U * i0 + (ಗಾತ್ರ_t)4U] = (uint8_t)(coefficient1 >> 14U);
    ಗಾತ್ರ_t uu____1 = (ಗಾತ್ರ_t)9U * i0 + (ಗಾತ್ರ_t)4U;
    serialized.ptr[uu____1] =
      (uint32_t)serialized.ptr[uu____1] | (uint32_t)(uint8_t)(int32_t)((uint32_t)coefficient2 << 4U);
    serialized.ptr[(ಗಾತ್ರ_t)9U * i0 + (ಗಾತ್ರ_t)5U] = (uint8_t)(coefficient2 >> 4U);
    serialized.ptr[(ಗಾತ್ರ_t)9U * i0 + (ಗಾತ್ರ_t)6U] = (uint8_t)(coefficient2 >> 12U);
    ಗಾತ್ರ_t uu____2 = (ಗಾತ್ರ_t)9U * i0 + (ಗಾತ್ರ_t)6U;
    serialized.ptr[uu____2] =
      (uint32_t)serialized.ptr[uu____2] | (uint32_t)(uint8_t)(int32_t)((uint32_t)coefficient3 << 6U);
    serialized.ptr[(ಗಾತ್ರ_t)9U * i0 + (ಗಾತ್ರ_t)7U] = (uint8_t)(coefficient3 >> 2U);
    serialized.ptr[(ಗಾತ್ರ_t)9U * i0 + (ಗಾತ್ರ_t)8U] = (uint8_t)(coefficient3 >> 10U);
  }
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_encoding_gamma1_serialize(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_ತುಂಡು_u8 serialized,
  ಗಾತ್ರ_t gamma1_exponent
)
{
  ಆಯ್ಕೆ (gamma1_exponent)
  {
    ಸ್ಥಿತಿ 17U:
      {
        ನಿಲ್ಲಿಸು;
      }
    ಸ್ಥಿತಿ 19U:
      {
        libcrux_ml_dsa_simd_portable_encoding_gamma1_serialize_when_gamma1_is_2_pow_19(simd_unit,
          serialized);
        ಹಿಂತಿರುಗಿ;
      }
    ಪೂರ್ವನಿಯೋಜಿತ:
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_gamma1_serialize_65(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_ತುಂಡು_u8 serialized,
  ಗಾತ್ರ_t gamma1_exponent
)
{
  libcrux_ml_dsa_simd_portable_encoding_gamma1_serialize(simd_unit, serialized, gamma1_exponent);
}

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_19_GAMMA1 ((int32_t)((uint32_t)1 << 19U))

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_19_GAMMA1_TIMES_2_BITMASK ((int32_t)((uint32_t)LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_19_GAMMA1 << 1U) - 1)

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_encoding_gamma1_deserialize_when_gamma1_is_2_pow_19(
  Eurydice_borrow_ತುಂಡು_u8 serialized,
  Eurydice_arr_4d *simd_unit
)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < serialized.meta / (ಗಾತ್ರ_t)5U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    Eurydice_borrow_ತುಂಡು_u8
    ಬೈಟುಗಳು =
      Eurydice_ತುಂಡು_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ಆರಂಭ = i0 * (ಗಾತ್ರ_t)5U,
            .ಕೊನೆ = i0 * (ಗಾತ್ರ_t)5U + (ಗಾತ್ರ_t)5U
          }
        ));
    int32_t coefficient0 = (int32_t)(uint32_t)ಬೈಟುಗಳು.ptr[0U];
    coefficient0 |= (int32_t)((uint32_t)(int32_t)(uint32_t)ಬೈಟುಗಳು.ptr[1U] << 8U);
    coefficient0 |= (int32_t)((uint32_t)(int32_t)(uint32_t)ಬೈಟುಗಳು.ptr[2U] << 16U);
    coefficient0 &=
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_19_GAMMA1_TIMES_2_BITMASK;
    int32_t coefficient1 = (int32_t)(uint32_t)ಬೈಟುಗಳು.ptr[2U] >> 4U;
    coefficient1 |= (int32_t)((uint32_t)(int32_t)(uint32_t)ಬೈಟುಗಳು.ptr[3U] << 4U);
    coefficient1 |= (int32_t)((uint32_t)(int32_t)(uint32_t)ಬೈಟುಗಳು.ptr[4U] << 12U);
    simd_unit->ದತ್ತಾಂಶ[(ಗಾತ್ರ_t)2U * i0] =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_19_GAMMA1 -
        coefficient0;
    simd_unit->ದತ್ತಾಂಶ[(ಗಾತ್ರ_t)2U * i0 + (ಗಾತ್ರ_t)1U] =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_19_GAMMA1 -
        coefficient1;
  }
}

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1 ((int32_t)((uint32_t)1 << 17U))

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1_TIMES_2_BITMASK ((int32_t)((uint32_t)LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1 << 1U) - 1)

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_encoding_gamma1_deserialize_when_gamma1_is_2_pow_17(
  Eurydice_borrow_ತುಂಡು_u8 serialized,
  Eurydice_arr_4d *simd_unit
)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < serialized.meta / (ಗಾತ್ರ_t)9U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    Eurydice_borrow_ತುಂಡು_u8
    ಬೈಟುಗಳು =
      Eurydice_ತುಂಡು_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ಆರಂಭ = i0 * (ಗಾತ್ರ_t)9U,
            .ಕೊನೆ = i0 * (ಗಾತ್ರ_t)9U + (ಗಾತ್ರ_t)9U
          }
        ));
    int32_t coefficient0 = (int32_t)(uint32_t)ಬೈಟುಗಳು.ptr[0U];
    coefficient0 |= (int32_t)((uint32_t)(int32_t)(uint32_t)ಬೈಟುಗಳು.ptr[1U] << 8U);
    coefficient0 |= (int32_t)((uint32_t)(int32_t)(uint32_t)ಬೈಟುಗಳು.ptr[2U] << 16U);
    coefficient0 &=
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1_TIMES_2_BITMASK;
    int32_t coefficient1 = (int32_t)(uint32_t)ಬೈಟುಗಳು.ptr[2U] >> 2U;
    coefficient1 |= (int32_t)((uint32_t)(int32_t)(uint32_t)ಬೈಟುಗಳು.ptr[3U] << 6U);
    coefficient1 |= (int32_t)((uint32_t)(int32_t)(uint32_t)ಬೈಟುಗಳು.ptr[4U] << 14U);
    coefficient1 &=
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1_TIMES_2_BITMASK;
    int32_t coefficient2 = (int32_t)(uint32_t)ಬೈಟುಗಳು.ptr[4U] >> 4U;
    coefficient2 |= (int32_t)((uint32_t)(int32_t)(uint32_t)ಬೈಟುಗಳು.ptr[5U] << 4U);
    coefficient2 |= (int32_t)((uint32_t)(int32_t)(uint32_t)ಬೈಟುಗಳು.ptr[6U] << 12U);
    coefficient2 &=
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1_TIMES_2_BITMASK;
    int32_t coefficient3 = (int32_t)(uint32_t)ಬೈಟುಗಳು.ptr[6U] >> 6U;
    coefficient3 |= (int32_t)((uint32_t)(int32_t)(uint32_t)ಬೈಟುಗಳು.ptr[7U] << 2U);
    coefficient3 |= (int32_t)((uint32_t)(int32_t)(uint32_t)ಬೈಟುಗಳು.ptr[8U] << 10U);
    coefficient3 &=
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1_TIMES_2_BITMASK;
    simd_unit->ದತ್ತಾಂಶ[(ಗಾತ್ರ_t)4U * i0] =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1 -
        coefficient0;
    simd_unit->ದತ್ತಾಂಶ[(ಗಾತ್ರ_t)4U * i0 + (ಗಾತ್ರ_t)1U] =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1 -
        coefficient1;
    simd_unit->ದತ್ತಾಂಶ[(ಗಾತ್ರ_t)4U * i0 + (ಗಾತ್ರ_t)2U] =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1 -
        coefficient2;
    simd_unit->ದತ್ತಾಂಶ[(ಗಾತ್ರ_t)4U * i0 + (ಗಾತ್ರ_t)3U] =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_GAMMA1_DESERIALIZE_WHEN_GAMMA1_IS_2_POW_17_GAMMA1 -
        coefficient3;
  }
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_encoding_gamma1_deserialize(
  Eurydice_borrow_ತುಂಡು_u8 serialized,
  Eurydice_arr_4d *ಹೊರಹೋಗು,
  ಗಾತ್ರ_t gamma1_exponent
)
{
  ಆಯ್ಕೆ (gamma1_exponent)
  {
    ಸ್ಥಿತಿ 17U:
      {
        ನಿಲ್ಲಿಸು;
      }
    ಸ್ಥಿತಿ 19U:
      {
        libcrux_ml_dsa_simd_portable_encoding_gamma1_deserialize_when_gamma1_is_2_pow_19(serialized,
          ಹೊರಹೋಗು);
        ಹಿಂತಿರುಗಿ;
      }
    ಪೂರ್ವನಿಯೋಜಿತ:
      {
        KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __FILE__, __LINE__, "panic!");
        KRML_HOST_EXIT(255U);
      }
  }
  libcrux_ml_dsa_simd_portable_encoding_gamma1_deserialize_when_gamma1_is_2_pow_17(serialized,
    ಹೊರಹೋಗು);
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_gamma1_deserialize_65(
  Eurydice_borrow_ತುಂಡು_u8 serialized,
  Eurydice_arr_4d *ಹೊರಹೋಗು,
  ಗಾತ್ರ_t gamma1_exponent
)
{
  libcrux_ml_dsa_simd_portable_encoding_gamma1_deserialize(serialized, ಹೊರಹೋಗು, gamma1_exponent);
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_encoding_commitment_serialize_4(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_ತುಂಡು_u8 serialized
)
{
  uint8_t coefficient0 = (uint8_t)simd_unit->ದತ್ತಾಂಶ[0U];
  uint8_t coefficient1 = (uint8_t)simd_unit->ದತ್ತಾಂಶ[1U];
  uint8_t coefficient2 = (uint8_t)simd_unit->ದತ್ತಾಂಶ[2U];
  uint8_t coefficient3 = (uint8_t)simd_unit->ದತ್ತಾಂಶ[3U];
  uint8_t coefficient4 = (uint8_t)simd_unit->ದತ್ತಾಂಶ[4U];
  uint8_t coefficient5 = (uint8_t)simd_unit->ದತ್ತಾಂಶ[5U];
  uint8_t coefficient6 = (uint8_t)simd_unit->ದತ್ತಾಂಶ[6U];
  uint8_t coefficient7 = (uint8_t)simd_unit->ದತ್ತಾಂಶ[7U];
  uint8_t byte0 = (uint32_t)coefficient1 << 4U | (uint32_t)coefficient0;
  uint8_t byte1 = (uint32_t)coefficient3 << 4U | (uint32_t)coefficient2;
  uint8_t byte2 = (uint32_t)coefficient5 << 4U | (uint32_t)coefficient4;
  uint8_t byte3 = (uint32_t)coefficient7 << 4U | (uint32_t)coefficient6;
  serialized.ptr[0U] = byte0;
  serialized.ptr[1U] = byte1;
  serialized.ptr[2U] = byte2;
  serialized.ptr[3U] = byte3;
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_encoding_commitment_serialize_6(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_ತುಂಡು_u8 serialized
)
{
  uint8_t coefficient0 = (uint8_t)simd_unit->ದತ್ತಾಂಶ[0U];
  uint8_t coefficient1 = (uint8_t)simd_unit->ದತ್ತಾಂಶ[1U];
  uint8_t coefficient2 = (uint8_t)simd_unit->ದತ್ತಾಂಶ[2U];
  uint8_t coefficient3 = (uint8_t)simd_unit->ದತ್ತಾಂಶ[3U];
  uint8_t coefficient4 = (uint8_t)simd_unit->ದತ್ತಾಂಶ[4U];
  uint8_t coefficient5 = (uint8_t)simd_unit->ದತ್ತಾಂಶ[5U];
  uint8_t coefficient6 = (uint8_t)simd_unit->ದತ್ತಾಂಶ[6U];
  uint8_t coefficient7 = (uint8_t)simd_unit->ದತ್ತಾಂಶ[7U];
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

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_encoding_commitment_serialize(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_ತುಂಡು_u8 serialized
)
{
  ಆಯ್ಕೆ ((uint32_t)(uint8_t)serialized.meta)
  {
    ಸ್ಥಿತಿ 4U:
      {
        libcrux_ml_dsa_simd_portable_encoding_commitment_serialize_4(simd_unit, serialized);
        ನಿಲ್ಲಿಸು;
      }
    ಸ್ಥಿತಿ 6U:
      {
        libcrux_ml_dsa_simd_portable_encoding_commitment_serialize_6(simd_unit, serialized);
        ನಿಲ್ಲಿಸು;
      }
    ಪೂರ್ವನಿಯೋಜಿತ:
      {
        KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __FILE__, __LINE__, "panic!");
        KRML_HOST_EXIT(255U);
      }
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_commitment_serialize_65(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_ತುಂಡು_u8 serialized
)
{
  libcrux_ml_dsa_simd_portable_encoding_commitment_serialize(simd_unit, serialized);
}

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_4_ETA (4)

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_encoding_error_serialize_when_eta_is_4(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_ತುಂಡು_u8 serialized
)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)8U / (ಗಾತ್ರ_t)2U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    Eurydice_dst_ref_shared_83
    coefficients =
      Eurydice_array_ಗಮ್ಯ_subslice_shared_44(simd_unit,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ಆರಂಭ = i0 * (ಗಾತ್ರ_t)2U,
            .ಕೊನೆ = i0 * (ಗಾತ್ರ_t)2U + (ಗಾತ್ರ_t)2U
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

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_2_ETA (2)

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_encoding_error_serialize_when_eta_is_2(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_ತುಂಡು_u8 serialized
)
{
  uint8_t
  coefficient0 =
    (uint8_t)(LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_2_ETA -
      simd_unit->ದತ್ತಾಂಶ[0U]);
  uint8_t
  coefficient1 =
    (uint8_t)(LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_2_ETA -
      simd_unit->ದತ್ತಾಂಶ[1U]);
  uint8_t
  coefficient2 =
    (uint8_t)(LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_2_ETA -
      simd_unit->ದತ್ತಾಂಶ[2U]);
  uint8_t
  coefficient3 =
    (uint8_t)(LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_2_ETA -
      simd_unit->ದತ್ತಾಂಶ[3U]);
  uint8_t
  coefficient4 =
    (uint8_t)(LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_2_ETA -
      simd_unit->ದತ್ತಾಂಶ[4U]);
  uint8_t
  coefficient5 =
    (uint8_t)(LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_2_ETA -
      simd_unit->ದತ್ತಾಂಶ[5U]);
  uint8_t
  coefficient6 =
    (uint8_t)(LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_2_ETA -
      simd_unit->ದತ್ತಾಂಶ[6U]);
  uint8_t
  coefficient7 =
    (uint8_t)(LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_SERIALIZE_WHEN_ETA_IS_2_ETA -
      simd_unit->ದತ್ತಾಂಶ[7U]);
  serialized.ptr[0U] =
    ((uint32_t)coefficient2 << 6U | (uint32_t)coefficient1 << 3U) | (uint32_t)coefficient0;
  serialized.ptr[1U] =
    (((uint32_t)coefficient5 << 7U | (uint32_t)coefficient4 << 4U) | (uint32_t)coefficient3 << 1U)
    | (uint32_t)coefficient2 >> 2U;
  serialized.ptr[2U] =
    ((uint32_t)coefficient7 << 5U | (uint32_t)coefficient6 << 2U) | (uint32_t)coefficient5 >> 1U;
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_encoding_error_serialize(
  libcrux_ml_dsa_constants_Eta eta,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_ತುಂಡು_u8 serialized
)
{
  ಆಯ್ಕೆ (eta)
  {
    ಸ್ಥಿತಿ libcrux_ml_dsa_constants_Eta_Two:
      {
        ನಿಲ್ಲಿಸು;
      }
    ಸ್ಥಿತಿ libcrux_ml_dsa_constants_Eta_Four:
      {
        libcrux_ml_dsa_simd_portable_encoding_error_serialize_when_eta_is_4(simd_unit, serialized);
        ಹಿಂತಿರುಗಿ;
      }
    ಪೂರ್ವನಿಯೋಜಿತ:
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_error_serialize_65(
  libcrux_ml_dsa_constants_Eta eta,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_ತುಂಡು_u8 serialized
)
{
  libcrux_ml_dsa_simd_portable_encoding_error_serialize(eta, simd_unit, serialized);
}

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_4_ETA (4)

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_encoding_error_deserialize_when_eta_is_4(
  Eurydice_borrow_ತುಂಡು_u8 serialized,
  Eurydice_arr_4d *simd_units
)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < serialized.meta; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    ಸ್ಥಿರಾಂಕ uint8_t *byte = &serialized.ptr[i0];
    uint8_t uu____0 = core_ops_ಬಿಟ್_core_ops_ಬಿಟ್_ಬಿಟ್_And_u8_u8_for_0_u8_bitand(byte, 15U);
    simd_units->ದತ್ತಾಂಶ[(ಗಾತ್ರ_t)2U * i0] =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_4_ETA -
        (int32_t)(uint32_t)uu____0;
    uint8_t uu____1 = core_ops_ಬಿಟ್_core_ops_ಬಿಟ್_Shr_i32_u8_for_0_u8_shr(byte, 4);
    simd_units->ದತ್ತಾಂಶ[(ಗಾತ್ರ_t)2U * i0 + (ಗಾತ್ರ_t)1U] =
      LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_4_ETA -
        (int32_t)(uint32_t)uu____1;
  }
}

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_2_ETA (2)

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_encoding_error_deserialize_when_eta_is_2(
  Eurydice_borrow_ತುಂಡು_u8 serialized,
  Eurydice_arr_4d *simd_unit
)
{
  int32_t byte0 = (int32_t)(uint32_t)serialized.ptr[0U];
  int32_t byte1 = (int32_t)(uint32_t)serialized.ptr[1U];
  int32_t byte2 = (int32_t)(uint32_t)serialized.ptr[2U];
  simd_unit->ದತ್ತಾಂಶ[0U] =
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_2_ETA - (byte0 & 7);
  simd_unit->ದತ್ತಾಂಶ[1U] =
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_2_ETA - (byte0 >> 3U & 7);
  simd_unit->ದತ್ತಾಂಶ[2U] =
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_2_ETA -
      ((byte0 >> 6U | (int32_t)((uint32_t)byte1 << 2U)) & 7);
  simd_unit->ದತ್ತಾಂಶ[3U] =
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_2_ETA - (byte1 >> 1U & 7);
  simd_unit->ದತ್ತಾಂಶ[4U] =
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_2_ETA - (byte1 >> 4U & 7);
  simd_unit->ದತ್ತಾಂಶ[5U] =
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_2_ETA -
      ((byte1 >> 7U | (int32_t)((uint32_t)byte2 << 1U)) & 7);
  simd_unit->ದತ್ತಾಂಶ[6U] =
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_2_ETA - (byte2 >> 2U & 7);
  simd_unit->ದತ್ತಾಂಶ[7U] =
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_ERROR_DESERIALIZE_WHEN_ETA_IS_2_ETA - (byte2 >> 5U & 7);
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_encoding_error_deserialize(
  libcrux_ml_dsa_constants_Eta eta,
  Eurydice_borrow_ತುಂಡು_u8 serialized,
  Eurydice_arr_4d *ಹೊರಹೋಗು
)
{
  ಆಯ್ಕೆ (eta)
  {
    ಸ್ಥಿತಿ libcrux_ml_dsa_constants_Eta_Two:
      {
        ನಿಲ್ಲಿಸು;
      }
    ಸ್ಥಿತಿ libcrux_ml_dsa_constants_Eta_Four:
      {
        libcrux_ml_dsa_simd_portable_encoding_error_deserialize_when_eta_is_4(serialized, ಹೊರಹೋಗು);
        ಹಿಂತಿರುಗಿ;
      }
    ಪೂರ್ವನಿಯೋಜಿತ:
      {
        KRML_HOST_EPRINTF("KaRaMeL incomplete match at %s:%d\n", __FILE__, __LINE__);
        KRML_HOST_EXIT(253U);
      }
  }
  libcrux_ml_dsa_simd_portable_encoding_error_deserialize_when_eta_is_2(serialized, ಹೊರಹೋಗು);
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_error_deserialize_65(
  libcrux_ml_dsa_constants_Eta eta,
  Eurydice_borrow_ತುಂಡು_u8 serialized,
  Eurydice_arr_4d *ಹೊರಹೋಗು
)
{
  libcrux_ml_dsa_simd_portable_encoding_error_deserialize(eta, serialized, ಹೊರಹೋಗು);
}

ಸ್ಥಿರ KRML_MUSTINLINE int32_t
libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(int32_t t0)
{
  ಹಿಂತಿರುಗಿ
    (int32_t)((uint32_t)1 <<
      (uint32_t)(LIBCRUX_ML_DSA_CONSTANTS_ಬಿಟ್ಟುಗಳು_ಒಳ_ಅಧೋ_PART_ದ_T - (ಗಾತ್ರ_t)1U))
    - t0;
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_encoding_t0_serialize(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_ತುಂಡು_u8 serialized
)
{
  int32_t
  coefficient0 = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(simd_unit->ದತ್ತಾಂಶ[0U]);
  int32_t
  coefficient1 = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(simd_unit->ದತ್ತಾಂಶ[1U]);
  int32_t
  coefficient2 = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(simd_unit->ದತ್ತಾಂಶ[2U]);
  int32_t
  coefficient3 = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(simd_unit->ದತ್ತಾಂಶ[3U]);
  int32_t
  coefficient4 = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(simd_unit->ದತ್ತಾಂಶ[4U]);
  int32_t
  coefficient5 = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(simd_unit->ದತ್ತಾಂಶ[5U]);
  int32_t
  coefficient6 = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(simd_unit->ದತ್ತಾಂಶ[6U]);
  int32_t
  coefficient7 = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(simd_unit->ದತ್ತಾಂಶ[7U]);
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_t0_serialize_65(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_ತುಂಡು_u8 ಹೊರಹೋಗು
)
{
  libcrux_ml_dsa_simd_portable_encoding_t0_serialize(simd_unit, ಹೊರಹೋಗು);
}

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_T0_DESERIALIZE_ಬಿಟ್ಟುಗಳು_ಒಳ_ಅಧೋ_PART_ದ_T_ಮುಖವಾಡ ((int32_t)((uint32_t)1 << (uint32_t)(int32_t)LIBCRUX_ML_DSA_CONSTANTS_ಬಿಟ್ಟುಗಳು_ಒಳ_ಅಧೋ_PART_ದ_T) - 1)

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_encoding_t0_deserialize(
  Eurydice_borrow_ತುಂಡು_u8 serialized,
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
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_T0_DESERIALIZE_ಬಿಟ್ಟುಗಳು_ಒಳ_ಅಧೋ_PART_ದ_T_ಮುಖವಾಡ;
  int32_t coefficient1 = byte1 >> 5U;
  coefficient1 |= (int32_t)((uint32_t)byte2 << 3U);
  coefficient1 |= (int32_t)((uint32_t)byte3 << 11U);
  coefficient1 &=
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_T0_DESERIALIZE_ಬಿಟ್ಟುಗಳು_ಒಳ_ಅಧೋ_PART_ದ_T_ಮುಖವಾಡ;
  int32_t coefficient2 = byte3 >> 2U;
  coefficient2 |= (int32_t)((uint32_t)byte4 << 6U);
  coefficient2 &=
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_T0_DESERIALIZE_ಬಿಟ್ಟುಗಳು_ಒಳ_ಅಧೋ_PART_ದ_T_ಮುಖವಾಡ;
  int32_t coefficient3 = byte4 >> 7U;
  coefficient3 |= (int32_t)((uint32_t)byte5 << 1U);
  coefficient3 |= (int32_t)((uint32_t)byte6 << 9U);
  coefficient3 &=
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_T0_DESERIALIZE_ಬಿಟ್ಟುಗಳು_ಒಳ_ಅಧೋ_PART_ದ_T_ಮುಖವಾಡ;
  int32_t coefficient4 = byte6 >> 4U;
  coefficient4 |= (int32_t)((uint32_t)byte7 << 4U);
  coefficient4 |= (int32_t)((uint32_t)byte8 << 12U);
  coefficient4 &=
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_T0_DESERIALIZE_ಬಿಟ್ಟುಗಳು_ಒಳ_ಅಧೋ_PART_ದ_T_ಮುಖವಾಡ;
  int32_t coefficient5 = byte8 >> 1U;
  coefficient5 |= (int32_t)((uint32_t)byte9 << 7U);
  coefficient5 &=
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_T0_DESERIALIZE_ಬಿಟ್ಟುಗಳು_ಒಳ_ಅಧೋ_PART_ದ_T_ಮುಖವಾಡ;
  int32_t coefficient6 = byte9 >> 6U;
  coefficient6 |= (int32_t)((uint32_t)byte10 << 2U);
  coefficient6 |= (int32_t)((uint32_t)byte11 << 10U);
  coefficient6 &=
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_T0_DESERIALIZE_ಬಿಟ್ಟುಗಳು_ಒಳ_ಅಧೋ_PART_ದ_T_ಮುಖವಾಡ;
  int32_t coefficient7 = byte11 >> 3U;
  coefficient7 |= (int32_t)((uint32_t)byte12 << 5U);
  coefficient7 &=
    LIBCRUX_ML_DSA_SIMD_PORTABLE_ENCODING_T0_DESERIALIZE_ಬಿಟ್ಟುಗಳು_ಒಳ_ಅಧೋ_PART_ದ_T_ಮುಖವಾಡ;
  simd_unit->ದತ್ತಾಂಶ[0U] = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(coefficient0);
  simd_unit->ದತ್ತಾಂಶ[1U] = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(coefficient1);
  simd_unit->ದತ್ತಾಂಶ[2U] = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(coefficient2);
  simd_unit->ದತ್ತಾಂಶ[3U] = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(coefficient3);
  simd_unit->ದತ್ತಾಂಶ[4U] = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(coefficient4);
  simd_unit->ದತ್ತಾಂಶ[5U] = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(coefficient5);
  simd_unit->ದತ್ತಾಂಶ[6U] = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(coefficient6);
  simd_unit->ದತ್ತಾಂಶ[7U] = libcrux_ml_dsa_simd_portable_encoding_t0_change_t0_interval(coefficient7);
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_t0_deserialize_65(
  Eurydice_borrow_ತುಂಡು_u8 serialized,
  Eurydice_arr_4d *ಹೊರಹೋಗು
)
{
  libcrux_ml_dsa_simd_portable_encoding_t0_deserialize(serialized, ಹೊರಹೋಗು);
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_encoding_t1_serialize(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_ತುಂಡು_u8 serialized
)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)8U / (ಗಾತ್ರ_t)4U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    Eurydice_dst_ref_shared_83
    coefficients =
      Eurydice_array_ಗಮ್ಯ_subslice_shared_44(simd_unit,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ಆರಂಭ = i0 * (ಗಾತ್ರ_t)4U,
            .ಕೊನೆ = i0 * (ಗಾತ್ರ_t)4U + (ಗಾತ್ರ_t)4U
          }
        ));
    serialized.ptr[(ಗಾತ್ರ_t)5U * i0] = (uint8_t)(coefficients.ptr[0U] & 255);
    serialized.ptr[(ಗಾತ್ರ_t)5U * i0 + (ಗಾತ್ರ_t)1U] =
      (uint32_t)(uint8_t)(coefficients.ptr[1U] & 63) << 2U |
        (uint32_t)(uint8_t)(coefficients.ptr[0U] >> 8U & 3);
    serialized.ptr[(ಗಾತ್ರ_t)5U * i0 + (ಗಾತ್ರ_t)2U] =
      (uint32_t)(uint8_t)(coefficients.ptr[2U] & 15) << 4U |
        (uint32_t)(uint8_t)(coefficients.ptr[1U] >> 6U & 15);
    serialized.ptr[(ಗಾತ್ರ_t)5U * i0 + (ಗಾತ್ರ_t)3U] =
      (uint32_t)(uint8_t)(coefficients.ptr[3U] & 3) << 6U |
        (uint32_t)(uint8_t)(coefficients.ptr[2U] >> 4U & 63);
    serialized.ptr[(ಗಾತ್ರ_t)5U * i0 + (ಗಾತ್ರ_t)4U] = (uint8_t)(coefficients.ptr[3U] >> 2U & 255);
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_t1_serialize_65(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_4d *simd_unit,
  Eurydice_mut_borrow_ತುಂಡು_u8 ಹೊರಹೋಗು
)
{
  libcrux_ml_dsa_simd_portable_encoding_t1_serialize(simd_unit, ಹೊರಹೋಗು);
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_encoding_t1_deserialize(
  Eurydice_borrow_ತುಂಡು_u8 serialized,
  Eurydice_arr_4d *simd_unit
)
{
  int32_t
  ಮುಖವಾಡ = (int32_t)((uint32_t)1 << (uint32_t)LIBCRUX_ML_DSA_CONSTANTS_ಬಿಟ್ಟುಗಳು_ಒಳ_ಊರ್ಧ್ವ_PART_ದ_T) - 1;
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < serialized.meta / (ಗಾತ್ರ_t)5U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    Eurydice_borrow_ತುಂಡು_u8
    ಬೈಟುಗಳು =
      Eurydice_ತುಂಡು_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ಆರಂಭ = i0 * (ಗಾತ್ರ_t)5U,
            .ಕೊನೆ = i0 * (ಗಾತ್ರ_t)5U + (ಗಾತ್ರ_t)5U
          }
        ));
    int32_t byte0 = (int32_t)(uint32_t)ಬೈಟುಗಳು.ptr[0U];
    int32_t byte1 = (int32_t)(uint32_t)ಬೈಟುಗಳು.ptr[1U];
    int32_t byte2 = (int32_t)(uint32_t)ಬೈಟುಗಳು.ptr[2U];
    int32_t byte3 = (int32_t)(uint32_t)ಬೈಟುಗಳು.ptr[3U];
    int32_t byte4 = (int32_t)(uint32_t)ಬೈಟುಗಳು.ptr[4U];
    simd_unit->ದತ್ತಾಂಶ[(ಗಾತ್ರ_t)4U * i0] = (byte0 | (int32_t)((uint32_t)byte1 << 8U)) & ಮುಖವಾಡ;
    simd_unit->ದತ್ತಾಂಶ[(ಗಾತ್ರ_t)4U * i0 + (ಗಾತ್ರ_t)1U] =
      (byte1 >> 2U | (int32_t)((uint32_t)byte2 << 6U)) & ಮುಖವಾಡ;
    simd_unit->ದತ್ತಾಂಶ[(ಗಾತ್ರ_t)4U * i0 + (ಗಾತ್ರ_t)2U] =
      (byte2 >> 4U | (int32_t)((uint32_t)byte3 << 4U)) & ಮುಖವಾಡ;
    simd_unit->ದತ್ತಾಂಶ[(ಗಾತ್ರ_t)4U * i0 + (ಗಾತ್ರ_t)3U] =
      (byte3 >> 6U | (int32_t)((uint32_t)byte4 << 2U)) & ಮುಖವಾಡ;
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_t1_deserialize_65(
  Eurydice_borrow_ತುಂಡು_u8 serialized,
  Eurydice_arr_4d *ಹೊರಹೋಗು
)
{
  libcrux_ml_dsa_simd_portable_encoding_t1_deserialize(serialized, ಹೊರಹೋಗು);
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(
  Eurydice_arr_4d *simd_unit,
  int32_t c
)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)8U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    simd_unit->ದತ್ತಾಂಶ[i0] =
      libcrux_ml_dsa_simd_portable_arithmetic_montgomery_reduce_element((int64_t)simd_unit->ದತ್ತಾಂಶ[i0]
        * (int64_t)c);
  }
}

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- $32size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_a3_s { Eurydice_arr_4d ದತ್ತಾಂಶ[32U]; } Eurydice_arr_a3;

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_ಸುತ್ತು(
  Eurydice_arr_a3 *re,
  ಗಾತ್ರ_t index,
  ಗಾತ್ರ_t ಹೆಜ್ಜೆ_by,
  int32_t zeta
)
{
  Eurydice_arr_4d tmp = re->ದತ್ತಾಂಶ[index + ಹೆಜ್ಜೆ_by];
  libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&tmp, zeta);
  re->ದತ್ತಾಂಶ[index + ಹೆಜ್ಜೆ_by] = re->ದತ್ತಾಂಶ[index];
  libcrux_ml_dsa_simd_portable_arithmetic_ಕಳೆ(&re->ದತ್ತಾಂಶ[index + ಹೆಜ್ಜೆ_by], &tmp);
  libcrux_ml_dsa_simd_portable_arithmetic_ಕೂಡಿಸು(&re->ದತ್ತಾಂಶ[index], &tmp);
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 0
- STEP_BY= 16
- ZETA= 25847
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_30(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)0U + (ಗಾತ್ರ_t)16U; i++)
  {
    ಗಾತ್ರ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_ಸುತ್ತು(re, j, (ಗಾತ್ರ_t)16U, 25847);
  }
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_300(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)0U + (ಗಾತ್ರ_t)8U; i++)
  {
    ಗಾತ್ರ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_ಸುತ್ತು(re, j, (ಗಾತ್ರ_t)8U, -2608894);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 16
- STEP_BY= 8
- ZETA= -518909
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_42(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)16U; i < (ಗಾತ್ರ_t)16U + (ಗಾತ್ರ_t)8U; i++)
  {
    ಗಾತ್ರ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_ಸುತ್ತು(re, j, (ಗಾತ್ರ_t)8U, -518909);
  }
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_301(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)0U + (ಗಾತ್ರ_t)4U; i++)
  {
    ಗಾತ್ರ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_ಸುತ್ತು(re, j, (ಗಾತ್ರ_t)4U, 237124);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 8
- STEP_BY= 4
- ZETA= -777960
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_82(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)8U; i < (ಗಾತ್ರ_t)8U + (ಗಾತ್ರ_t)4U; i++)
  {
    ಗಾತ್ರ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_ಸುತ್ತು(re, j, (ಗಾತ್ರ_t)4U, -777960);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 16
- STEP_BY= 4
- ZETA= -876248
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_420(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)16U; i < (ಗಾತ್ರ_t)16U + (ಗಾತ್ರ_t)4U; i++)
  {
    ಗಾತ್ರ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_ಸುತ್ತು(re, j, (ಗಾತ್ರ_t)4U, -876248);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 24
- STEP_BY= 4
- ZETA= 466468
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_fe(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)24U; i < (ಗಾತ್ರ_t)24U + (ಗಾತ್ರ_t)4U; i++)
  {
    ಗಾತ್ರ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_ಸುತ್ತು(re, j, (ಗಾತ್ರ_t)4U, 466468);
  }
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_302(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)0U + (ಗಾತ್ರ_t)2U; i++)
  {
    ಗಾತ್ರ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_ಸುತ್ತು(re, j, (ಗಾತ್ರ_t)2U, 1826347);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 4
- STEP_BY= 2
- ZETA= 2353451
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_43(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)4U; i < (ಗಾತ್ರ_t)4U + (ಗಾತ್ರ_t)2U; i++)
  {
    ಗಾತ್ರ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_ಸುತ್ತು(re, j, (ಗಾತ್ರ_t)2U, 2353451);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 8
- STEP_BY= 2
- ZETA= -359251
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_820(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)8U; i < (ಗಾತ್ರ_t)8U + (ಗಾತ್ರ_t)2U; i++)
  {
    ಗಾತ್ರ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_ಸುತ್ತು(re, j, (ಗಾತ್ರ_t)2U, -359251);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 12
- STEP_BY= 2
- ZETA= -2091905
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_ea(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)12U; i < (ಗಾತ್ರ_t)12U + (ಗಾತ್ರ_t)2U; i++)
  {
    ಗಾತ್ರ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_ಸುತ್ತು(re, j, (ಗಾತ್ರ_t)2U, -2091905);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 16
- STEP_BY= 2
- ZETA= 3119733
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_421(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)16U; i < (ಗಾತ್ರ_t)16U + (ಗಾತ್ರ_t)2U; i++)
  {
    ಗಾತ್ರ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_ಸುತ್ತು(re, j, (ಗಾತ್ರ_t)2U, 3119733);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 20
- STEP_BY= 2
- ZETA= -2884855
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_61(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)20U; i < (ಗಾತ್ರ_t)20U + (ಗಾತ್ರ_t)2U; i++)
  {
    ಗಾತ್ರ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_ಸುತ್ತು(re, j, (ಗಾತ್ರ_t)2U, -2884855);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 24
- STEP_BY= 2
- ZETA= 3111497
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_fe0(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)24U; i < (ಗಾತ್ರ_t)24U + (ಗಾತ್ರ_t)2U; i++)
  {
    ಗಾತ್ರ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_ಸುತ್ತು(re, j, (ಗಾತ್ರ_t)2U, 3111497);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 28
- STEP_BY= 2
- ZETA= 2680103
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_38(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)28U; i < (ಗಾತ್ರ_t)28U + (ಗಾತ್ರ_t)2U; i++)
  {
    ಗಾತ್ರ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_ಸುತ್ತು(re, j, (ಗಾತ್ರ_t)2U, 2680103);
  }
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_303(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)0U + (ಗಾತ್ರ_t)1U; i++)
  {
    ಗಾತ್ರ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_ಸುತ್ತು(re, j, (ಗಾತ್ರ_t)1U, 2725464);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 2
- STEP_BY= 1
- ZETA= 1024112
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_25(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)2U; i < (ಗಾತ್ರ_t)2U + (ಗಾತ್ರ_t)1U; i++)
  {
    ಗಾತ್ರ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_ಸುತ್ತು(re, j, (ಗಾತ್ರ_t)1U, 1024112);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 4
- STEP_BY= 1
- ZETA= -1079900
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_430(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)4U; i < (ಗಾತ್ರ_t)4U + (ಗಾತ್ರ_t)1U; i++)
  {
    ಗಾತ್ರ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_ಸುತ್ತು(re, j, (ಗಾತ್ರ_t)1U, -1079900);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 6
- STEP_BY= 1
- ZETA= 3585928
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_f4(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)6U; i < (ಗಾತ್ರ_t)6U + (ಗಾತ್ರ_t)1U; i++)
  {
    ಗಾತ್ರ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_ಸುತ್ತು(re, j, (ಗಾತ್ರ_t)1U, 3585928);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 8
- STEP_BY= 1
- ZETA= -549488
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_821(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)8U; i < (ಗಾತ್ರ_t)8U + (ಗಾತ್ರ_t)1U; i++)
  {
    ಗಾತ್ರ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_ಸುತ್ತು(re, j, (ಗಾತ್ರ_t)1U, -549488);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 10
- STEP_BY= 1
- ZETA= -1119584
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_1d(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)10U; i < (ಗಾತ್ರ_t)10U + (ಗಾತ್ರ_t)1U; i++)
  {
    ಗಾತ್ರ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_ಸುತ್ತು(re, j, (ಗಾತ್ರ_t)1U, -1119584);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 12
- STEP_BY= 1
- ZETA= 2619752
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_ea0(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)12U; i < (ಗಾತ್ರ_t)12U + (ಗಾತ್ರ_t)1U; i++)
  {
    ಗಾತ್ರ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_ಸುತ್ತು(re, j, (ಗಾತ್ರ_t)1U, 2619752);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 14
- STEP_BY= 1
- ZETA= -2108549
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_d8(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)14U; i < (ಗಾತ್ರ_t)14U + (ಗಾತ್ರ_t)1U; i++)
  {
    ಗಾತ್ರ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_ಸುತ್ತು(re, j, (ಗಾತ್ರ_t)1U, -2108549);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 16
- STEP_BY= 1
- ZETA= -2118186
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_422(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)16U; i < (ಗಾತ್ರ_t)16U + (ಗಾತ್ರ_t)1U; i++)
  {
    ಗಾತ್ರ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_ಸುತ್ತು(re, j, (ಗಾತ್ರ_t)1U, -2118186);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 18
- STEP_BY= 1
- ZETA= -3859737
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_60(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)18U; i < (ಗಾತ್ರ_t)18U + (ಗಾತ್ರ_t)1U; i++)
  {
    ಗಾತ್ರ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_ಸುತ್ತು(re, j, (ಗಾತ್ರ_t)1U, -3859737);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 20
- STEP_BY= 1
- ZETA= -1399561
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_610(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)20U; i < (ಗಾತ್ರ_t)20U + (ಗಾತ್ರ_t)1U; i++)
  {
    ಗಾತ್ರ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_ಸುತ್ತು(re, j, (ಗಾತ್ರ_t)1U, -1399561);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 22
- STEP_BY= 1
- ZETA= -3277672
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_29(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)22U; i < (ಗಾತ್ರ_t)22U + (ಗಾತ್ರ_t)1U; i++)
  {
    ಗಾತ್ರ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_ಸುತ್ತು(re, j, (ಗಾತ್ರ_t)1U, -3277672);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 24
- STEP_BY= 1
- ZETA= 1757237
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_fe1(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)24U; i < (ಗಾತ್ರ_t)24U + (ಗಾತ್ರ_t)1U; i++)
  {
    ಗಾತ್ರ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_ಸುತ್ತು(re, j, (ಗಾತ್ರ_t)1U, 1757237);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 26
- STEP_BY= 1
- ZETA= -19422
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_9d(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)26U; i < (ಗಾತ್ರ_t)26U + (ಗಾತ್ರ_t)1U; i++)
  {
    ಗಾತ್ರ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_ಸುತ್ತು(re, j, (ಗಾತ್ರ_t)1U, -19422);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 28
- STEP_BY= 1
- ZETA= 4010497
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_380(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)28U; i < (ಗಾತ್ರ_t)28U + (ಗಾತ್ರ_t)1U; i++)
  {
    ಗಾತ್ರ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_ಸುತ್ತು(re, j, (ಗಾತ್ರ_t)1U, 4010497);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.ntt.outer_3_plus
with const generics
- OFFSET= 30
- STEP_BY= 1
- ZETA= 280005
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_5f(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)30U; i < (ಗಾತ್ರ_t)30U + (ಗಾತ್ರ_t)1U; i++)
  {
    ಗಾತ್ರ_t j = i;
    libcrux_ml_dsa_simd_portable_ntt_outer_3_plus_ಸುತ್ತು(re, j, (ಗಾತ್ರ_t)1U, 280005);
  }
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
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

ಸ್ಥಿರ KRML_MUSTINLINE int32_t
libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_fe_by_fer(int32_t fe, int32_t fer)
{
  ಹಿಂತಿರುಗಿ
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_reduce_element((int64_t)fe * (int64_t)fer);
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_ಹೆಜ್ಜೆ(
  Eurydice_arr_4d *simd_unit,
  int32_t zeta,
  ಗಾತ್ರ_t index,
  ಗಾತ್ರ_t ಹೆಜ್ಜೆ
)
{
  int32_t
  t =
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_fe_by_fer(simd_unit->ದತ್ತಾಂಶ[index +
        ಹೆಜ್ಜೆ],
      zeta);
  simd_unit->ದತ್ತಾಂಶ[index + ಹೆಜ್ಜೆ] = simd_unit->ದತ್ತಾಂಶ[index] - t;
  simd_unit->ದತ್ತಾಂಶ[index] += t;
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_at_layer_2(
  Eurydice_arr_4d *simd_unit,
  int32_t zeta
)
{
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_ಹೆಜ್ಜೆ(simd_unit, zeta, (ಗಾತ್ರ_t)0U, (ಗಾತ್ರ_t)4U);
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_ಹೆಜ್ಜೆ(simd_unit, zeta, (ಗಾತ್ರ_t)1U, (ಗಾತ್ರ_t)4U);
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_ಹೆಜ್ಜೆ(simd_unit, zeta, (ಗಾತ್ರ_t)2U, (ಗಾತ್ರ_t)4U);
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_ಹೆಜ್ಜೆ(simd_unit, zeta, (ಗಾತ್ರ_t)3U, (ಗಾತ್ರ_t)4U);
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_ಸುತ್ತು(
  Eurydice_arr_a3 *re,
  ಗಾತ್ರ_t index,
  int32_t zeta
)
{
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_at_layer_2(&re->ದತ್ತಾಂಶ[index], zeta);
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)0U, 2706023);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)1U, 95776);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)2U, 3077325);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)3U, 3530437);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)4U, -1661693);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)5U, -3592148);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)6U, -2537516);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)7U, 3915439);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)8U, -3861115);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)9U, -3043716);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)10U, 3574422);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)11U, -2867647);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)12U, 3539968);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)13U, -300467);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)14U, 2348700);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)15U, -539299);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)16U, -1699267);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)17U, -1643818);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)18U, 3505694);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)19U, -3821735);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)20U, 3507263);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)21U, -2140649);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)22U, -1600420);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)23U, 3699596);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)24U, 811944);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)25U, 531354);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)26U, 954230);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)27U, 3881043);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)28U, 3900724);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)29U, -2556880);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)30U, 2071892);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)31U, -2797779);
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_at_layer_1(
  Eurydice_arr_4d *simd_unit,
  int32_t zeta1,
  int32_t zeta2
)
{
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_ಹೆಜ್ಜೆ(simd_unit, zeta1, (ಗಾತ್ರ_t)0U, (ಗಾತ್ರ_t)2U);
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_ಹೆಜ್ಜೆ(simd_unit, zeta1, (ಗಾತ್ರ_t)1U, (ಗಾತ್ರ_t)2U);
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_ಹೆಜ್ಜೆ(simd_unit, zeta2, (ಗಾತ್ರ_t)4U, (ಗಾತ್ರ_t)2U);
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_ಹೆಜ್ಜೆ(simd_unit, zeta2, (ಗಾತ್ರ_t)5U, (ಗಾತ್ರ_t)2U);
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_ಸುತ್ತು(
  Eurydice_arr_a3 *re,
  ಗಾತ್ರ_t index,
  int32_t zeta_0,
  int32_t zeta_1
)
{
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_at_layer_1(&re->ದತ್ತಾಂಶ[index], zeta_0, zeta_1);
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_ಸುತ್ತು(re, (ಗಾತ್ರ_t)0U, -3930395, -1528703);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_ಸುತ್ತು(re, (ಗಾತ್ರ_t)1U, -3677745, -3041255);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_ಸುತ್ತು(re, (ಗಾತ್ರ_t)2U, -1452451, 3475950);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_ಸುತ್ತು(re, (ಗಾತ್ರ_t)3U, 2176455, -1585221);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_ಸುತ್ತು(re, (ಗಾತ್ರ_t)4U, -1257611, 1939314);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_ಸುತ್ತು(re, (ಗಾತ್ರ_t)5U, -4083598, -1000202);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_ಸುತ್ತು(re, (ಗಾತ್ರ_t)6U, -3190144, -3157330);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_ಸುತ್ತು(re, (ಗಾತ್ರ_t)7U, -3632928, 126922);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_ಸುತ್ತು(re, (ಗಾತ್ರ_t)8U, 3412210, -983419);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_ಸುತ್ತು(re, (ಗಾತ್ರ_t)9U, 2147896, 2715295);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_ಸುತ್ತು(re, (ಗಾತ್ರ_t)10U, -2967645, -3693493);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_ಸುತ್ತು(re, (ಗಾತ್ರ_t)11U, -411027, -2477047);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_ಸುತ್ತು(re, (ಗಾತ್ರ_t)12U, -671102, -1228525);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_ಸುತ್ತು(re, (ಗಾತ್ರ_t)13U, -22981, -1308169);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_ಸುತ್ತು(re, (ಗಾತ್ರ_t)14U, -381987, 1349076);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_ಸುತ್ತು(re, (ಗಾತ್ರ_t)15U, 1852771, -1430430);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_ಸುತ್ತು(re, (ಗಾತ್ರ_t)16U, -3343383, 264944);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_ಸುತ್ತು(re, (ಗಾತ್ರ_t)17U, 508951, 3097992);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_ಸುತ್ತು(re, (ಗಾತ್ರ_t)18U, 44288, -1100098);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_ಸುತ್ತು(re, (ಗಾತ್ರ_t)19U, 904516, 3958618);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_ಸುತ್ತು(re, (ಗಾತ್ರ_t)20U, -3724342, -8578);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_ಸುತ್ತು(re, (ಗಾತ್ರ_t)21U, 1653064, -3249728);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_ಸುತ್ತು(re, (ಗಾತ್ರ_t)22U, 2389356, -210977);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_ಸುತ್ತು(re, (ಗಾತ್ರ_t)23U, 759969, -1316856);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_ಸುತ್ತು(re, (ಗಾತ್ರ_t)24U, 189548, -3553272);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_ಸುತ್ತು(re, (ಗಾತ್ರ_t)25U, 3159746, -1851402);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_ಸುತ್ತು(re, (ಗಾತ್ರ_t)26U, -2409325, -177440);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_ಸುತ್ತು(re, (ಗಾತ್ರ_t)27U, 1315589, 1341330);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_ಸುತ್ತು(re, (ಗಾತ್ರ_t)28U, 1285669, -1584928);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_ಸುತ್ತು(re, (ಗಾತ್ರ_t)29U, -812732, -1439742);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_ಸುತ್ತು(re, (ಗಾತ್ರ_t)30U, -3019102, -3881060);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_1_ಸುತ್ತು(re, (ಗಾತ್ರ_t)31U, -3628969, 3839961);
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_at_layer_0(
  Eurydice_arr_4d *simd_unit,
  int32_t zeta0,
  int32_t zeta1,
  int32_t zeta2,
  int32_t zeta3
)
{
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_ಹೆಜ್ಜೆ(simd_unit, zeta0, (ಗಾತ್ರ_t)0U, (ಗಾತ್ರ_t)1U);
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_ಹೆಜ್ಜೆ(simd_unit, zeta1, (ಗಾತ್ರ_t)2U, (ಗಾತ್ರ_t)1U);
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_ಹೆಜ್ಜೆ(simd_unit, zeta2, (ಗಾತ್ರ_t)4U, (ಗಾತ್ರ_t)1U);
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_ಹೆಜ್ಜೆ(simd_unit, zeta3, (ಗಾತ್ರ_t)6U, (ಗಾತ್ರ_t)1U);
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_ಸುತ್ತು(
  Eurydice_arr_a3 *re,
  ಗಾತ್ರ_t index,
  int32_t zeta_0,
  int32_t zeta_1,
  int32_t zeta_2,
  int32_t zeta_3
)
{
  libcrux_ml_dsa_simd_portable_ntt_simd_unit_ntt_at_layer_0(&re->ದತ್ತಾಂಶ[index],
    zeta_0,
    zeta_1,
    zeta_2,
    zeta_3);
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)0U,
    2091667,
    3407706,
    2316500,
    3817976);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)1U,
    -3342478,
    2244091,
    -2446433,
    -3562462);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)2U,
    266997,
    2434439,
    -1235728,
    3513181);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)3U,
    -3520352,
    -3759364,
    -1197226,
    -3193378);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)4U,
    900702,
    1859098,
    909542,
    819034);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)5U,
    495491,
    -1613174,
    -43260,
    -522500);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)6U,
    -655327,
    -3122442,
    2031748,
    3207046);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)7U,
    -3556995,
    -525098,
    -768622,
    -3595838);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)8U,
    342297,
    286988,
    -2437823,
    4108315);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)9U,
    3437287,
    -3342277,
    1735879,
    203044);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)10U,
    2842341,
    2691481,
    -2590150,
    1265009);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)11U,
    4055324,
    1247620,
    2486353,
    1595974);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)12U,
    -3767016,
    1250494,
    2635921,
    -3548272);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)13U,
    -2994039,
    1869119,
    1903435,
    -1050970);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)14U,
    -1333058,
    1237275,
    -3318210,
    -1430225);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)15U,
    -451100,
    1312455,
    3306115,
    -1962642);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)16U,
    -1279661,
    1917081,
    -2546312,
    -1374803);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)17U,
    1500165,
    777191,
    2235880,
    3406031);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)18U,
    -542412,
    -2831860,
    -1671176,
    -1846953);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)19U,
    -2584293,
    -3724270,
    594136,
    -3776993);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)20U,
    -2013608,
    2432395,
    2454455,
    -164721);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)21U,
    1957272,
    3369112,
    185531,
    -1207385);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)22U,
    -3183426,
    162844,
    1616392,
    3014001);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)23U,
    810149,
    1652634,
    -3694233,
    -1799107);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)24U,
    -3038916,
    3523897,
    3866901,
    269760);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)25U,
    2213111,
    -975884,
    1717735,
    472078);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)26U,
    -426683,
    1723600,
    -1803090,
    1910376);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)27U,
    -1667432,
    -1104333,
    -260646,
    -3833893);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)28U,
    -2939036,
    -2235985,
    -420899,
    -2286327);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)29U,
    183443,
    -976891,
    1612842,
    -3545687);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)30U,
    -554416,
    3919660,
    -48306,
    -1362209);
  libcrux_ml_dsa_simd_portable_ntt_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)31U,
    3937738,
    1400424,
    -846154,
    1976782);
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ libcrux_ml_dsa_simd_portable_ntt_ntt(Eurydice_arr_a3 *re)
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ libcrux_ml_dsa_simd_portable_ntt_65(Eurydice_arr_a3 *simd_units)
{
  libcrux_ml_dsa_simd_portable_ntt_ntt(simd_units);
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_ಹೆಜ್ಜೆ(
  Eurydice_arr_4d *simd_unit,
  int32_t zeta,
  ಗಾತ್ರ_t index,
  ಗಾತ್ರ_t ಹೆಜ್ಜೆ
)
{
  int32_t a_minus_b = simd_unit->ದತ್ತಾಂಶ[index + ಹೆಜ್ಜೆ] - simd_unit->ದತ್ತಾಂಶ[index];
  simd_unit->ದತ್ತಾಂಶ[index] += simd_unit->ದತ್ತಾಂಶ[index + ಹೆಜ್ಜೆ];
  simd_unit->ದತ್ತಾಂಶ[index + ಹೆಜ್ಜೆ] =
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_fe_by_fer(a_minus_b,
      zeta);
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_invntt_simd_unit_invert_ntt_at_layer_0(
  Eurydice_arr_4d *simd_unit,
  int32_t zeta0,
  int32_t zeta1,
  int32_t zeta2,
  int32_t zeta3
)
{
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_ಹೆಜ್ಜೆ(simd_unit,
    zeta0,
    (ಗಾತ್ರ_t)0U,
    (ಗಾತ್ರ_t)1U);
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_ಹೆಜ್ಜೆ(simd_unit,
    zeta1,
    (ಗಾತ್ರ_t)2U,
    (ಗಾತ್ರ_t)1U);
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_ಹೆಜ್ಜೆ(simd_unit,
    zeta2,
    (ಗಾತ್ರ_t)4U,
    (ಗಾತ್ರ_t)1U);
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_ಹೆಜ್ಜೆ(simd_unit,
    zeta3,
    (ಗಾತ್ರ_t)6U,
    (ಗಾತ್ರ_t)1U);
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_ಸುತ್ತು(
  Eurydice_arr_a3 *re,
  ಗಾತ್ರ_t index,
  int32_t zeta0,
  int32_t zeta1,
  int32_t zeta2,
  int32_t zeta3
)
{
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_invert_ntt_at_layer_0(&re->ದತ್ತಾಂಶ[index],
    zeta0,
    zeta1,
    zeta2,
    zeta3);
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)0U,
    1976782,
    -846154,
    1400424,
    3937738);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)1U,
    -1362209,
    -48306,
    3919660,
    -554416);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)2U,
    -3545687,
    1612842,
    -976891,
    183443);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)3U,
    -2286327,
    -420899,
    -2235985,
    -2939036);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)4U,
    -3833893,
    -260646,
    -1104333,
    -1667432);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)5U,
    1910376,
    -1803090,
    1723600,
    -426683);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)6U,
    472078,
    1717735,
    -975884,
    2213111);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)7U,
    269760,
    3866901,
    3523897,
    -3038916);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)8U,
    -1799107,
    -3694233,
    1652634,
    810149);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)9U,
    3014001,
    1616392,
    162844,
    -3183426);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)10U,
    -1207385,
    185531,
    3369112,
    1957272);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)11U,
    -164721,
    2454455,
    2432395,
    -2013608);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)12U,
    -3776993,
    594136,
    -3724270,
    -2584293);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)13U,
    -1846953,
    -1671176,
    -2831860,
    -542412);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)14U,
    3406031,
    2235880,
    777191,
    1500165);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)15U,
    -1374803,
    -2546312,
    1917081,
    -1279661);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)16U,
    -1962642,
    3306115,
    1312455,
    -451100);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)17U,
    -1430225,
    -3318210,
    1237275,
    -1333058);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)18U,
    -1050970,
    1903435,
    1869119,
    -2994039);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)19U,
    -3548272,
    2635921,
    1250494,
    -3767016);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)20U,
    1595974,
    2486353,
    1247620,
    4055324);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)21U,
    1265009,
    -2590150,
    2691481,
    2842341);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)22U,
    203044,
    1735879,
    -3342277,
    3437287);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)23U,
    4108315,
    -2437823,
    286988,
    342297);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)24U,
    -3595838,
    -768622,
    -525098,
    -3556995);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)25U,
    3207046,
    2031748,
    -3122442,
    -655327);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)26U,
    -522500,
    -43260,
    -1613174,
    495491);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)27U,
    819034,
    909542,
    1859098,
    900702);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)28U,
    -3193378,
    -1197226,
    -3759364,
    -3520352);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)29U,
    3513181,
    -1235728,
    2434439,
    266997);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)30U,
    -3562462,
    -2446433,
    2244091,
    -3342478);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_0_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)31U,
    3817976,
    2316500,
    3407706,
    2091667);
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_invntt_simd_unit_invert_ntt_at_layer_1(
  Eurydice_arr_4d *simd_unit,
  int32_t zeta0,
  int32_t zeta1
)
{
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_ಹೆಜ್ಜೆ(simd_unit,
    zeta0,
    (ಗಾತ್ರ_t)0U,
    (ಗಾತ್ರ_t)2U);
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_ಹೆಜ್ಜೆ(simd_unit,
    zeta0,
    (ಗಾತ್ರ_t)1U,
    (ಗಾತ್ರ_t)2U);
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_ಹೆಜ್ಜೆ(simd_unit,
    zeta1,
    (ಗಾತ್ರ_t)4U,
    (ಗಾತ್ರ_t)2U);
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_ಹೆಜ್ಜೆ(simd_unit,
    zeta1,
    (ಗಾತ್ರ_t)5U,
    (ಗಾತ್ರ_t)2U);
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_ಸುತ್ತು(
  Eurydice_arr_a3 *re,
  ಗಾತ್ರ_t index,
  int32_t zeta_00,
  int32_t zeta_01
)
{
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_invert_ntt_at_layer_1(&re->ದತ್ತಾಂಶ[index],
    zeta_00,
    zeta_01);
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)0U,
    3839961,
    -3628969);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)1U,
    -3881060,
    -3019102);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)2U,
    -1439742,
    -812732);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)3U,
    -1584928,
    1285669);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)4U,
    1341330,
    1315589);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)5U,
    -177440,
    -2409325);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)6U,
    -1851402,
    3159746);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)7U,
    -3553272,
    189548);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)8U,
    -1316856,
    759969);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)9U,
    -210977,
    2389356);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)10U,
    -3249728,
    1653064);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)11U,
    -8578,
    -3724342);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)12U,
    3958618,
    904516);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)13U,
    -1100098,
    44288);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)14U,
    3097992,
    508951);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)15U,
    264944,
    -3343383);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)16U,
    -1430430,
    1852771);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)17U,
    1349076,
    -381987);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)18U,
    -1308169,
    -22981);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)19U,
    -1228525,
    -671102);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)20U,
    -2477047,
    -411027);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)21U,
    -3693493,
    -2967645);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)22U,
    2715295,
    2147896);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)23U,
    -983419,
    3412210);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)24U,
    126922,
    -3632928);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)25U,
    -3157330,
    -3190144);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)26U,
    -1000202,
    -4083598);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)27U,
    1939314,
    -1257611);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)28U,
    -1585221,
    2176455);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)29U,
    3475950,
    -1452451);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)30U,
    -3041255,
    -3677745);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_1_ಸುತ್ತು(re,
    (ಗಾತ್ರ_t)31U,
    -1528703,
    -3930395);
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_invntt_simd_unit_invert_ntt_at_layer_2(
  Eurydice_arr_4d *simd_unit,
  int32_t zeta
)
{
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_ಹೆಜ್ಜೆ(simd_unit,
    zeta,
    (ಗಾತ್ರ_t)0U,
    (ಗಾತ್ರ_t)4U);
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_ಹೆಜ್ಜೆ(simd_unit,
    zeta,
    (ಗಾತ್ರ_t)1U,
    (ಗಾತ್ರ_t)4U);
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_ಹೆಜ್ಜೆ(simd_unit,
    zeta,
    (ಗಾತ್ರ_t)2U,
    (ಗಾತ್ರ_t)4U);
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_inv_ntt_ಹೆಜ್ಜೆ(simd_unit,
    zeta,
    (ಗಾತ್ರ_t)3U,
    (ಗಾತ್ರ_t)4U);
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_ಸುತ್ತು(
  Eurydice_arr_a3 *re,
  ಗಾತ್ರ_t index,
  int32_t zeta1
)
{
  libcrux_ml_dsa_simd_portable_invntt_simd_unit_invert_ntt_at_layer_2(&re->ದತ್ತಾಂಶ[index], zeta1);
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)0U, -2797779);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)1U, 2071892);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)2U, -2556880);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)3U, 3900724);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)4U, 3881043);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)5U, 954230);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)6U, 531354);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)7U, 811944);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)8U, 3699596);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)9U, -1600420);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)10U, -2140649);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)11U, 3507263);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)12U, -3821735);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)13U, 3505694);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)14U, -1643818);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)15U, -1699267);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)16U, -539299);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)17U, 2348700);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)18U, -300467);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)19U, 3539968);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)20U, -2867647);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)21U, 3574422);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)22U, -3043716);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)23U, -3861115);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)24U, 3915439);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)25U, -2537516);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)26U, -3592148);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)27U, -1661693);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)28U, 3530437);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)29U, 3077325);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)30U, 95776);
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_2_ಸುತ್ತು(re, (ಗಾತ್ರ_t)31U, 2706023);
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.invntt.outer_3_plus
with const generics
- OFFSET= 0
- STEP_BY= 1
- ZETA= 280005
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_30(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)0U + (ಗಾತ್ರ_t)1U; i++)
  {
    ಗಾತ್ರ_t j = i;
    Eurydice_arr_4d rej = re->ದತ್ತಾಂಶ[j];
    Eurydice_arr_4d rejs = re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_ಕೂಡಿಸು(&re->ದತ್ತಾಂಶ[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_ಕಳೆ(&re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->ದತ್ತಾಂಶ[j +
        (ಗಾತ್ರ_t)1U],
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_25(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)2U; i < (ಗಾತ್ರ_t)2U + (ಗಾತ್ರ_t)1U; i++)
  {
    ಗಾತ್ರ_t j = i;
    Eurydice_arr_4d rej = re->ದತ್ತಾಂಶ[j];
    Eurydice_arr_4d rejs = re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_ಕೂಡಿಸು(&re->ದತ್ತಾಂಶ[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_ಕಳೆ(&re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->ದತ್ತಾಂಶ[j +
        (ಗಾತ್ರ_t)1U],
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_43(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)4U; i < (ಗಾತ್ರ_t)4U + (ಗಾತ್ರ_t)1U; i++)
  {
    ಗಾತ್ರ_t j = i;
    Eurydice_arr_4d rej = re->ದತ್ತಾಂಶ[j];
    Eurydice_arr_4d rejs = re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_ಕೂಡಿಸು(&re->ದತ್ತಾಂಶ[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_ಕಳೆ(&re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->ದತ್ತಾಂಶ[j +
        (ಗಾತ್ರ_t)1U],
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_f4(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)6U; i < (ಗಾತ್ರ_t)6U + (ಗಾತ್ರ_t)1U; i++)
  {
    ಗಾತ್ರ_t j = i;
    Eurydice_arr_4d rej = re->ದತ್ತಾಂಶ[j];
    Eurydice_arr_4d rejs = re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_ಕೂಡಿಸು(&re->ದತ್ತಾಂಶ[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_ಕಳೆ(&re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->ದತ್ತಾಂಶ[j +
        (ಗಾತ್ರ_t)1U],
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_82(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)8U; i < (ಗಾತ್ರ_t)8U + (ಗಾತ್ರ_t)1U; i++)
  {
    ಗಾತ್ರ_t j = i;
    Eurydice_arr_4d rej = re->ದತ್ತಾಂಶ[j];
    Eurydice_arr_4d rejs = re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_ಕೂಡಿಸು(&re->ದತ್ತಾಂಶ[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_ಕಳೆ(&re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->ದತ್ತಾಂಶ[j +
        (ಗಾತ್ರ_t)1U],
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_1d(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)10U; i < (ಗಾತ್ರ_t)10U + (ಗಾತ್ರ_t)1U; i++)
  {
    ಗಾತ್ರ_t j = i;
    Eurydice_arr_4d rej = re->ದತ್ತಾಂಶ[j];
    Eurydice_arr_4d rejs = re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_ಕೂಡಿಸು(&re->ದತ್ತಾಂಶ[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_ಕಳೆ(&re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->ದತ್ತಾಂಶ[j +
        (ಗಾತ್ರ_t)1U],
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_ea(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)12U; i < (ಗಾತ್ರ_t)12U + (ಗಾತ್ರ_t)1U; i++)
  {
    ಗಾತ್ರ_t j = i;
    Eurydice_arr_4d rej = re->ದತ್ತಾಂಶ[j];
    Eurydice_arr_4d rejs = re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_ಕೂಡಿಸು(&re->ದತ್ತಾಂಶ[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_ಕಳೆ(&re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->ದತ್ತಾಂಶ[j +
        (ಗಾತ್ರ_t)1U],
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_d8(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)14U; i < (ಗಾತ್ರ_t)14U + (ಗಾತ್ರ_t)1U; i++)
  {
    ಗಾತ್ರ_t j = i;
    Eurydice_arr_4d rej = re->ದತ್ತಾಂಶ[j];
    Eurydice_arr_4d rejs = re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_ಕೂಡಿಸು(&re->ದತ್ತಾಂಶ[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_ಕಳೆ(&re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->ದತ್ತಾಂಶ[j +
        (ಗಾತ್ರ_t)1U],
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_42(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)16U; i < (ಗಾತ್ರ_t)16U + (ಗಾತ್ರ_t)1U; i++)
  {
    ಗಾತ್ರ_t j = i;
    Eurydice_arr_4d rej = re->ದತ್ತಾಂಶ[j];
    Eurydice_arr_4d rejs = re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_ಕೂಡಿಸು(&re->ದತ್ತಾಂಶ[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_ಕಳೆ(&re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->ದತ್ತಾಂಶ[j +
        (ಗಾತ್ರ_t)1U],
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_60(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)18U; i < (ಗಾತ್ರ_t)18U + (ಗಾತ್ರ_t)1U; i++)
  {
    ಗಾತ್ರ_t j = i;
    Eurydice_arr_4d rej = re->ದತ್ತಾಂಶ[j];
    Eurydice_arr_4d rejs = re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_ಕೂಡಿಸು(&re->ದತ್ತಾಂಶ[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_ಕಳೆ(&re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->ದತ್ತಾಂಶ[j +
        (ಗಾತ್ರ_t)1U],
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_61(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)20U; i < (ಗಾತ್ರ_t)20U + (ಗಾತ್ರ_t)1U; i++)
  {
    ಗಾತ್ರ_t j = i;
    Eurydice_arr_4d rej = re->ದತ್ತಾಂಶ[j];
    Eurydice_arr_4d rejs = re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_ಕೂಡಿಸು(&re->ದತ್ತಾಂಶ[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_ಕಳೆ(&re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->ದತ್ತಾಂಶ[j +
        (ಗಾತ್ರ_t)1U],
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_29(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)22U; i < (ಗಾತ್ರ_t)22U + (ಗಾತ್ರ_t)1U; i++)
  {
    ಗಾತ್ರ_t j = i;
    Eurydice_arr_4d rej = re->ದತ್ತಾಂಶ[j];
    Eurydice_arr_4d rejs = re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_ಕೂಡಿಸು(&re->ದತ್ತಾಂಶ[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_ಕಳೆ(&re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->ದತ್ತಾಂಶ[j +
        (ಗಾತ್ರ_t)1U],
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_fe(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)24U; i < (ಗಾತ್ರ_t)24U + (ಗಾತ್ರ_t)1U; i++)
  {
    ಗಾತ್ರ_t j = i;
    Eurydice_arr_4d rej = re->ದತ್ತಾಂಶ[j];
    Eurydice_arr_4d rejs = re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_ಕೂಡಿಸು(&re->ದತ್ತಾಂಶ[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_ಕಳೆ(&re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->ದತ್ತಾಂಶ[j +
        (ಗಾತ್ರ_t)1U],
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_9d(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)26U; i < (ಗಾತ್ರ_t)26U + (ಗಾತ್ರ_t)1U; i++)
  {
    ಗಾತ್ರ_t j = i;
    Eurydice_arr_4d rej = re->ದತ್ತಾಂಶ[j];
    Eurydice_arr_4d rejs = re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_ಕೂಡಿಸು(&re->ದತ್ತಾಂಶ[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_ಕಳೆ(&re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->ದತ್ತಾಂಶ[j +
        (ಗಾತ್ರ_t)1U],
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_38(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)28U; i < (ಗಾತ್ರ_t)28U + (ಗಾತ್ರ_t)1U; i++)
  {
    ಗಾತ್ರ_t j = i;
    Eurydice_arr_4d rej = re->ದತ್ತಾಂಶ[j];
    Eurydice_arr_4d rejs = re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_ಕೂಡಿಸು(&re->ದತ್ತಾಂಶ[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_ಕಳೆ(&re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->ದತ್ತಾಂಶ[j +
        (ಗಾತ್ರ_t)1U],
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_5f(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)30U; i < (ಗಾತ್ರ_t)30U + (ಗಾತ್ರ_t)1U; i++)
  {
    ಗಾತ್ರ_t j = i;
    Eurydice_arr_4d rej = re->ದತ್ತಾಂಶ[j];
    Eurydice_arr_4d rejs = re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)1U];
    libcrux_ml_dsa_simd_portable_arithmetic_ಕೂಡಿಸು(&re->ದತ್ತಾಂಶ[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_ಕಳೆ(&re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)1U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->ದತ್ತಾಂಶ[j +
        (ಗಾತ್ರ_t)1U],
      2725464);
  }
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_300(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)0U + (ಗಾತ್ರ_t)2U; i++)
  {
    ಗಾತ್ರ_t j = i;
    Eurydice_arr_4d rej = re->ದತ್ತಾಂಶ[j];
    Eurydice_arr_4d rejs = re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)2U];
    libcrux_ml_dsa_simd_portable_arithmetic_ಕೂಡಿಸು(&re->ದತ್ತಾಂಶ[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_ಕಳೆ(&re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)2U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->ದತ್ತಾಂಶ[j +
        (ಗಾತ್ರ_t)2U],
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_430(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)4U; i < (ಗಾತ್ರ_t)4U + (ಗಾತ್ರ_t)2U; i++)
  {
    ಗಾತ್ರ_t j = i;
    Eurydice_arr_4d rej = re->ದತ್ತಾಂಶ[j];
    Eurydice_arr_4d rejs = re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)2U];
    libcrux_ml_dsa_simd_portable_arithmetic_ಕೂಡಿಸು(&re->ದತ್ತಾಂಶ[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_ಕಳೆ(&re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)2U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->ದತ್ತಾಂಶ[j +
        (ಗಾತ್ರ_t)2U],
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_820(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)8U; i < (ಗಾತ್ರ_t)8U + (ಗಾತ್ರ_t)2U; i++)
  {
    ಗಾತ್ರ_t j = i;
    Eurydice_arr_4d rej = re->ದತ್ತಾಂಶ[j];
    Eurydice_arr_4d rejs = re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)2U];
    libcrux_ml_dsa_simd_portable_arithmetic_ಕೂಡಿಸು(&re->ದತ್ತಾಂಶ[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_ಕಳೆ(&re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)2U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->ದತ್ತಾಂಶ[j +
        (ಗಾತ್ರ_t)2U],
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_ea0(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)12U; i < (ಗಾತ್ರ_t)12U + (ಗಾತ್ರ_t)2U; i++)
  {
    ಗಾತ್ರ_t j = i;
    Eurydice_arr_4d rej = re->ದತ್ತಾಂಶ[j];
    Eurydice_arr_4d rejs = re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)2U];
    libcrux_ml_dsa_simd_portable_arithmetic_ಕೂಡಿಸು(&re->ದತ್ತಾಂಶ[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_ಕಳೆ(&re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)2U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->ದತ್ತಾಂಶ[j +
        (ಗಾತ್ರ_t)2U],
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_420(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)16U; i < (ಗಾತ್ರ_t)16U + (ಗಾತ್ರ_t)2U; i++)
  {
    ಗಾತ್ರ_t j = i;
    Eurydice_arr_4d rej = re->ದತ್ತಾಂಶ[j];
    Eurydice_arr_4d rejs = re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)2U];
    libcrux_ml_dsa_simd_portable_arithmetic_ಕೂಡಿಸು(&re->ದತ್ತಾಂಶ[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_ಕಳೆ(&re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)2U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->ದತ್ತಾಂಶ[j +
        (ಗಾತ್ರ_t)2U],
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_610(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)20U; i < (ಗಾತ್ರ_t)20U + (ಗಾತ್ರ_t)2U; i++)
  {
    ಗಾತ್ರ_t j = i;
    Eurydice_arr_4d rej = re->ದತ್ತಾಂಶ[j];
    Eurydice_arr_4d rejs = re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)2U];
    libcrux_ml_dsa_simd_portable_arithmetic_ಕೂಡಿಸು(&re->ದತ್ತಾಂಶ[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_ಕಳೆ(&re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)2U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->ದತ್ತಾಂಶ[j +
        (ಗಾತ್ರ_t)2U],
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_fe0(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)24U; i < (ಗಾತ್ರ_t)24U + (ಗಾತ್ರ_t)2U; i++)
  {
    ಗಾತ್ರ_t j = i;
    Eurydice_arr_4d rej = re->ದತ್ತಾಂಶ[j];
    Eurydice_arr_4d rejs = re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)2U];
    libcrux_ml_dsa_simd_portable_arithmetic_ಕೂಡಿಸು(&re->ದತ್ತಾಂಶ[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_ಕಳೆ(&re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)2U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->ದತ್ತಾಂಶ[j +
        (ಗಾತ್ರ_t)2U],
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_380(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)28U; i < (ಗಾತ್ರ_t)28U + (ಗಾತ್ರ_t)2U; i++)
  {
    ಗಾತ್ರ_t j = i;
    Eurydice_arr_4d rej = re->ದತ್ತಾಂಶ[j];
    Eurydice_arr_4d rejs = re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)2U];
    libcrux_ml_dsa_simd_portable_arithmetic_ಕೂಡಿಸು(&re->ದತ್ತಾಂಶ[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_ಕಳೆ(&re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)2U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->ದತ್ತಾಂಶ[j +
        (ಗಾತ್ರ_t)2U],
      1826347);
  }
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_301(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)0U + (ಗಾತ್ರ_t)4U; i++)
  {
    ಗಾತ್ರ_t j = i;
    Eurydice_arr_4d rej = re->ದತ್ತಾಂಶ[j];
    Eurydice_arr_4d rejs = re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)4U];
    libcrux_ml_dsa_simd_portable_arithmetic_ಕೂಡಿಸು(&re->ದತ್ತಾಂಶ[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_ಕಳೆ(&re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)4U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->ದತ್ತಾಂಶ[j +
        (ಗಾತ್ರ_t)4U],
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_821(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)8U; i < (ಗಾತ್ರ_t)8U + (ಗಾತ್ರ_t)4U; i++)
  {
    ಗಾತ್ರ_t j = i;
    Eurydice_arr_4d rej = re->ದತ್ತಾಂಶ[j];
    Eurydice_arr_4d rejs = re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)4U];
    libcrux_ml_dsa_simd_portable_arithmetic_ಕೂಡಿಸು(&re->ದತ್ತಾಂಶ[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_ಕಳೆ(&re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)4U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->ದತ್ತಾಂಶ[j +
        (ಗಾತ್ರ_t)4U],
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_421(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)16U; i < (ಗಾತ್ರ_t)16U + (ಗಾತ್ರ_t)4U; i++)
  {
    ಗಾತ್ರ_t j = i;
    Eurydice_arr_4d rej = re->ದತ್ತಾಂಶ[j];
    Eurydice_arr_4d rejs = re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)4U];
    libcrux_ml_dsa_simd_portable_arithmetic_ಕೂಡಿಸು(&re->ದತ್ತಾಂಶ[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_ಕಳೆ(&re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)4U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->ದತ್ತಾಂಶ[j +
        (ಗಾತ್ರ_t)4U],
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_fe1(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)24U; i < (ಗಾತ್ರ_t)24U + (ಗಾತ್ರ_t)4U; i++)
  {
    ಗಾತ್ರ_t j = i;
    Eurydice_arr_4d rej = re->ದತ್ತಾಂಶ[j];
    Eurydice_arr_4d rejs = re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)4U];
    libcrux_ml_dsa_simd_portable_arithmetic_ಕೂಡಿಸು(&re->ದತ್ತಾಂಶ[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_ಕಳೆ(&re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)4U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->ದತ್ತಾಂಶ[j +
        (ಗಾತ್ರ_t)4U],
      237124);
  }
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_302(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)0U + (ಗಾತ್ರ_t)8U; i++)
  {
    ಗಾತ್ರ_t j = i;
    Eurydice_arr_4d rej = re->ದತ್ತಾಂಶ[j];
    Eurydice_arr_4d rejs = re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)8U];
    libcrux_ml_dsa_simd_portable_arithmetic_ಕೂಡಿಸು(&re->ದತ್ತಾಂಶ[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_ಕಳೆ(&re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)8U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->ದತ್ತಾಂಶ[j +
        (ಗಾತ್ರ_t)8U],
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_422(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)16U; i < (ಗಾತ್ರ_t)16U + (ಗಾತ್ರ_t)8U; i++)
  {
    ಗಾತ್ರ_t j = i;
    Eurydice_arr_4d rej = re->ದತ್ತಾಂಶ[j];
    Eurydice_arr_4d rejs = re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)8U];
    libcrux_ml_dsa_simd_portable_arithmetic_ಕೂಡಿಸು(&re->ದತ್ತಾಂಶ[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_ಕಳೆ(&re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)8U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->ದತ್ತಾಂಶ[j +
        (ಗಾತ್ರ_t)8U],
      -2608894);
  }
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_303(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)0U + (ಗಾತ್ರ_t)16U; i++)
  {
    ಗಾತ್ರ_t j = i;
    Eurydice_arr_4d rej = re->ದತ್ತಾಂಶ[j];
    Eurydice_arr_4d rejs = re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)16U];
    libcrux_ml_dsa_simd_portable_arithmetic_ಕೂಡಿಸು(&re->ದತ್ತಾಂಶ[j], &rejs);
    libcrux_ml_dsa_simd_portable_arithmetic_ಕಳೆ(&re->ದತ್ತಾಂಶ[j + (ಗಾತ್ರ_t)16U], &rej);
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->ದತ್ತಾಂಶ[j +
        (ಗಾತ್ರ_t)16U],
      25847);
  }
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_invntt_invert_ntt_at_layer_7(Eurydice_arr_a3 *re)
{
  libcrux_ml_dsa_simd_portable_invntt_outer_3_plus_303(re);
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
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
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)32U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    libcrux_ml_dsa_simd_portable_arithmetic_montgomery_multiply_by_constant(&re->ದತ್ತಾಂಶ[i0], 41978);
  }
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_invert_ntt_montgomery_65(Eurydice_arr_a3 *simd_units)
{
  libcrux_ml_dsa_simd_portable_invntt_invert_ntt_montgomery(simd_units);
}

/**
This function found in impl {libcrux_ml_dsa::simd::traits::Operations for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_barrett_reduce_simd_unit_65(Eurydice_arr_4d *simd_unit)
{
  libcrux_ml_dsa_simd_portable_arithmetic_barrett_reduce_simd_unit(simd_unit);
}

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_ERROR_RING_ELEMENT_ಗಾತ್ರ (libcrux_ml_dsa_constants_error_ring_element_ಗಾತ್ರ(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ಬಿಟ್ಟುಗಳು_ಪ್ರತಿ_ERROR_COEFFICIENT))

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_COMMITMENT_RING_ELEMENT_ಗಾತ್ರ (libcrux_ml_dsa_constants_commitment_ring_element_ಗಾತ್ರ(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ಬಿಟ್ಟುಗಳು_ಪ್ರತಿ_COMMITMENT_COEFFICIENT))

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_BETA (libcrux_ml_dsa_constants_beta(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ONES_ಒಳ_VERIFIER_CHALLENGE, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ETA))

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_GAMMA1_RING_ELEMENT_ಗಾತ್ರ (libcrux_ml_dsa_constants_gamma1_ring_element_ಗಾತ್ರ(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ಬಿಟ್ಟುಗಳು_ಪ್ರತಿ_GAMMA1_COEFFICIENT))

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_VERIFICATION_ಕೀಲಿ_ಗಾತ್ರ (libcrux_ml_dsa_constants_verification_ಕೀಲಿ_ಗಾತ್ರ(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A))

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_SIGNATURE_ಗಾತ್ರ (libcrux_ml_dsa_constants_signature_ಗಾತ್ರ(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_ಒಳ_A, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_MAX_ONES_ಒಳ_HINT, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COMMITMENT_HASH_ಗಾತ್ರ, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ಬಿಟ್ಟುಗಳು_ಪ್ರತಿ_GAMMA1_COEFFICIENT))

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_ERROR_RING_ELEMENT_ಗಾತ್ರ (libcrux_ml_dsa_constants_error_ring_element_ಗಾತ್ರ(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ಬಿಟ್ಟುಗಳು_ಪ್ರತಿ_ERROR_COEFFICIENT))

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_COMMITMENT_RING_ELEMENT_ಗಾತ್ರ (libcrux_ml_dsa_constants_commitment_ring_element_ಗಾತ್ರ(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ಬಿಟ್ಟುಗಳು_ಪ್ರತಿ_COMMITMENT_COEFFICIENT))

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_BETA (libcrux_ml_dsa_constants_beta(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ONES_ಒಳ_VERIFIER_CHALLENGE, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ETA))

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_GAMMA1_RING_ELEMENT_ಗಾತ್ರ (libcrux_ml_dsa_constants_gamma1_ring_element_ಗಾತ್ರ(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ಬಿಟ್ಟುಗಳು_ಪ್ರತಿ_GAMMA1_COEFFICIENT))

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_VERIFICATION_ಕೀಲಿ_ಗಾತ್ರ (libcrux_ml_dsa_constants_verification_ಕೀಲಿ_ಗಾತ್ರ(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A))

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_SIGNATURE_ಗಾತ್ರ (libcrux_ml_dsa_constants_signature_ಗಾತ್ರ(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_ಒಳ_A, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_MAX_ONES_ಒಳ_HINT, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COMMITMENT_HASH_ಗಾತ್ರ, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ಬಿಟ್ಟುಗಳು_ಪ್ರತಿ_GAMMA1_COEFFICIENT))

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_COMMITMENT_ಸದಿಶ_ಗಾತ್ರ (libcrux_ml_dsa_constants_commitment_ಸದಿಶ_ಗಾತ್ರ(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ಬಿಟ್ಟುಗಳು_ಪ್ರತಿ_COMMITMENT_COEFFICIENT, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A))

/**
A monomorphic instance of libcrux_ml_dsa.types.MLDSASigningKey
with const generics
- $2560size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ Eurydice_arr_10 libcrux_ml_dsa_types_MLDSASigning_ಕೀಲಿ_11;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ Eurydice_arr_10 libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_MLDSA44_Signing_ಕೀಲಿ;

/**
A monomorphic instance of libcrux_ml_dsa.types.MLDSAVerificationKey
with const generics
- $1312size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ Eurydice_arr_02 libcrux_ml_dsa_types_MLDSAVerification_ಕೀಲಿ_1d;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ Eurydice_arr_02 libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_MLDSA44_Verification_ಕೀಲಿ;

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_ಅಡ್ಡಸಾಲು_ಸ್ತಂಭ (LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A + LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_ಒಳ_A)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_ಅಡ್ಡಸಾಲು_X_ಸ್ತಂಭ (LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A * LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_ಒಳ_A)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_SIGNING_ಕೀಲಿ_ಗಾತ್ರ (libcrux_ml_dsa_constants_signing_ಕೀಲಿ_ಗಾತ್ರ(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_ಒಳ_A, LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_ERROR_RING_ELEMENT_ಗಾತ್ರ))

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_COMMITMENT_ಸದಿಶ_ಗಾತ್ರ (libcrux_ml_dsa_constants_commitment_ಸದಿಶ_ಗಾತ್ರ(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ಬಿಟ್ಟುಗಳು_ಪ್ರತಿ_COMMITMENT_COEFFICIENT, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A))

/**
A monomorphic instance of libcrux_ml_dsa.types.MLDSASigningKey
with const generics
- $4032size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ Eurydice_arr_24 libcrux_ml_dsa_types_MLDSASigning_ಕೀಲಿ_8e;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ Eurydice_arr_24 libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_MLDSA65_Signing_ಕೀಲಿ;

/**
A monomorphic instance of libcrux_ml_dsa.types.MLDSAVerificationKey
with const generics
- $1952size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ Eurydice_arr_29 libcrux_ml_dsa_types_MLDSAVerification_ಕೀಲಿ_c8;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ Eurydice_arr_29 libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_MLDSA65_Verification_ಕೀಲಿ;

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_ಅಡ್ಡಸಾಲು_ಸ್ತಂಭ (LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A + LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_ಒಳ_A)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_ಅಡ್ಡಸಾಲು_X_ಸ್ತಂಭ (LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A * LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_ಒಳ_A)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_SIGNING_ಕೀಲಿ_ಗಾತ್ರ (libcrux_ml_dsa_constants_signing_ಕೀಲಿ_ಗಾತ್ರ(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_ಒಳ_A, LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_ERROR_RING_ELEMENT_ಗಾತ್ರ))

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_COMMITMENT_ಸದಿಶ_ಗಾತ್ರ (libcrux_ml_dsa_constants_commitment_ಸದಿಶ_ಗಾತ್ರ(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ಬಿಟ್ಟುಗಳು_ಪ್ರತಿ_COMMITMENT_COEFFICIENT, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A))

/**
A monomorphic instance of libcrux_ml_dsa.types.MLDSASigningKey
with const generics
- $4896size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ Eurydice_arr_e2 libcrux_ml_dsa_types_MLDSASigning_ಕೀಲಿ_b8;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ Eurydice_arr_e2 libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_MLDSA87_Signing_ಕೀಲಿ;

/**
A monomorphic instance of libcrux_ml_dsa.types.MLDSAVerificationKey
with const generics
- $2592size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ Eurydice_arr_43 libcrux_ml_dsa_types_MLDSAVerification_ಕೀಲಿ_e9;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ Eurydice_arr_43 libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_MLDSA87_Verification_ಕೀಲಿ;

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_ಅಡ್ಡಸಾಲು_ಸ್ತಂಭ (LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A + LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_ಒಳ_A)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_ಅಡ್ಡಸಾಲು_X_ಸ್ತಂಭ (LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A * LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_ಒಳ_A)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_SIGNING_ಕೀಲಿ_ಗಾತ್ರ (libcrux_ml_dsa_constants_signing_ಕೀಲಿ_ಗಾತ್ರ(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A, LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_ಒಳ_A, LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_ERROR_RING_ELEMENT_ಗಾತ್ರ))

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_PRE_HASH_PRE_HASH_OID_LEN ((ಗಾತ್ರ_t)11U)

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ Eurydice_arr_c9 libcrux_ml_dsa_pre_hash_PreHashOID;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_a8 libcrux_ml_dsa_pre_hash_Pre_Hash_ಫಲಿತಾಂಶ;

/**
This function found in impl {core::convert::From<libcrux_ml_dsa::pre_hash::DomainSeparationError> for libcrux_ml_dsa::types::SigningError}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ libcrux_ml_dsa_types_SigningError
libcrux_ml_dsa_pre_hash_from_96(libcrux_ml_dsa_pre_hash_DomainSeparationError e)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_dsa_types_SigningError_ContextTooLongError;
}

/**
This function found in impl {core::convert::From<libcrux_ml_dsa::pre_hash::DomainSeparationError> for libcrux_ml_dsa::types::VerificationError}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ libcrux_ml_dsa_types_VerificationError
libcrux_ml_dsa_pre_hash_from_bf(libcrux_ml_dsa_pre_hash_DomainSeparationError e)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_dsa_types_VerificationError_VerificationContextTooLongError;
}

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_SIMD_PORTABLE_INVNTT_INVERT_NTT_AT_LAYER_3_ಹೆಜ್ಜೆ ((ಗಾತ್ರ_t)8U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_SIMD_PORTABLE_INVNTT_INVERT_NTT_AT_LAYER_3_ಹೆಜ್ಜೆ_BY ((ಗಾತ್ರ_t)1U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_SIMD_PORTABLE_INVNTT_INVERT_NTT_AT_LAYER_4_ಹೆಜ್ಜೆ ((ಗಾತ್ರ_t)16U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_SIMD_PORTABLE_INVNTT_INVERT_NTT_AT_LAYER_4_ಹೆಜ್ಜೆ_BY ((ಗಾತ್ರ_t)2U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_SIMD_PORTABLE_INVNTT_INVERT_NTT_AT_LAYER_5_ಹೆಜ್ಜೆ ((ಗಾತ್ರ_t)32U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_SIMD_PORTABLE_INVNTT_INVERT_NTT_AT_LAYER_5_ಹೆಜ್ಜೆ_BY ((ಗಾತ್ರ_t)4U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_SIMD_PORTABLE_INVNTT_INVERT_NTT_AT_LAYER_6_ಹೆಜ್ಜೆ ((ಗಾತ್ರ_t)64U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_SIMD_PORTABLE_INVNTT_INVERT_NTT_AT_LAYER_6_ಹೆಜ್ಜೆ_BY ((ಗಾತ್ರ_t)8U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_SIMD_PORTABLE_INVNTT_INVERT_NTT_AT_LAYER_7_ಹೆಜ್ಜೆ ((ಗಾತ್ರ_t)128U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_SIMD_PORTABLE_INVNTT_INVERT_NTT_AT_LAYER_7_ಹೆಜ್ಜೆ_BY ((ಗಾತ್ರ_t)16U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_SIMD_PORTABLE_NTT_NTT_AT_LAYER_3_ಹೆಜ್ಜೆ ((ಗಾತ್ರ_t)8U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_SIMD_PORTABLE_NTT_NTT_AT_LAYER_3_ಹೆಜ್ಜೆ_BY ((ಗಾತ್ರ_t)1U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_SIMD_PORTABLE_NTT_NTT_AT_LAYER_4_ಹೆಜ್ಜೆ ((ಗಾತ್ರ_t)16U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_SIMD_PORTABLE_NTT_NTT_AT_LAYER_4_ಹೆಜ್ಜೆ_BY ((ಗಾತ್ರ_t)2U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_SIMD_PORTABLE_NTT_NTT_AT_LAYER_5_ಹೆಜ್ಜೆ ((ಗಾತ್ರ_t)32U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_SIMD_PORTABLE_NTT_NTT_AT_LAYER_5_ಹೆಜ್ಜೆ_BY ((ಗಾತ್ರ_t)4U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_SIMD_PORTABLE_NTT_NTT_AT_LAYER_6_ಹೆಜ್ಜೆ ((ಗಾತ್ರ_t)64U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_SIMD_PORTABLE_NTT_NTT_AT_LAYER_6_ಹೆಜ್ಜೆ_BY ((ಗಾತ್ರ_t)8U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_SIMD_PORTABLE_NTT_NTT_AT_LAYER_7_ಹೆಜ್ಜೆ ((ಗಾತ್ರ_t)128U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_DSA_SIMD_PORTABLE_NTT_NTT_AT_LAYER_7_ಹೆಜ್ಜೆ_BY ((ಗಾತ್ರ_t)16U)

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ int32_t libcrux_ml_dsa_simd_portable_ಸದಿಶ_type_ಕ್ಷೇತ್ರ_Element;

/**
This function found in impl {core::clone::Clone for libcrux_ml_dsa::simd::portable::vector_type::Coefficients}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_4d
libcrux_ml_dsa_simd_portable_ಸದಿಶ_type_clone_a5(ಸ್ಥಿರಾಂಕ Eurydice_arr_4d *self)
{
  ಹಿಂತಿರುಗಿ self[0U];
}

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ int32_t libcrux_ml_dsa_simd_traits_ಕ್ಷೇತ್ರ_Element_Times_Montgomery_R;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ Eurydice_arr_93 libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_MLDSA87Signature;

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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಸ್ಥಿರಾಂಕ
Eurydice_arr_93
*libcrux_ml_dsa_types_as_ref_c5_f1(ಸ್ಥಿರಾಂಕ Eurydice_arr_93 *self)
{
  ಹಿಂತಿರುಗಿ self;
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಸ್ಥಿರಾಂಕ
Eurydice_arr_43
*libcrux_ml_dsa_types_as_ref_7f_c6(ಸ್ಥಿರಾಂಕ Eurydice_arr_43 *self)
{
  ಹಿಂತಿರುಗಿ self;
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಸ್ಥಿರಾಂಕ
Eurydice_arr_e2
*libcrux_ml_dsa_types_as_ref_9b_72(ಸ್ಥಿರಾಂಕ Eurydice_arr_e2 *self)
{
  ಹಿಂತಿರುಗಿ self;
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_43 libcrux_ml_dsa_types_new_7f_c6(Eurydice_arr_43 ಮೌಲ್ಯ)
{
  ಹಿಂತಿರುಗಿ ಮೌಲ್ಯ;
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_e2 libcrux_ml_dsa_types_new_9b_72(Eurydice_arr_e2 ಮೌಲ್ಯ)
{
  ಹಿಂತಿರುಗಿ ಮೌಲ್ಯ;
}

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ Eurydice_arr_85 libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_MLDSA44Signature;

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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಸ್ಥಿರಾಂಕ
Eurydice_arr_85
*libcrux_ml_dsa_types_as_ref_c5_37(ಸ್ಥಿರಾಂಕ Eurydice_arr_85 *self)
{
  ಹಿಂತಿರುಗಿ self;
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಸ್ಥಿರಾಂಕ
Eurydice_arr_02
*libcrux_ml_dsa_types_as_ref_7f_7d(ಸ್ಥಿರಾಂಕ Eurydice_arr_02 *self)
{
  ಹಿಂತಿರುಗಿ self;
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಸ್ಥಿರಾಂಕ
Eurydice_arr_10
*libcrux_ml_dsa_types_as_ref_9b_ab(ಸ್ಥಿರಾಂಕ Eurydice_arr_10 *self)
{
  ಹಿಂತಿರುಗಿ self;
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_02 libcrux_ml_dsa_types_new_7f_7d(Eurydice_arr_02 ಮೌಲ್ಯ)
{
  ಹಿಂತಿರುಗಿ ಮೌಲ್ಯ;
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_10 libcrux_ml_dsa_types_new_9b_ab(Eurydice_arr_10 ಮೌಲ್ಯ)
{
  ಹಿಂತಿರುಗಿ ಮೌಲ್ಯ;
}

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ Eurydice_arr_0c libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_MLDSA65Signature;

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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಸ್ಥಿರಾಂಕ
Eurydice_arr_0c
*libcrux_ml_dsa_types_as_ref_c5_5c(ಸ್ಥಿರಾಂಕ Eurydice_arr_0c *self)
{
  ಹಿಂತಿರುಗಿ self;
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಸ್ಥಿರಾಂಕ
Eurydice_arr_29
*libcrux_ml_dsa_types_as_ref_7f_a2(ಸ್ಥಿರಾಂಕ Eurydice_arr_29 *self)
{
  ಹಿಂತಿರುಗಿ self;
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಸ್ಥಿರಾಂಕ
Eurydice_arr_24
*libcrux_ml_dsa_types_as_ref_9b_e5(ಸ್ಥಿರಾಂಕ Eurydice_arr_24 *self)
{
  ಹಿಂತಿರುಗಿ self;
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_29 libcrux_ml_dsa_types_new_7f_a2(Eurydice_arr_29 ಮೌಲ್ಯ)
{
  ಹಿಂತಿರುಗಿ ಮೌಲ್ಯ;
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_24 libcrux_ml_dsa_types_new_9b_e5(Eurydice_arr_24 ಮೌಲ್ಯ)
{
  ಹಿಂತಿರುಗಿ ಮೌಲ್ಯ;
}

/**
A monomorphic instance of core.result.Result
with types libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_MLDSA87Signature, libcrux_ml_dsa_types_SigningError

*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_8b_s
{
  core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_57_ಟ್ಯಾಗುಗಳು ಟ್ಯಾಗ್;
  ಒಕ್ಕೂಟ {
    Eurydice_arr_93 case_Ok;
    libcrux_ml_dsa_types_SigningError case_Err;
  }
  val;
}
core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_8b;

/**
A monomorphic instance of libcrux_ml_dsa.polynomial.PolynomialRingElement
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients

*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ Eurydice_arr_a3 libcrux_ml_dsa_polynomial_PolynomialRingElement_e8;

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8
with const generics
- $7size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_bb_s { Eurydice_arr_a3 ದತ್ತಾಂಶ[7U]; } Eurydice_arr_bb;

/**
A monomorphic instance of core.option.Option
with types Eurydice_arr_bb

*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ core_option_Option_2d_s
{
  core_option_Option_45_ಟ್ಯಾಗುಗಳು ಟ್ಯಾಗ್;
  Eurydice_arr_bb f0;
}
core_option_Option_2d;

/**
A monomorphic instance of Eurydice.dst_ref_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8, size_t

*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_dst_ref_shared_44_s
{
  ಸ್ಥಿರಾಂಕ Eurydice_arr_a3 *ptr;
  ಗಾತ್ರ_t meta;
}
Eurydice_dst_ref_shared_44;

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8
with const generics
- $56size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_0f_s { Eurydice_arr_a3 ದತ್ತಾಂಶ[56U]; } Eurydice_arr_0f;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 56
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_dst_ref_shared_44
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_208(ಸ್ಥಿರಾಂಕ Eurydice_arr_0f *a)
{
  Eurydice_dst_ref_shared_44 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)56U;
  ಹಿಂತಿರುಗಿ lit;
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_93 libcrux_ml_dsa_types_zero_c5_f1(ಶೂನ್ಯ)
{
  ಹಿಂತಿರುಗಿ (KRML_CLITERAL(Eurydice_arr_93){ .ದತ್ತಾಂಶ = { 0U } });
}

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8
with const generics
- $8size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_8f_s { Eurydice_arr_a3 ದತ್ತಾಂಶ[8U]; } Eurydice_arr_8f;

/**
 Declassify secret memory.

 No-op if `valgrind_ct_test` cfg is not enabled.
*/
/**
A monomorphic instance of libcrux_secrets.mem_requests.ct_declassify
with types Eurydice_arr libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients[[$8size_t]]

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_secrets_mem_ವಿನಂತಿಗಳು_ct_declassify_6a(ಸ್ಥಿರಾಂಕ Eurydice_arr_8f *val)
{

}

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8
with const generics
- $15size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_92_s { Eurydice_arr_a3 ದತ್ತಾಂಶ[15U]; } Eurydice_arr_92;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 15
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_dst_ref_shared_44
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_207(ಸ್ಥಿರಾಂಕ Eurydice_arr_92 *a)
{
  Eurydice_dst_ref_shared_44 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)15U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 7
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_dst_ref_shared_44
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_206(ಸ್ಥಿರಾಂಕ Eurydice_arr_bb *a)
{
  Eurydice_dst_ref_shared_44 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)7U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients, core_ops_range_Range size_t, Eurydice_derefed_slice libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 15
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_dst_ref_shared_44
Eurydice_array_ಗಮ್ಯ_subslice_shared_251(ಸ್ಥಿರಾಂಕ Eurydice_arr_92 *a, core_ops_range_Range_87 r)
{
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(Eurydice_dst_ref_shared_44){ .ptr = a->ದತ್ತಾಂಶ + r.ಆರಂಭ, .meta = r.ಕೊನೆ - r.ಆರಂಭ }
    );
}

/**
A monomorphic instance of Eurydice.dst_ref_mut
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8, size_t

*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_dst_ref_mut_44_s
{
  Eurydice_arr_a3 *ptr;
  ಗಾತ್ರ_t meta;
}
Eurydice_dst_ref_mut_44;

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 7
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_dst_ref_mut_44 Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_208(Eurydice_arr_bb *a)
{
  Eurydice_dst_ref_mut_44 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)7U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 56
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_dst_ref_mut_44 Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_207(Eurydice_arr_0f *a)
{
  Eurydice_dst_ref_mut_44 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)56U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 15
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_dst_ref_mut_44 Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_206(Eurydice_arr_92 *a)
{
  Eurydice_dst_ref_mut_44 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)15U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of core.result.Result
with types libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_MLDSA65Signature, libcrux_ml_dsa_types_SigningError

*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_8c_s
{
  core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_57_ಟ್ಯಾಗುಗಳು ಟ್ಯಾಗ್;
  ಒಕ್ಕೂಟ {
    Eurydice_arr_0c case_Ok;
    libcrux_ml_dsa_types_SigningError case_Err;
  }
  val;
}
core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_8c;

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8
with const generics
- $5size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_5d_s { Eurydice_arr_a3 ದತ್ತಾಂಶ[5U]; } Eurydice_arr_5d;

/**
A monomorphic instance of core.option.Option
with types Eurydice_arr_5d

*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ core_option_Option_1e_s
{
  core_option_Option_45_ಟ್ಯಾಗುಗಳು ಟ್ಯಾಗ್;
  Eurydice_arr_5d f0;
}
core_option_Option_1e;

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8
with const generics
- $30size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_5a_s { Eurydice_arr_a3 ದತ್ತಾಂಶ[30U]; } Eurydice_arr_5a;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 30
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_dst_ref_shared_44
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_205(ಸ್ಥಿರಾಂಕ Eurydice_arr_5a *a)
{
  Eurydice_dst_ref_shared_44 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)30U;
  ಹಿಂತಿರುಗಿ lit;
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_0c libcrux_ml_dsa_types_zero_c5_5c(ಶೂನ್ಯ)
{
  ಹಿಂತಿರುಗಿ (KRML_CLITERAL(Eurydice_arr_0c){ .ದತ್ತಾಂಶ = { 0U } });
}

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8
with const generics
- $6size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_dc1_s { Eurydice_arr_a3 ದತ್ತಾಂಶ[6U]; } Eurydice_arr_dc1;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 6
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_dst_ref_shared_44
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_204(ಸ್ಥಿರಾಂಕ Eurydice_arr_dc1 *a)
{
  Eurydice_dst_ref_shared_44 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)6U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
 Declassify secret memory.

 No-op if `valgrind_ct_test` cfg is not enabled.
*/
/**
A monomorphic instance of libcrux_secrets.mem_requests.ct_declassify
with types Eurydice_arr libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients[[$6size_t]]

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_secrets_mem_ವಿನಂತಿಗಳು_ct_declassify_b2(ಸ್ಥಿರಾಂಕ Eurydice_arr_dc1 *val)
{

}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 6
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_dst_ref_mut_44 Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_205(Eurydice_arr_dc1 *a)
{
  Eurydice_dst_ref_mut_44 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)6U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8
with const generics
- $11size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_47_s { Eurydice_arr_a3 ದತ್ತಾಂಶ[11U]; } Eurydice_arr_47;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 11
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_dst_ref_shared_44
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_203(ಸ್ಥಿರಾಂಕ Eurydice_arr_47 *a)
{
  Eurydice_dst_ref_shared_44 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)11U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 5
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_dst_ref_shared_44
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_202(ಸ್ಥಿರಾಂಕ Eurydice_arr_5d *a)
{
  Eurydice_dst_ref_shared_44 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)5U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients, core_ops_range_Range size_t, Eurydice_derefed_slice libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 11
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_dst_ref_shared_44
Eurydice_array_ಗಮ್ಯ_subslice_shared_250(ಸ್ಥಿರಾಂಕ Eurydice_arr_47 *a, core_ops_range_Range_87 r)
{
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(Eurydice_dst_ref_shared_44){ .ptr = a->ದತ್ತಾಂಶ + r.ಆರಂಭ, .meta = r.ಕೊನೆ - r.ಆರಂಭ }
    );
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 5
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_dst_ref_mut_44 Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_204(Eurydice_arr_5d *a)
{
  Eurydice_dst_ref_mut_44 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)5U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 30
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_dst_ref_mut_44 Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_203(Eurydice_arr_5a *a)
{
  Eurydice_dst_ref_mut_44 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)30U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 11
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_dst_ref_mut_44 Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_202(Eurydice_arr_47 *a)
{
  Eurydice_dst_ref_mut_44 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)11U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
This function found in impl {libcrux_ml_dsa::polynomial::PolynomialRingElement<SIMDUnit>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_dsa.polynomial.zero_ff
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_a3 libcrux_ml_dsa_polynomial_zero_ff_37(ಶೂನ್ಯ)
{
  Eurydice_arr_a3 lit;
  Eurydice_arr_4d repeat_ಅಭಿವ್ಯಕ್ತಿ[32U];
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)32U; i++)
  {
    repeat_ಅಭಿವ್ಯಕ್ತಿ[i] = libcrux_ml_dsa_simd_portable_zero_65();
  }
  ಸ್ಮರಣೆ_ನಕಲು(lit.ದತ್ತಾಂಶ, repeat_ಅಭಿವ್ಯಕ್ತಿ, (ಗಾತ್ರ_t)32U * ಗಾತ್ರ (Eurydice_arr_4d));
  ಹಿಂತಿರುಗಿ lit;
}

/**
This function found in impl {libcrux_ml_dsa::polynomial::PolynomialRingElement<SIMDUnit>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_dsa.polynomial.from_i32_array_ff
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_ml_dsa_polynomial_from_i32_array_ff_37(
  Eurydice_dst_ref_shared_83 array,
  Eurydice_arr_a3 *ಫಲಿತಾಂಶ
)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < LIBCRUX_ML_DSA_SIMD_TRAITS_SIMD_UNITS_ಒಳ_RING_ELEMENT; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    libcrux_ml_dsa_simd_portable_from_coefficient_array_65(Eurydice_ತುಂಡು_subslice_shared_47(array,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ಆರಂಭ = i0 * LIBCRUX_ML_DSA_SIMD_TRAITS_COEFFICIENTS_ಒಳ_SIMD_UNIT,
            .ಕೊನೆ = (i0 + (ಗಾತ್ರ_t)1U) * LIBCRUX_ML_DSA_SIMD_TRAITS_COEFFICIENTS_ಒಳ_SIMD_UNIT
          }
        )),
      &ಫಲಿತಾಂಶ->ದತ್ತಾಂಶ[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.arithmetic.use_hint
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_arithmetic_use_hint_37(
  int32_t gamma2,
  Eurydice_dst_ref_shared_20 hint,
  Eurydice_dst_ref_mut_44 re_ಸದಿಶ
)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i0 = (ಗಾತ್ರ_t)0U; i0 < re_ಸದಿಶ.meta; i0++)
  {
    ಗಾತ್ರ_t i1 = i0;
    Eurydice_arr_a3 tmp = libcrux_ml_dsa_polynomial_zero_ff_37();
    libcrux_ml_dsa_polynomial_from_i32_array_ff_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_af(&hint.ptr[i1]),
      &tmp);
    ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)32U; i++)
    {
      ಗಾತ್ರ_t j = i;
      libcrux_ml_dsa_simd_portable_use_hint_65(gamma2, &re_ಸದಿಶ.ptr[i1].ದತ್ತಾಂಶ[j], &tmp.ದತ್ತಾಂಶ[j]);
    }
    re_ಸದಿಶ.ptr[i1] = tmp;
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.ntt.ntt_multiply_montgomery
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_ntt_ntt_multiply_montgomery_37(Eurydice_arr_a3 *lhs, ಸ್ಥಿರಾಂಕ Eurydice_arr_a3 *rhs)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)32U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    libcrux_ml_dsa_simd_portable_montgomery_multiply_65(&lhs->ದತ್ತಾಂಶ[i0], &rhs->ದತ್ತಾಂಶ[i0]);
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_polynomial_ಕೂಡಿಸು_ff_37(Eurydice_arr_a3 *self, ಸ್ಥಿರಾಂಕ Eurydice_arr_a3 *rhs)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)32U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    libcrux_ml_dsa_simd_portable_ಕೂಡಿಸು_65(&self->ದತ್ತಾಂಶ[i0], &rhs->ದತ್ತಾಂಶ[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.simd.portable.arithmetic.shift_left_then_reduce
with const generics
- SHIFT_BY= 13
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_arithmetic_ಸರಿಸು_ಎಡ_then_reduce_84(Eurydice_arr_4d *simd_unit)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)8U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    simd_unit->ದತ್ತಾಂಶ[i0] = (int32_t)((uint32_t)simd_unit->ದತ್ತಾಂಶ[i0] << (uint32_t)13);
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_ml_dsa_simd_portable_ಸರಿಸು_ಎಡ_then_reduce_65_84(Eurydice_arr_4d *simd_unit)
{
  libcrux_ml_dsa_simd_portable_arithmetic_ಸರಿಸು_ಎಡ_then_reduce_84(simd_unit);
}

/**
A monomorphic instance of libcrux_ml_dsa.arithmetic.shift_left_then_reduce
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- SHIFT_BY= 13
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_arithmetic_ಸರಿಸು_ಎಡ_then_reduce_68(Eurydice_arr_a3 *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)32U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    libcrux_ml_dsa_simd_portable_ಸರಿಸು_ಎಡ_then_reduce_65_84(&re->ದತ್ತಾಂಶ[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.ntt.ntt
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ libcrux_ml_dsa_ntt_ntt_37(Eurydice_arr_a3 *re)
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_polynomial_ಕಳೆ_ff_37(Eurydice_arr_a3 *self, ಸ್ಥಿರಾಂಕ Eurydice_arr_a3 *rhs)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)32U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    libcrux_ml_dsa_simd_portable_ಕಳೆ_65(&self->ದತ್ತಾಂಶ[i0], &rhs->ದತ್ತಾಂಶ[i0]);
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_polynomial_barrett_reduce_ff_37(Eurydice_arr_a3 *self)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)32U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    libcrux_ml_dsa_simd_portable_barrett_reduce_simd_unit_65(&self->ದತ್ತಾಂಶ[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.ntt.invert_ntt_montgomery
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ libcrux_ml_dsa_ntt_invert_ntt_montgomery_37(Eurydice_arr_a3 *re)
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_ಮಾತೃಕೆ_compute_w_approx_37(
  ಗಾತ್ರ_t ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_a,
  ಗಾತ್ರ_t columns_ಒಳ_a,
  Eurydice_dst_ref_shared_44 ಮಾತೃಕೆ,
  Eurydice_dst_ref_shared_44 signer_response,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_a3 *verifier_challenge_as_ntt,
  Eurydice_dst_ref_mut_44 t1
)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i0 = (ಗಾತ್ರ_t)0U; i0 < ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_a; i0++)
  {
    ಗಾತ್ರ_t i1 = i0;
    Eurydice_arr_a3 inner_ಫಲಿತಾಂಶ = libcrux_ml_dsa_polynomial_zero_ff_37();
    ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < columns_ಒಳ_a; i++)
    {
      ಗಾತ್ರ_t j = i;
      Eurydice_arr_a3 ಗುಣಲಬ್ಧ = ಮಾತೃಕೆ.ptr[i1 * columns_ಒಳ_a + j];
      libcrux_ml_dsa_ntt_ntt_multiply_montgomery_37(&ಗುಣಲಬ್ಧ, &signer_response.ptr[j]);
      libcrux_ml_dsa_polynomial_ಕೂಡಿಸು_ff_37(&inner_ಫಲಿತಾಂಶ, &ಗುಣಲಬ್ಧ);
    }
    libcrux_ml_dsa_arithmetic_ಸರಿಸು_ಎಡ_then_reduce_68(&t1.ptr[i1]);
    libcrux_ml_dsa_ntt_ntt_37(&t1.ptr[i1]);
    libcrux_ml_dsa_ntt_ntt_multiply_montgomery_37(&t1.ptr[i1], verifier_challenge_as_ntt);
    libcrux_ml_dsa_polynomial_ಕಳೆ_ff_37(&inner_ಫಲಿತಾಂಶ, &t1.ptr[i1]);
    t1.ptr[i1] = inner_ಫಲಿತಾಂಶ;
    libcrux_ml_dsa_polynomial_barrett_reduce_ff_37(&t1.ptr[i1]);
    libcrux_ml_dsa_ntt_invert_ntt_montgomery_37(&t1.ptr[i1]);
  }
}

/**
A monomorphic instance of core.result.Result
with types (), libcrux_ml_dsa_types_VerificationError

*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41_s
{
  core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_57_ಟ್ಯಾಗುಗಳು ಟ್ಯಾಗ್;
  libcrux_ml_dsa_types_VerificationError f0;
}
core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41;

/**
A monomorphic instance of libcrux_ml_dsa.encoding.gamma1.deserialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_encoding_gamma1_deserialize_37(
  ಗಾತ್ರ_t gamma1_exponent,
  Eurydice_borrow_ತುಂಡು_u8 serialized,
  Eurydice_arr_a3 *ಫಲಿತಾಂಶ
)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)32U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    libcrux_ml_dsa_simd_portable_gamma1_deserialize_65(Eurydice_ತುಂಡು_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ಆರಂಭ = i0 * (gamma1_exponent + (ಗಾತ್ರ_t)1U),
            .ಕೊನೆ = (i0 + (ಗಾತ್ರ_t)1U) * (gamma1_exponent + (ಗಾತ್ರ_t)1U)
          }
        )),
      &ಫಲಿತಾಂಶ->ದತ್ತಾಂಶ[i0],
      gamma1_exponent);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.signature.deserialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41
libcrux_ml_dsa_encoding_signature_deserialize_37(
  ಗಾತ್ರ_t columns_ಒಳ_a,
  ಗಾತ್ರ_t ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_a,
  ಗಾತ್ರ_t commitment_hash_ಗಾತ್ರ,
  ಗಾತ್ರ_t gamma1_exponent,
  ಗಾತ್ರ_t gamma1_ring_element_ಗಾತ್ರ,
  ಗಾತ್ರ_t max_ones_ಒಳ_hint,
  ಗಾತ್ರ_t signature_ಗಾತ್ರ,
  Eurydice_borrow_ತುಂಡು_u8 serialized,
  Eurydice_mut_borrow_ತುಂಡು_u8 ಹೊರಹೋಗು_commitment_hash,
  Eurydice_dst_ref_mut_44 ಹೊರಹೋಗು_signer_response,
  Eurydice_dst_ref_mut_20 ಹೊರಹೋಗು_hint
)
{
  Eurydice_borrow_ತುಂಡು_u8_x2
  uu____0 =
    Eurydice_ತುಂಡು_ವಿಭಜಿಸು_at(serialized,
      commitment_hash_ಗಾತ್ರ,
      uint8_t,
      Eurydice_borrow_ತುಂಡು_u8_x2);
  Eurydice_borrow_ತುಂಡು_u8 commitment_hash = uu____0.fst;
  Eurydice_borrow_ತುಂಡು_u8 rest_ದ_serialized = uu____0.snd;
  Eurydice_ತುಂಡು_copy(Eurydice_ತುಂಡು_subslice_mut_c8(ಹೊರಹೋಗು_commitment_hash,
      (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = (ಗಾತ್ರ_t)0U, .ಕೊನೆ = commitment_hash_ಗಾತ್ರ })),
    commitment_hash,
    uint8_t);
  Eurydice_borrow_ತುಂಡು_u8_x2
  uu____1 =
    Eurydice_ತುಂಡು_ವಿಭಜಿಸು_at(rest_ದ_serialized,
      gamma1_ring_element_ಗಾತ್ರ * columns_ಒಳ_a,
      uint8_t,
      Eurydice_borrow_ತುಂಡು_u8_x2);
  Eurydice_borrow_ತುಂಡು_u8 signer_response_serialized = uu____1.fst;
  Eurydice_borrow_ತುಂಡು_u8 hint_serialized = uu____1.snd;
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < columns_ಒಳ_a; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
      Eurydice_ತುಂಡು_subslice_shared_c8(signer_response_serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ಆರಂಭ = i0 * gamma1_ring_element_ಗಾತ್ರ,
            .ಕೊನೆ = (i0 + (ಗಾತ್ರ_t)1U) * gamma1_ring_element_ಗಾತ್ರ
          }
        )),
      &ಹೊರಹೋಗು_signer_response.ptr[i0]);
  }
  ಗಾತ್ರ_t ಹಿಂದಿನ_true_hints_ನೋಡಿದ = (ಗಾತ್ರ_t)0U;
  bool malformed_hint = false;
  ಗಾಗಿ (ಗಾತ್ರ_t i0 = (ಗಾತ್ರ_t)0U; i0 < ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_a; i0++)
  {
    ಗಾತ್ರ_t i1 = i0;
    ಗಾತ್ರ_t current_true_hints_ನೋಡಿದ = (ಗಾತ್ರ_t)(uint32_t)hint_serialized.ptr[max_ones_ಒಳ_hint + i1];
    ಆದರೆ (current_true_hints_ನೋಡಿದ < ಹಿಂದಿನ_true_hints_ನೋಡಿದ)
    {
      malformed_hint = true;
      ನಿಲ್ಲಿಸು;
    }
    ಆದರೆ (current_true_hints_ನೋಡಿದ > max_ones_ಒಳ_hint)
    {
      malformed_hint = true;
      ನಿಲ್ಲಿಸು;
    }
    ಗಾಗಿ (ಗಾತ್ರ_t i = ಹಿಂದಿನ_true_hints_ನೋಡಿದ; i < current_true_hints_ನೋಡಿದ; i++)
    {
      ಗಾತ್ರ_t j = i;
      ಆದರೆ (j > ಹಿಂದಿನ_true_hints_ನೋಡಿದ)
      {
        ಆದರೆ (hint_serialized.ptr[j] <= hint_serialized.ptr[j - (ಗಾತ್ರ_t)1U])
        {
          malformed_hint = true;
          ನಿಲ್ಲಿಸು;
        }
      }
      libcrux_ml_dsa_encoding_signature_ಗಣ_hint(ಹೊರಹೋಗು_hint,
        i1,
        (ಗಾತ್ರ_t)(uint32_t)hint_serialized.ptr[j]);
    }
    ಆದರೆ (malformed_hint)
    {
      ನಿಲ್ಲಿಸು;
    }
    ಹಿಂದಿನ_true_hints_ನೋಡಿದ = current_true_hints_ನೋಡಿದ;
  }
  ಗಾಗಿ (ಗಾತ್ರ_t i = ಹಿಂದಿನ_true_hints_ನೋಡಿದ; i < max_ones_ಒಳ_hint; i++)
  {
    ಗಾತ್ರ_t j = i;
    ಆದರೆ (hint_serialized.ptr[j] != 0U)
    {
      malformed_hint = true;
      ನಿಲ್ಲಿಸು;
    }
  }
  core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41 uu____2;
  ಆದರೆ (malformed_hint)
  {
    uu____2 =
      (
        KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41){
          .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Err,
          .f0 = libcrux_ml_dsa_types_VerificationError_MalformedHintError
        }
      );
  }
  ಇಲ್ಲದಿದ್ದರೆ
  {
    uu____2 = (KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41){ .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Ok });
  }
  ಹಿಂತಿರುಗಿ uu____2;
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.t1.deserialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_ml_dsa_encoding_t1_deserialize_37(
  Eurydice_borrow_ತುಂಡು_u8 serialized,
  Eurydice_arr_a3 *ಫಲಿತಾಂಶ
)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)32U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    libcrux_ml_dsa_simd_portable_t1_deserialize_65(Eurydice_ತುಂಡು_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ಆರಂಭ = i0 * LIBCRUX_ML_DSA_ENCODING_T1_DESERIALIZE_ಕಿಟಕಿ,
            .ಕೊನೆ = (i0 + (ಗಾತ್ರ_t)1U) * LIBCRUX_ML_DSA_ENCODING_T1_DESERIALIZE_ಕಿಟಕಿ
          }
        )),
      &ಫಲಿತಾಂಶ->ದತ್ತಾಂಶ[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.verification_key.deserialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_encoding_verification_ಕೀಲಿ_deserialize_37(
  ಗಾತ್ರ_t ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_a,
  ಗಾತ್ರ_t verification_ಕೀಲಿ_ಗಾತ್ರ,
  Eurydice_borrow_ತುಂಡು_u8 serialized,
  Eurydice_dst_ref_mut_44 t1
)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_a; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    libcrux_ml_dsa_encoding_t1_deserialize_37(Eurydice_ತುಂಡು_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ಆರಂಭ = i0 * LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_ದ_T1_S_ಗಾತ್ರ,
            .ಕೊನೆ = (i0 + (ಗಾತ್ರ_t)1U) * LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_ದ_T1_S_ಗಾತ್ರ
          }
        )),
      &t1.ptr[i0]);
  }
}

/**
A monomorphic instance of core.result.Result
with types libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_MLDSA44Signature, libcrux_ml_dsa_types_SigningError

*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_48_s
{
  core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_57_ಟ್ಯಾಗುಗಳು ಟ್ಯಾಗ್;
  ಒಕ್ಕೂಟ {
    Eurydice_arr_85 case_Ok;
    libcrux_ml_dsa_types_SigningError case_Err;
  }
  val;
}
core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_48;

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8
with const generics
- $4size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_9d_s { Eurydice_arr_a3 ದತ್ತಾಂಶ[4U]; } Eurydice_arr_9d;

/**
A monomorphic instance of core.option.Option
with types Eurydice_arr_9d

*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ core_option_Option_d9_s
{
  core_option_Option_45_ಟ್ಯಾಗುಗಳು ಟ್ಯಾಗ್;
  Eurydice_arr_9d f0;
}
core_option_Option_d9;

/**
A monomorphic instance of core.result.Result
with types (), libcrux_ml_dsa_types_SigningError

*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_53_s
{
  core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_57_ಟ್ಯಾಗುಗಳು ಟ್ಯಾಗ್;
  libcrux_ml_dsa_types_SigningError f0;
}
core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_53;

/**
A monomorphic instance of libcrux_ml_dsa.encoding.gamma1.serialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_encoding_gamma1_serialize_37(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_a3 *re,
  Eurydice_mut_borrow_ತುಂಡು_u8 serialized,
  ಗಾತ್ರ_t gamma1_exponent
)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)32U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    ಸ್ಥಿರಾಂಕ Eurydice_arr_4d *simd_unit = &re->ದತ್ತಾಂಶ[i0];
    libcrux_ml_dsa_simd_portable_gamma1_serialize_65(simd_unit,
      Eurydice_ತುಂಡು_subslice_mut_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ಆರಂಭ = i0 * (gamma1_exponent + (ಗಾತ್ರ_t)1U),
            .ಕೊನೆ = (i0 + (ಗಾತ್ರ_t)1U) * (gamma1_exponent + (ಗಾತ್ರ_t)1U)
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_encoding_signature_serialize_37(
  Eurydice_borrow_ತುಂಡು_u8 commitment_hash,
  Eurydice_dst_ref_shared_44 signer_response,
  Eurydice_dst_ref_shared_20 hint,
  ಗಾತ್ರ_t commitment_hash_ಗಾತ್ರ,
  ಗಾತ್ರ_t columns_ಒಳ_a,
  ಗಾತ್ರ_t ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_a,
  ಗಾತ್ರ_t gamma1_exponent,
  ಗಾತ್ರ_t gamma1_ring_element_ಗಾತ್ರ,
  ಗಾತ್ರ_t max_ones_ಒಳ_hint,
  Eurydice_mut_borrow_ತುಂಡು_u8 signature
)
{
  ಗಾತ್ರ_t ಸ್ಥಾನಾಂತರ = (ಗಾತ್ರ_t)0U;
  Eurydice_ತುಂಡು_copy(Eurydice_ತುಂಡು_subslice_mut_c8(signature,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .ಆರಂಭ = ಸ್ಥಾನಾಂತರ,
          .ಕೊನೆ = ಸ್ಥಾನಾಂತರ + commitment_hash_ಗಾತ್ರ
        }
      )),
    commitment_hash,
    uint8_t);
  ಸ್ಥಾನಾಂತರ += commitment_hash_ಗಾತ್ರ;
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < columns_ಒಳ_a; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    libcrux_ml_dsa_encoding_gamma1_serialize_37(&signer_response.ptr[i0],
      Eurydice_ತುಂಡು_subslice_mut_c8(signature,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ಆರಂಭ = ಸ್ಥಾನಾಂತರ,
            .ಕೊನೆ = ಸ್ಥಾನಾಂತರ + gamma1_ring_element_ಗಾತ್ರ
          }
        )),
      gamma1_exponent);
    ಸ್ಥಾನಾಂತರ += gamma1_ring_element_ಗಾತ್ರ;
  }
  ಗಾತ್ರ_t true_hints_ನೋಡಿದ = (ಗಾತ್ರ_t)0U;
  ಗಾಗಿ (ಗಾತ್ರ_t i0 = (ಗಾತ್ರ_t)0U; i0 < ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_a; i0++)
  {
    ಗಾತ್ರ_t i1 = i0;
    ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)256U; i++)
    {
      ಗಾತ್ರ_t j = i;
      ಆದರೆ (hint.ptr[i1].ದತ್ತಾಂಶ[j] == 1)
      {
        signature.ptr[ಸ್ಥಾನಾಂತರ + true_hints_ನೋಡಿದ] = (uint8_t)j;
        true_hints_ನೋಡಿದ++;
      }
    }
    signature.ptr[ಸ್ಥಾನಾಂತರ + max_ones_ಒಳ_hint + i1] = (uint8_t)true_hints_ನೋಡಿದ;
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_6c
libcrux_ml_dsa_polynomial_ಗಮ್ಯ_i32_array_ff_37(ಸ್ಥಿರಾಂಕ Eurydice_arr_a3 *self)
{
  Eurydice_arr_6c ಫಲಿತಾಂಶ = { .ದತ್ತಾಂಶ = { 0U } };
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)32U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    libcrux_ml_dsa_simd_portable_ಗಮ್ಯ_coefficient_array_65(&self->ದತ್ತಾಂಶ[i0],
      Eurydice_array_ಗಮ್ಯ_subslice_mut_44(&ಫಲಿತಾಂಶ,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ಆರಂಭ = i0 * LIBCRUX_ML_DSA_SIMD_TRAITS_COEFFICIENTS_ಒಳ_SIMD_UNIT,
            .ಕೊನೆ = (i0 + (ಗಾತ್ರ_t)1U) * LIBCRUX_ML_DSA_SIMD_TRAITS_COEFFICIENTS_ಒಳ_SIMD_UNIT
          }
        )));
  }
  ಹಿಂತಿರುಗಿ ಫಲಿತಾಂಶ;
}

/**
A monomorphic instance of libcrux_ml_dsa.arithmetic.make_hint
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಗಾತ್ರ_t
libcrux_ml_dsa_arithmetic_make_hint_37(
  Eurydice_dst_ref_shared_44 ಕೆಳಗಿನ,
  Eurydice_dst_ref_shared_44 ಮೇಲಿನ,
  int32_t gamma2,
  Eurydice_dst_ref_mut_20 hint
)
{
  ಗಾತ್ರ_t true_hints = (ಗಾತ್ರ_t)0U;
  Eurydice_arr_a3 hint_simd = libcrux_ml_dsa_polynomial_zero_ff_37();
  ಗಾಗಿ (ಗಾತ್ರ_t i0 = (ಗಾತ್ರ_t)0U; i0 < ಕೆಳಗಿನ.meta; i0++)
  {
    ಗಾತ್ರ_t i1 = i0;
    ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)32U; i++)
    {
      ಗಾತ್ರ_t j = i;
      ಗಾತ್ರ_t
      one_hints_ಎಣಿಕೆ =
        libcrux_ml_dsa_simd_portable_compute_hint_65(&ಕೆಳಗಿನ.ptr[i1].ದತ್ತಾಂಶ[j],
          &ಮೇಲಿನ.ptr[i1].ದತ್ತಾಂಶ[j],
          gamma2,
          &hint_simd.ದತ್ತಾಂಶ[j]);
      true_hints += one_hints_ಎಣಿಕೆ;
    }
    Eurydice_arr_6c uu____0 = libcrux_ml_dsa_polynomial_ಗಮ್ಯ_i32_array_ff_37(&hint_simd);
    hint.ptr[i1] = uu____0;
  }
  ಹಿಂತಿರುಗಿ true_hints;
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
ಸ್ಥಿರ KRML_MUSTINLINE bool
libcrux_ml_dsa_polynomial_infinity_norm_exceeds_ff_37(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_a3 *self,
  int32_t bound
)
{
  bool ಫಲಿತಾಂಶ = false;
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)32U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    bool
    coeff_exceeds = libcrux_ml_dsa_simd_portable_infinity_norm_exceeds_65(&self->ದತ್ತಾಂಶ[i0], bound);
    bool uu____0;
    ಆದರೆ (ಫಲಿತಾಂಶ)
    {
      uu____0 = true;
    }
    ಇಲ್ಲದಿದ್ದರೆ
    {
      uu____0 = coeff_exceeds;
    }
    ಫಲಿತಾಂಶ = uu____0;
  }
  ಹಿಂತಿರುಗಿ ಫಲಿತಾಂಶ;
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
ಸ್ಥಿರ KRML_MUSTINLINE bool
libcrux_ml_dsa_arithmetic_ಸದಿಶ_infinity_norm_exceeds_37(
  Eurydice_dst_ref_shared_44 ಸದಿಶ,
  int32_t bound
)
{
  bool ಫಲಿತಾಂಶ = false;
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < ಸದಿಶ.meta; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    bool uu____0;
    ಆದರೆ (ಫಲಿತಾಂಶ)
    {
      uu____0 = true;
    }
    ಇಲ್ಲದಿದ್ದರೆ
    {
      uu____0 = libcrux_ml_dsa_polynomial_infinity_norm_exceeds_ff_37(&ಸದಿಶ.ptr[i0], bound);
    }
    ಫಲಿತಾಂಶ = uu____0;
  }
  ಹಿಂತಿರುಗಿ ಫಲಿತಾಂಶ;
}

/**
A monomorphic instance of libcrux_ml_dsa.matrix.subtract_vectors
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_ಮಾತೃಕೆ_ಕಳೆ_vectors_37(
  ಗಾತ್ರ_t dimension,
  Eurydice_dst_ref_mut_44 lhs,
  Eurydice_dst_ref_shared_44 rhs
)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < dimension; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    libcrux_ml_dsa_polynomial_ಕಳೆ_ff_37(&lhs.ptr[i0], &rhs.ptr[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.matrix.add_vectors
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_ಮಾತೃಕೆ_ಕೂಡಿಸು_vectors_37(
  ಗಾತ್ರ_t dimension,
  Eurydice_dst_ref_mut_44 lhs,
  Eurydice_dst_ref_shared_44 rhs
)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < dimension; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    libcrux_ml_dsa_polynomial_ಕೂಡಿಸು_ff_37(&lhs.ptr[i0], &rhs.ptr[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.matrix.vector_times_ring_element
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_ಮಾತೃಕೆ_ಸದಿಶ_times_ring_element_37(
  Eurydice_dst_ref_mut_44 ಸದಿಶ,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_a3 *ring_element
)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < ಸದಿಶ.meta; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    libcrux_ml_dsa_ntt_ntt_multiply_montgomery_37(&ಸದಿಶ.ptr[i0], ring_element);
    libcrux_ml_dsa_ntt_invert_ntt_montgomery_37(&ಸದಿಶ.ptr[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.commitment.serialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_encoding_commitment_serialize_37(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_a3 *re,
  Eurydice_mut_borrow_ತುಂಡು_u8 serialized
)
{
  ಗಾತ್ರ_t output_ಬೈಟುಗಳು_ಪ್ರತಿ_simd_unit = serialized.meta / ((ಗಾತ್ರ_t)8U * (ಗಾತ್ರ_t)4U);
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)32U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    ಸ್ಥಿರಾಂಕ Eurydice_arr_4d *simd_unit = &re->ದತ್ತಾಂಶ[i0];
    libcrux_ml_dsa_simd_portable_commitment_serialize_65(simd_unit,
      Eurydice_ತುಂಡು_subslice_mut_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ಆರಂಭ = i0 * output_ಬೈಟುಗಳು_ಪ್ರತಿ_simd_unit,
            .ಕೊನೆ = (i0 + (ಗಾತ್ರ_t)1U) * output_ಬೈಟುಗಳು_ಪ್ರತಿ_simd_unit
          }
        )));
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.commitment.serialize_vector
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_encoding_commitment_serialize_ಸದಿಶ_37(
  ಗಾತ್ರ_t ring_element_ಗಾತ್ರ,
  Eurydice_dst_ref_shared_44 ಸದಿಶ,
  Eurydice_mut_borrow_ತುಂಡು_u8 serialized
)
{
  ಗಾತ್ರ_t ಸ್ಥಾನಾಂತರ = (ಗಾತ್ರ_t)0U;
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < ಸದಿಶ.meta; i++)
  {
    ಗಾತ್ರ_t _cloop_j = i;
    ಸ್ಥಿರಾಂಕ Eurydice_arr_a3 *ring_element = &ಸದಿಶ.ptr[_cloop_j];
    libcrux_ml_dsa_encoding_commitment_serialize_37(ring_element,
      Eurydice_ತುಂಡು_subslice_mut_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ಆರಂಭ = ಸ್ಥಾನಾಂತರ,
            .ಕೊನೆ = ಸ್ಥಾನಾಂತರ + ring_element_ಗಾತ್ರ
          }
        )));
    ಸ್ಥಾನಾಂತರ += ring_element_ಗಾತ್ರ;
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.arithmetic.decompose_vector
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_arithmetic_decompose_ಸದಿಶ_37(
  ಗಾತ್ರ_t dimension,
  int32_t gamma2,
  Eurydice_dst_ref_shared_44 t,
  Eurydice_dst_ref_mut_44 ಕೆಳಗಿನ,
  Eurydice_dst_ref_mut_44 ಮೇಲಿನ
)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i0 = (ಗಾತ್ರ_t)0U; i0 < dimension; i0++)
  {
    ಗಾತ್ರ_t i1 = i0;
    ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)32U; i++)
    {
      ಗಾತ್ರ_t j = i;
      libcrux_ml_dsa_simd_portable_decompose_65(gamma2,
        &t.ptr[i1].ದತ್ತಾಂಶ[j],
        &ಕೆಳಗಿನ.ptr[i1].ದತ್ತಾಂಶ[j],
        &ಮೇಲಿನ.ptr[i1].ದತ್ತಾಂಶ[j]);
    }
  }
}

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_dsa_polynomial_PolynomialRingElement_e8
with const generics
- $16size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_2f_s { Eurydice_arr_a3 ದತ್ತಾಂಶ[16U]; } Eurydice_arr_2f;

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 16
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_dst_ref_shared_44
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_201(ಸ್ಥಿರಾಂಕ Eurydice_arr_2f *a)
{
  Eurydice_dst_ref_shared_44 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)16U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
 Compute InvertNTT(Â ◦ ŷ)
*/
/**
A monomorphic instance of libcrux_ml_dsa.matrix.compute_matrix_x_mask
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_ಮಾತೃಕೆ_compute_ಮಾತೃಕೆ_x_ಮುಖವಾಡ_37(
  ಗಾತ್ರ_t ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_a,
  ಗಾತ್ರ_t columns_ಒಳ_a,
  Eurydice_dst_ref_shared_44 ಮಾತೃಕೆ,
  Eurydice_dst_ref_shared_44 ಮುಖವಾಡ,
  Eurydice_dst_ref_mut_44 ಫಲಿತಾಂಶ
)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i0 = (ಗಾತ್ರ_t)0U; i0 < ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_a; i0++)
  {
    ಗಾತ್ರ_t i1 = i0;
    ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < columns_ಒಳ_a; i++)
    {
      ಗಾತ್ರ_t j = i;
      Eurydice_arr_a3 ಗುಣಲಬ್ಧ = ಮುಖವಾಡ.ptr[j];
      libcrux_ml_dsa_ntt_ntt_multiply_montgomery_37(&ಗುಣಲಬ್ಧ, &ಮಾತೃಕೆ.ptr[i1 * columns_ಒಳ_a + j]);
      libcrux_ml_dsa_polynomial_ಕೂಡಿಸು_ff_37(&ಫಲಿತಾಂಶ.ptr[i1], &ಗುಣಲಬ್ಧ);
    }
    libcrux_ml_dsa_polynomial_barrett_reduce_ff_37(&ಫಲಿತಾಂಶ.ptr[i1]);
    libcrux_ml_dsa_ntt_invert_ntt_montgomery_37(&ಫಲಿತಾಂಶ.ptr[i1]);
  }
}

/**
A monomorphic instance of core.option.Option
with types libcrux_ml_dsa_pre_hash_DomainSeparationContext

*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ core_option_Option_84_s
{
  core_option_Option_45_ಟ್ಯಾಗುಗಳು ಟ್ಯಾಗ್;
  libcrux_ml_dsa_pre_hash_DomainSeparationContext f0;
}
core_option_Option_84;

/**
A monomorphic instance of libcrux_ml_dsa.encoding.t0.deserialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_encoding_t0_deserialize_37(
  Eurydice_borrow_ತುಂಡು_u8 serialized,
  Eurydice_arr_a3 *ಫಲಿತಾಂಶ
)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)32U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    libcrux_ml_dsa_simd_portable_t0_deserialize_65(Eurydice_ತುಂಡು_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ಆರಂಭ = i0 * LIBCRUX_ML_DSA_ENCODING_T0_OUTPUT_ಬೈಟುಗಳು_ಪ್ರತಿ_SIMD_UNIT,
            .ಕೊನೆ = (i0 + (ಗಾತ್ರ_t)1U) * LIBCRUX_ML_DSA_ENCODING_T0_OUTPUT_ಬೈಟುಗಳು_ಪ್ರತಿ_SIMD_UNIT
          }
        )),
      &ಫಲಿತಾಂಶ->ದತ್ತಾಂಶ[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.t0.deserialize_to_vector_then_ntt
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_encoding_t0_deserialize_ಗಮ್ಯ_ಸದಿಶ_then_ntt_37(
  Eurydice_borrow_ತುಂಡು_u8 serialized,
  Eurydice_dst_ref_mut_44 ring_elements
)
{
  ಗಾಗಿ
  (ಗಾತ್ರ_t
    i = (ಗಾತ್ರ_t)0U;
    i < serialized.meta / LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_ದ_T0_S_ಗಾತ್ರ;
    i++)
  {
    ಗಾತ್ರ_t i0 = i;
    Eurydice_borrow_ತುಂಡು_u8
    ಬೈಟುಗಳು =
      Eurydice_ತುಂಡು_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ಆರಂಭ = i0 * LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_ದ_T0_S_ಗಾತ್ರ,
            .ಕೊನೆ = i0 * LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_ದ_T0_S_ಗಾತ್ರ +
              LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_ದ_T0_S_ಗಾತ್ರ
          }
        ));
    libcrux_ml_dsa_encoding_t0_deserialize_37(ಬೈಟುಗಳು, &ring_elements.ptr[i0]);
    libcrux_ml_dsa_ntt_ntt_37(&ring_elements.ptr[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.error.deserialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_encoding_error_deserialize_37(
  libcrux_ml_dsa_constants_Eta eta,
  Eurydice_borrow_ತುಂಡು_u8 serialized,
  Eurydice_arr_a3 *ಫಲಿತಾಂಶ
)
{
  ಗಾತ್ರ_t chunk_ಗಾತ್ರ = libcrux_ml_dsa_encoding_error_chunk_ಗಾತ್ರ(eta);
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)32U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    libcrux_ml_dsa_simd_portable_error_deserialize_65(eta,
      Eurydice_ತುಂಡು_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ಆರಂಭ = i0 * chunk_ಗಾತ್ರ,
            .ಕೊನೆ = (i0 + (ಗಾತ್ರ_t)1U) * chunk_ಗಾತ್ರ
          }
        )),
      &ಫಲಿತಾಂಶ->ದತ್ತಾಂಶ[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.error.deserialize_to_vector_then_ntt
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_encoding_error_deserialize_ಗಮ್ಯ_ಸದಿಶ_then_ntt_37(
  libcrux_ml_dsa_constants_Eta eta,
  ಗಾತ್ರ_t ring_element_ಗಾತ್ರ,
  Eurydice_borrow_ತುಂಡು_u8 serialized,
  Eurydice_dst_ref_mut_44 ring_elements
)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < serialized.meta / ring_element_ಗಾತ್ರ; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    Eurydice_borrow_ತುಂಡು_u8
    ಬೈಟುಗಳು =
      Eurydice_ತುಂಡು_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ಆರಂಭ = i0 * ring_element_ಗಾತ್ರ,
            .ಕೊನೆ = i0 * ring_element_ಗಾತ್ರ + ring_element_ಗಾತ್ರ
          }
        ));
    libcrux_ml_dsa_encoding_error_deserialize_37(eta, ಬೈಟುಗಳು, &ring_elements.ptr[i0]);
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_85 libcrux_ml_dsa_types_zero_c5_37(ಶೂನ್ಯ)
{
  ಹಿಂತಿರುಗಿ (KRML_CLITERAL(Eurydice_arr_85){ .ದತ್ತಾಂಶ = { 0U } });
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.t0.serialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_encoding_t0_serialize_37(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_a3 *re,
  Eurydice_mut_borrow_ತುಂಡು_u8 serialized
)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)32U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    ಸ್ಥಿರಾಂಕ Eurydice_arr_4d *simd_unit = &re->ದತ್ತಾಂಶ[i0];
    libcrux_ml_dsa_simd_portable_t0_serialize_65(simd_unit,
      Eurydice_ತುಂಡು_subslice_mut_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ಆರಂಭ = i0 * LIBCRUX_ML_DSA_ENCODING_T0_OUTPUT_ಬೈಟುಗಳು_ಪ್ರತಿ_SIMD_UNIT,
            .ಕೊನೆ = (i0 + (ಗಾತ್ರ_t)1U) * LIBCRUX_ML_DSA_ENCODING_T0_OUTPUT_ಬೈಟುಗಳು_ಪ್ರತಿ_SIMD_UNIT
          }
        )));
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.error.serialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_encoding_error_serialize_37(
  libcrux_ml_dsa_constants_Eta eta,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_a3 *re,
  Eurydice_mut_borrow_ತುಂಡು_u8 serialized
)
{
  ಗಾತ್ರ_t output_ಬೈಟುಗಳು_ಪ್ರತಿ_simd_unit = libcrux_ml_dsa_encoding_error_chunk_ಗಾತ್ರ(eta);
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)32U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    ಸ್ಥಿರಾಂಕ Eurydice_arr_4d *simd_unit = &re->ದತ್ತಾಂಶ[i0];
    libcrux_ml_dsa_simd_portable_error_serialize_65(eta,
      simd_unit,
      Eurydice_ತುಂಡು_subslice_mut_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ಆರಂಭ = i0 * output_ಬೈಟುಗಳು_ಪ್ರತಿ_simd_unit,
            .ಕೊನೆ = (i0 + (ಗಾತ್ರ_t)1U) * output_ಬೈಟುಗಳು_ಪ್ರತಿ_simd_unit
          }
        )));
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.t1.serialize
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_encoding_t1_serialize_37(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_a3 *re,
  Eurydice_mut_borrow_ತುಂಡು_u8 serialized
)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)32U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    ಸ್ಥಿರಾಂಕ Eurydice_arr_4d *simd_unit = &re->ದತ್ತಾಂಶ[i0];
    libcrux_ml_dsa_simd_portable_t1_serialize_65(simd_unit,
      Eurydice_ತುಂಡು_subslice_mut_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ಆರಂಭ = i0 * LIBCRUX_ML_DSA_ENCODING_T1_SERIALIZE_OUTPUT_ಬೈಟುಗಳು_ಪ್ರತಿ_SIMD_UNIT,
            .ಕೊನೆ = (i0 + (ಗಾತ್ರ_t)1U) *
              LIBCRUX_ML_DSA_ENCODING_T1_SERIALIZE_OUTPUT_ಬೈಟುಗಳು_ಪ್ರತಿ_SIMD_UNIT
          }
        )));
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.verification_key.generate_serialized
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_encoding_verification_ಕೀಲಿ_generate_serialized_37(
  Eurydice_borrow_ತುಂಡು_u8 ಬೀಜ,
  Eurydice_dst_ref_shared_44 t1,
  Eurydice_mut_borrow_ತುಂಡು_u8 verification_ಕೀಲಿ_serialized
)
{
  Eurydice_ತುಂಡು_copy(Eurydice_ತುಂಡು_subslice_mut_c8(verification_ಕೀಲಿ_serialized,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .ಆರಂಭ = (ಗಾತ್ರ_t)0U,
          .ಕೊನೆ = LIBCRUX_ML_DSA_CONSTANTS_ಬೀಜ_FOR_A_ಗಾತ್ರ
        }
      )),
    ಬೀಜ,
    uint8_t);
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < t1.meta; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    ಸ್ಥಿರಾಂಕ Eurydice_arr_a3 *ring_element = &t1.ptr[i0];
    ಗಾತ್ರ_t
    ಸ್ಥಾನಾಂತರ =
      LIBCRUX_ML_DSA_CONSTANTS_ಬೀಜ_FOR_A_ಗಾತ್ರ +
        i0 * LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_ದ_T1_S_ಗಾತ್ರ;
    libcrux_ml_dsa_encoding_t1_serialize_37(ring_element,
      Eurydice_ತುಂಡು_subslice_mut_c8(verification_ಕೀಲಿ_serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ಆರಂಭ = ಸ್ಥಾನಾಂತರ,
            .ಕೊನೆ = ಸ್ಥಾನಾಂತರ + LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_ದ_T1_S_ಗಾತ್ರ
          }
        )));
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.arithmetic.power2round_vector
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_arithmetic_power2round_ಸದಿಶ_37(
  Eurydice_dst_ref_mut_44 t,
  Eurydice_dst_ref_mut_44 t1
)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i0 = (ಗಾತ್ರ_t)0U; i0 < t.meta; i0++)
  {
    ಗಾತ್ರ_t i1 = i0;
    ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)32U; i++)
    {
      ಗಾತ್ರ_t j = i;
      libcrux_ml_dsa_simd_portable_power2round_65(&t.ptr[i1].ದತ್ತಾಂಶ[j], &t1.ptr[i1].ದತ್ತಾಂಶ[j]);
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_secrets_mem_ವಿನಂತಿಗಳು_ct_declassify_f5(ಸ್ಥಿರಾಂಕ Eurydice_arr_9d *val)
{

}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 8
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_dst_ref_shared_44
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_200(ಸ್ಥಿರಾಂಕ Eurydice_arr_8f *a)
{
  Eurydice_dst_ref_shared_44 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)8U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 4
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_dst_ref_shared_44
Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_20(ಸ್ಥಿರಾಂಕ Eurydice_arr_9d *a)
{
  Eurydice_dst_ref_shared_44 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)4U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
 Compute InvertNTT(Â ◦ ŝ₁) + s₂
*/
/**
A monomorphic instance of libcrux_ml_dsa.matrix.compute_as1_plus_s2
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_ಮಾತೃಕೆ_compute_as1_plus_s2_37(
  ಗಾತ್ರ_t ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_a,
  ಗಾತ್ರ_t columns_ಒಳ_a,
  Eurydice_dst_ref_mut_44 a_as_ntt,
  Eurydice_dst_ref_shared_44 s1_ntt,
  Eurydice_dst_ref_shared_44 s1_s2,
  Eurydice_dst_ref_mut_44 ಫಲಿತಾಂಶ
)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i0 = (ಗಾತ್ರ_t)0U; i0 < ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_a; i0++)
  {
    ಗಾತ್ರ_t i1 = i0;
    ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < columns_ಒಳ_a; i++)
    {
      ಗಾತ್ರ_t j = i;
      libcrux_ml_dsa_ntt_ntt_multiply_montgomery_37(&a_as_ntt.ptr[i1 * columns_ಒಳ_a + j],
        &s1_ntt.ptr[j]);
      libcrux_ml_dsa_polynomial_ಕೂಡಿಸು_ff_37(&ಫಲಿತಾಂಶ.ptr[i1], &a_as_ntt.ptr[i1 * columns_ಒಳ_a + j]);
    }
  }
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < ಫಲಿತಾಂಶ.meta; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    libcrux_ml_dsa_polynomial_barrett_reduce_ff_37(&ಫಲಿತಾಂಶ.ptr[i0]);
    libcrux_ml_dsa_ntt_invert_ntt_montgomery_37(&ಫಲಿತಾಂಶ.ptr[i0]);
    libcrux_ml_dsa_polynomial_ಕೂಡಿಸು_ff_37(&ಫಲಿತಾಂಶ.ptr[i0], &s1_s2.ptr[columns_ಒಳ_a + i0]);
  }
}

/**
A monomorphic instance of Eurydice.array_to_subslice_shared
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients, core_ops_range_Range size_t, Eurydice_derefed_slice libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 8
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_dst_ref_shared_44
Eurydice_array_ಗಮ್ಯ_subslice_shared_25(ಸ್ಥಿರಾಂಕ Eurydice_arr_8f *a, core_ops_range_Range_87 r)
{
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(Eurydice_dst_ref_shared_44){ .ptr = a->ದತ್ತಾಂಶ + r.ಆರಂಭ, .meta = r.ಕೊನೆ - r.ಆರಂಭ }
    );
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 4
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_dst_ref_mut_44 Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_201(Eurydice_arr_9d *a)
{
  Eurydice_dst_ref_mut_44 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)4U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 16
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_dst_ref_mut_44 Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_200(Eurydice_arr_2f *a)
{
  Eurydice_dst_ref_mut_44 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)16U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of libcrux_ml_dsa.sample.rejection_sample_less_than_field_modulus
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE bool
libcrux_ml_dsa_sample_rejection_sample_less_than_ಕ್ಷೇತ್ರ_modulus_37(
  Eurydice_borrow_ತುಂಡು_u8 randomness,
  ಗಾತ್ರ_t *sampled_coefficients,
  Eurydice_arr_d0 *ಹೊರಹೋಗು
)
{
  bool ಮುಗಿದ = false;
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < randomness.meta / (ಗಾತ್ರ_t)24U; i++)
  {
    ಗಾತ್ರ_t _cloop_i = i;
    Eurydice_borrow_ತುಂಡು_u8
    random_ಬೈಟುಗಳು =
      Eurydice_ತುಂಡು_subslice_shared_c8(randomness,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ಆರಂಭ = _cloop_i * (ಗಾತ್ರ_t)24U,
            .ಕೊನೆ = _cloop_i * (ಗಾತ್ರ_t)24U + (ಗಾತ್ರ_t)24U
          }
        ));
    ಆದರೆ (!ಮುಗಿದ)
    {
      ಗಾತ್ರ_t
      sampled =
        libcrux_ml_dsa_simd_portable_rejection_sample_less_than_ಕ್ಷೇತ್ರ_modulus_65(random_ಬೈಟುಗಳು,
          Eurydice_array_ಗಮ್ಯ_subslice_from_mut_11(ಹೊರಹೋಗು, sampled_coefficients[0U]));
      sampled_coefficients[0U] += sampled;
      ಆದರೆ (sampled_coefficients[0U] >= LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_ಒಳ_RING_ELEMENT)
      {
        ಮುಗಿದ = true;
      }
    }
  }
  ಹಿಂತಿರುಗಿ ಮುಗಿದ;
}

/**
A monomorphic instance of Eurydice.array_to_slice_mut
with types libcrux_ml_dsa_polynomial_PolynomialRingElement libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics
- N= 8
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_dst_ref_mut_44 Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_20(Eurydice_arr_8f *a)
{
  Eurydice_dst_ref_mut_44 lit;
  lit.ptr = a->ದತ್ತಾಂಶ;
  lit.meta = (ಗಾತ್ರ_t)8U;
  ಹಿಂತಿರುಗಿ lit;
}

/**
A monomorphic instance of libcrux_ml_dsa.sample.rejection_sample_less_than_eta_equals_4
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE bool
libcrux_ml_dsa_sample_rejection_sample_less_than_eta_equals_4_37(
  Eurydice_borrow_ತುಂಡು_u8 randomness,
  ಗಾತ್ರ_t *sampled_coefficients,
  Eurydice_arr_d0 *ಹೊರಹೋಗು
)
{
  bool ಮುಗಿದ = false;
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < randomness.meta / (ಗಾತ್ರ_t)4U; i++)
  {
    ಗಾತ್ರ_t _cloop_i = i;
    Eurydice_borrow_ತುಂಡು_u8
    random_ಬೈಟುಗಳು =
      Eurydice_ತುಂಡು_subslice_shared_c8(randomness,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ಆರಂಭ = _cloop_i * (ಗಾತ್ರ_t)4U,
            .ಕೊನೆ = _cloop_i * (ಗಾತ್ರ_t)4U + (ಗಾತ್ರ_t)4U
          }
        ));
    ಆದರೆ (!ಮುಗಿದ)
    {
      ಗಾತ್ರ_t
      sampled =
        libcrux_ml_dsa_simd_portable_rejection_sample_less_than_eta_equals_4_65(random_ಬೈಟುಗಳು,
          Eurydice_array_ಗಮ್ಯ_subslice_from_mut_11(ಹೊರಹೋಗು, sampled_coefficients[0U]));
      sampled_coefficients[0U] += sampled;
      ಆದರೆ (sampled_coefficients[0U] >= LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_ಒಳ_RING_ELEMENT)
      {
        ಮುಗಿದ = true;
      }
    }
  }
  ಹಿಂತಿರುಗಿ ಮುಗಿದ;
}

/**
A monomorphic instance of libcrux_ml_dsa.sample.rejection_sample_less_than_eta_equals_2
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE bool
libcrux_ml_dsa_sample_rejection_sample_less_than_eta_equals_2_37(
  Eurydice_borrow_ತುಂಡು_u8 randomness,
  ಗಾತ್ರ_t *sampled_coefficients,
  Eurydice_arr_d0 *ಹೊರಹೋಗು
)
{
  bool ಮುಗಿದ = false;
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < randomness.meta / (ಗಾತ್ರ_t)4U; i++)
  {
    ಗಾತ್ರ_t _cloop_i = i;
    Eurydice_borrow_ತುಂಡು_u8
    random_ಬೈಟುಗಳು =
      Eurydice_ತುಂಡು_subslice_shared_c8(randomness,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ಆರಂಭ = _cloop_i * (ಗಾತ್ರ_t)4U,
            .ಕೊನೆ = _cloop_i * (ಗಾತ್ರ_t)4U + (ಗಾತ್ರ_t)4U
          }
        ));
    ಆದರೆ (!ಮುಗಿದ)
    {
      ಗಾತ್ರ_t
      sampled =
        libcrux_ml_dsa_simd_portable_rejection_sample_less_than_eta_equals_2_65(random_ಬೈಟುಗಳು,
          Eurydice_array_ಗಮ್ಯ_subslice_from_mut_11(ಹೊರಹೋಗು, sampled_coefficients[0U]));
      sampled_coefficients[0U] += sampled;
      ಆದರೆ (sampled_coefficients[0U] >= LIBCRUX_ML_DSA_CONSTANTS_COEFFICIENTS_ಒಳ_RING_ELEMENT)
      {
        ಮುಗಿದ = true;
      }
    }
  }
  ಹಿಂತಿರುಗಿ ಮುಗಿದ;
}

/**
A monomorphic instance of libcrux_ml_dsa.sample.rejection_sample_less_than_eta
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE bool
libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(
  libcrux_ml_dsa_constants_Eta eta,
  Eurydice_borrow_ತುಂಡು_u8 randomness,
  ಗಾತ್ರ_t *sampled,
  Eurydice_arr_d0 *ಹೊರಹೋಗು
)
{
  ಆಯ್ಕೆ (eta)
  {
    ಸ್ಥಿತಿ libcrux_ml_dsa_constants_Eta_Two:
      {
        ನಿಲ್ಲಿಸು;
      }
    ಸ್ಥಿತಿ libcrux_ml_dsa_constants_Eta_Four:
      {
        ಹಿಂತಿರುಗಿ
          libcrux_ml_dsa_sample_rejection_sample_less_than_eta_equals_4_37(randomness,
            sampled,
            ಹೊರಹೋಗು);
      }
    ಪೂರ್ವನಿಯೋಜಿತ:
      {
        KRML_HOST_EPRINTF("KaRaMeL incomplete match at %s:%d\n", __FILE__, __LINE__);
        KRML_HOST_EXIT(253U);
      }
  }
  ಹಿಂತಿರುಗಿ
    libcrux_ml_dsa_sample_rejection_sample_less_than_eta_equals_2_37(randomness,
      sampled,
      ಹೊರಹೋಗು);
}

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_MLDSA87_ಕೀಲಿ_Pair_s
{
  Eurydice_arr_e2 signing_ಕೀಲಿ;
  Eurydice_arr_43 verification_ಕೀಲಿ;
}
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_MLDSA87_ಕೀಲಿ_Pair;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_MLDSA65_ಕೀಲಿ_Pair_s
{
  Eurydice_arr_24 signing_ಕೀಲಿ;
  Eurydice_arr_29 verification_ಕೀಲಿ;
}
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_MLDSA65_ಕೀಲಿ_Pair;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_MLDSA44_ಕೀಲಿ_Pair_s
{
  Eurydice_arr_10 signing_ಕೀಲಿ;
  Eurydice_arr_02 verification_ಕೀಲಿ;
}
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_MLDSA44_ಕೀಲಿ_Pair;

#ಆದರೆ defined(__cplusplus)
}
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿಸು libcrux_mldsa_core_H_DEFINED
#ಆದರೆ_ಅಂತ್ಯ /* libcrux_mldsa_core_H */

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


#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ libcrux_ct_ops_H
#ವ್ಯಾಖ್ಯಾನಿಸು libcrux_ct_ops_H



#ಆದರೆ defined(__cplusplus)
ಬಾಹ್ಯ "C" {
#ಆದರೆ_ಅಂತ್ಯ


/**
 Return 1 if `value` is not zero and 0 otherwise.
*/
ಸ್ಥಿರ KRML_NOINLINE uint8_t libcrux_ml_kem_constant_ಸಮಯ_ops_inz(uint8_t ಮೌಲ್ಯ)
{
  uint16_t value0 = (uint16_t)(uint32_t)ಮೌಲ್ಯ;
  uint8_t ಫಲಿತಾಂಶ = (uint8_t)((uint32_t)core_ಅಂಕೆ_u16_wrapping_ಕೂಡಿಸು(~value0, 1U) >> 8U & 0xFFFFU);
  ಹಿಂತಿರುಗಿ (uint32_t)ಫಲಿತಾಂಶ & 1U;
}

ಸ್ಥಿರ KRML_NOINLINE uint8_t libcrux_ml_kem_constant_ಸಮಯ_ops_is_non_zero(uint8_t ಮೌಲ್ಯ)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_constant_ಸಮಯ_ops_inz(ಮೌಲ್ಯ);
}

/**
 Return 1 if the bytes of `lhs` and `rhs` do not exactly
 match and 0 otherwise.
*/
ಸ್ಥಿರ KRML_NOINLINE uint8_t
libcrux_ml_kem_constant_ಸಮಯ_ops_compare(
  Eurydice_borrow_ತುಂಡು_u8 lhs,
  Eurydice_borrow_ತುಂಡು_u8 rhs
)
{
  uint8_t r = 0U;
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < lhs.meta; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    uint8_t nr = (uint32_t)r | ((uint32_t)lhs.ptr[i0] ^ (uint32_t)rhs.ptr[i0]);
    r = nr;
  }
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_constant_ಸಮಯ_ops_is_non_zero(r);
}

ಸ್ಥಿರ KRML_NOINLINE uint8_t
libcrux_ml_kem_constant_ಸಮಯ_ops_compare_ciphertexts_ಒಳ_constant_ಸಮಯ(
  Eurydice_borrow_ತುಂಡು_u8 lhs,
  Eurydice_borrow_ತುಂಡು_u8 rhs
)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_constant_ಸಮಯ_ops_compare(lhs, rhs);
}

/**
 If `selector` is not zero, return the bytes in `rhs`; return the bytes in
 `lhs` otherwise.
*/
ಸ್ಥಿರ KRML_NOINLINE Eurydice_arr_ec
libcrux_ml_kem_constant_ಸಮಯ_ops_select_ct(
  Eurydice_borrow_ತುಂಡು_u8 lhs,
  Eurydice_borrow_ತುಂಡು_u8 rhs,
  uint8_t selector
)
{
  uint8_t
  ಮುಖವಾಡ = core_ಅಂಕೆ_u8_wrapping_sub(libcrux_ml_kem_constant_ಸಮಯ_ops_is_non_zero(selector), 1U);
  Eurydice_arr_ec ಹೊರಹೋಗು = { .ದತ್ತಾಂಶ = { 0U } };
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_ಗಾತ್ರ; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    uint8_t
    outi =
      ((uint32_t)lhs.ptr[i0] & (uint32_t)ಮುಖವಾಡ) | ((uint32_t)rhs.ptr[i0] & (~(uint32_t)ಮುಖವಾಡ & 0xFFU));
    ಹೊರಹೋಗು.ದತ್ತಾಂಶ[i0] = outi;
  }
  ಹಿಂತಿರುಗಿ ಹೊರಹೋಗು;
}

ಸ್ಥಿರ KRML_NOINLINE Eurydice_arr_ec
libcrux_ml_kem_constant_ಸಮಯ_ops_select_shared_secret_ಒಳ_constant_ಸಮಯ(
  Eurydice_borrow_ತುಂಡು_u8 lhs,
  Eurydice_borrow_ತುಂಡು_u8 rhs,
  uint8_t selector
)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_constant_ಸಮಯ_ops_select_ct(lhs, rhs, selector);
}

ಸ್ಥಿರ KRML_NOINLINE Eurydice_arr_ec
libcrux_ml_kem_constant_ಸಮಯ_ops_compare_ciphertexts_select_shared_secret_ಒಳ_constant_ಸಮಯ(
  Eurydice_borrow_ತುಂಡು_u8 lhs_c,
  Eurydice_borrow_ತುಂಡು_u8 rhs_c,
  Eurydice_borrow_ತುಂಡು_u8 lhs_s,
  Eurydice_borrow_ತುಂಡು_u8 rhs_s
)
{
  uint8_t
  selector = libcrux_ml_kem_constant_ಸಮಯ_ops_compare_ciphertexts_ಒಳ_constant_ಸಮಯ(lhs_c, rhs_c);
  ಹಿಂತಿರುಗಿ
    libcrux_ml_kem_constant_ಸಮಯ_ops_select_shared_secret_ಒಳ_constant_ಸಮಯ(lhs_s,
      rhs_s,
      selector);
}

#ಆದರೆ defined(__cplusplus)
}
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿಸು libcrux_ct_ops_H_DEFINED
#ಆದರೆ_ಅಂತ್ಯ /* libcrux_ct_ops_H */

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


#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ libcrux_mldsa_portable_H
#ವ್ಯಾಖ್ಯಾನಿಸು libcrux_mldsa_portable_H



#ಆದರೆ defined(__cplusplus)
ಬಾಹ್ಯ "C" {
#ಆದರೆ_ಅಂತ್ಯ


ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ libcrux_ml_dsa_hash_functions_portable_Shake128X4_s
{
  Eurydice_arr_7c state0;
  Eurydice_arr_7c state1;
  Eurydice_arr_7c state2;
  Eurydice_arr_7c state3;
}
libcrux_ml_dsa_hash_functions_portable_Shake128X4;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ libcrux_sha3_portable_KeccakState libcrux_ml_dsa_hash_functions_portable_Shake256;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ libcrux_ml_dsa_hash_functions_portable_Shake256X4_s
{
  Eurydice_arr_7c state0;
  Eurydice_arr_7c state1;
  Eurydice_arr_7c state2;
  Eurydice_arr_7c state3;
}
libcrux_ml_dsa_hash_functions_portable_Shake256X4;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ libcrux_sha3_portable_incremental_Shake256Xof
libcrux_ml_dsa_hash_functions_portable_Shake256Xof;

ಸ್ಥಿರ KRML_MUSTINLINE libcrux_ml_dsa_hash_functions_portable_Shake128X4
libcrux_ml_dsa_hash_functions_portable_init_absorb(
  Eurydice_borrow_ತುಂಡು_u8 input0,
  Eurydice_borrow_ತುಂಡು_u8 input1,
  Eurydice_borrow_ತುಂಡು_u8 input2,
  Eurydice_borrow_ತುಂಡು_u8 input3
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
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(libcrux_ml_dsa_hash_functions_portable_Shake128X4){
        .state0 = state0,
        .state1 = state1,
        .state2 = state2,
        .state3 = state3
      }
    );
}

ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_7c
libcrux_ml_dsa_hash_functions_portable_init_absorb_final_shake256(
  Eurydice_borrow_ತುಂಡು_u8 ಒಳಹರಿವು
)
{
  Eurydice_arr_7c state = libcrux_sha3_portable_incremental_shake256_init();
  libcrux_sha3_portable_incremental_shake256_absorb_final(&state, ಒಳಹರಿವು);
  ಹಿಂತಿರುಗಿ state;
}

ಸ್ಥಿರ KRML_MUSTINLINE libcrux_ml_dsa_hash_functions_portable_Shake256X4
libcrux_ml_dsa_hash_functions_portable_init_absorb_x4(
  Eurydice_borrow_ತುಂಡು_u8 input0,
  Eurydice_borrow_ತುಂಡು_u8 input1,
  Eurydice_borrow_ತುಂಡು_u8 input2,
  Eurydice_borrow_ತುಂಡು_u8 input3
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
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(libcrux_ml_dsa_hash_functions_portable_Shake256X4){
        .state0 = state0,
        .state1 = state1,
        .state2 = state2,
        .state3 = state3
      }
    );
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_hash_functions_portable_shake128(
  Eurydice_borrow_ತುಂಡು_u8 ಒಳಹರಿವು,
  Eurydice_mut_borrow_ತುಂಡು_u8 ಹೊರಹೋಗು
)
{
  libcrux_sha3_portable_shake128(ಹೊರಹೋಗು, ಒಳಹರಿವು);
}

ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_ff
libcrux_ml_dsa_hash_functions_portable_squeeze_ಮೊದಲ_ಖಂಡ_shake256(Eurydice_arr_7c *state)
{
  Eurydice_arr_ff ಹೊರಹೋಗು = { .ದತ್ತಾಂಶ = { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_ಮೊದಲ_ಖಂಡ(state,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_58(&ಹೊರಹೋಗು));
  ಹಿಂತಿರುಗಿ ಹೊರಹೋಗು;
}

ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_ff_x4
libcrux_ml_dsa_hash_functions_portable_squeeze_ಮೊದಲ_ಖಂಡ_x4(
  libcrux_ml_dsa_hash_functions_portable_Shake256X4 *state
)
{
  Eurydice_arr_ff out0 = { .ದತ್ತಾಂಶ = { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_ಮೊದಲ_ಖಂಡ(&state->state0,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_58(&out0));
  Eurydice_arr_ff out1 = { .ದತ್ತಾಂಶ = { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_ಮೊದಲ_ಖಂಡ(&state->state1,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_58(&out1));
  Eurydice_arr_ff out2 = { .ದತ್ತಾಂಶ = { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_ಮೊದಲ_ಖಂಡ(&state->state2,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_58(&out2));
  Eurydice_arr_ff out3 = { .ದತ್ತಾಂಶ = { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_ಮೊದಲ_ಖಂಡ(&state->state3,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_58(&out3));
  ಹಿಂತಿರುಗಿ
    (KRML_CLITERAL(Eurydice_arr_ff_x4){ .fst = out0, .snd = out1, .thd = out2, .f3 = out3 });
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_hash_functions_portable_squeeze_ಮೊದಲ_five_ಖಂಡಗಳು(
  libcrux_ml_dsa_hash_functions_portable_Shake128X4 *state,
  Eurydice_arr_d10 *out0,
  Eurydice_arr_d10 *out1,
  Eurydice_arr_d10 *out2,
  Eurydice_arr_d10 *out3
)
{
  libcrux_sha3_portable_incremental_shake128_squeeze_ಮೊದಲ_five_ಖಂಡಗಳು(&state->state0,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_4c(out0));
  libcrux_sha3_portable_incremental_shake128_squeeze_ಮೊದಲ_five_ಖಂಡಗಳು(&state->state1,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_4c(out1));
  libcrux_sha3_portable_incremental_shake128_squeeze_ಮೊದಲ_five_ಖಂಡಗಳು(&state->state2,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_4c(out2));
  libcrux_sha3_portable_incremental_shake128_squeeze_ಮೊದಲ_five_ಖಂಡಗಳು(&state->state3,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_4c(out3));
}

ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_c5_x4
libcrux_ml_dsa_hash_functions_portable_squeeze_ಮುಂದಿನ_ಖಂಡ(
  libcrux_ml_dsa_hash_functions_portable_Shake128X4 *state
)
{
  Eurydice_arr_c5 out0 = { .ದತ್ತಾಂಶ = { 0U } };
  libcrux_sha3_portable_incremental_shake128_squeeze_ಮುಂದಿನ_ಖಂಡ(&state->state0,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_2c(&out0));
  Eurydice_arr_c5 out1 = { .ದತ್ತಾಂಶ = { 0U } };
  libcrux_sha3_portable_incremental_shake128_squeeze_ಮುಂದಿನ_ಖಂಡ(&state->state1,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_2c(&out1));
  Eurydice_arr_c5 out2 = { .ದತ್ತಾಂಶ = { 0U } };
  libcrux_sha3_portable_incremental_shake128_squeeze_ಮುಂದಿನ_ಖಂಡ(&state->state2,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_2c(&out2));
  Eurydice_arr_c5 out3 = { .ದತ್ತಾಂಶ = { 0U } };
  libcrux_sha3_portable_incremental_shake128_squeeze_ಮುಂದಿನ_ಖಂಡ(&state->state3,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_2c(&out3));
  ಹಿಂತಿರುಗಿ
    (KRML_CLITERAL(Eurydice_arr_c5_x4){ .fst = out0, .snd = out1, .thd = out2, .f3 = out3 });
}

ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_ff
libcrux_ml_dsa_hash_functions_portable_squeeze_ಮುಂದಿನ_ಖಂಡ_shake256(Eurydice_arr_7c *state)
{
  Eurydice_arr_ff ಹೊರಹೋಗು = { .ದತ್ತಾಂಶ = { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_ಮುಂದಿನ_ಖಂಡ(state,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_58(&ಹೊರಹೋಗು));
  ಹಿಂತಿರುಗಿ ಹೊರಹೋಗು;
}

ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_ff_x4
libcrux_ml_dsa_hash_functions_portable_squeeze_ಮುಂದಿನ_ಖಂಡ_x4(
  libcrux_ml_dsa_hash_functions_portable_Shake256X4 *state
)
{
  Eurydice_arr_ff out0 = { .ದತ್ತಾಂಶ = { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_ಮುಂದಿನ_ಖಂಡ(&state->state0,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_58(&out0));
  Eurydice_arr_ff out1 = { .ದತ್ತಾಂಶ = { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_ಮುಂದಿನ_ಖಂಡ(&state->state1,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_58(&out1));
  Eurydice_arr_ff out2 = { .ದತ್ತಾಂಶ = { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_ಮುಂದಿನ_ಖಂಡ(&state->state2,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_58(&out2));
  Eurydice_arr_ff out3 = { .ದತ್ತಾಂಶ = { 0U } };
  libcrux_sha3_portable_incremental_shake256_squeeze_ಮುಂದಿನ_ಖಂಡ(&state->state3,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_58(&out3));
  ಹಿಂತಿರುಗಿ
    (KRML_CLITERAL(Eurydice_arr_ff_x4){ .fst = out0, .snd = out1, .thd = out2, .f3 = out3 });
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake128::Xof for libcrux_ml_dsa::hash_functions::portable::Shake128}
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_hash_functions_portable_shake128_7b(
  Eurydice_borrow_ತುಂಡು_u8 ಒಳಹರಿವು,
  Eurydice_mut_borrow_ತುಂಡು_u8 ಹೊರಹೋಗು
)
{
  libcrux_ml_dsa_hash_functions_portable_shake128(ಒಳಹರಿವು, ಹೊರಹೋಗು);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake128::XofX4 for libcrux_ml_dsa::hash_functions::portable::Shake128X4}
*/
ಸ್ಥಿರ KRML_MUSTINLINE libcrux_ml_dsa_hash_functions_portable_Shake128X4
libcrux_ml_dsa_hash_functions_portable_init_absorb_11(
  Eurydice_borrow_ತುಂಡು_u8 input0,
  Eurydice_borrow_ತುಂಡು_u8 input1,
  Eurydice_borrow_ತುಂಡು_u8 input2,
  Eurydice_borrow_ತುಂಡು_u8 input3
)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_dsa_hash_functions_portable_init_absorb(input0, input1, input2, input3);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake128::XofX4 for libcrux_ml_dsa::hash_functions::portable::Shake128X4}
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_hash_functions_portable_squeeze_ಮೊದಲ_five_ಖಂಡಗಳು_11(
  libcrux_ml_dsa_hash_functions_portable_Shake128X4 *self,
  Eurydice_arr_d10 *out0,
  Eurydice_arr_d10 *out1,
  Eurydice_arr_d10 *out2,
  Eurydice_arr_d10 *out3
)
{
  libcrux_ml_dsa_hash_functions_portable_squeeze_ಮೊದಲ_five_ಖಂಡಗಳು(self, out0, out1, out2, out3);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake128::XofX4 for libcrux_ml_dsa::hash_functions::portable::Shake128X4}
*/
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_c5_x4
libcrux_ml_dsa_hash_functions_portable_squeeze_ಮುಂದಿನ_ಖಂಡ_11(
  libcrux_ml_dsa_hash_functions_portable_Shake128X4 *self
)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_dsa_hash_functions_portable_squeeze_ಮುಂದಿನ_ಖಂಡ(self);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::DsaXof for libcrux_ml_dsa::hash_functions::portable::Shake256}
*/
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_7c
libcrux_ml_dsa_hash_functions_portable_init_absorb_final_61(Eurydice_borrow_ತುಂಡು_u8 ಒಳಹರಿವು)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_dsa_hash_functions_portable_init_absorb_final_shake256(ಒಳಹರಿವು);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::DsaXof for libcrux_ml_dsa::hash_functions::portable::Shake256}
*/
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_ff
libcrux_ml_dsa_hash_functions_portable_squeeze_ಮೊದಲ_ಖಂಡ_61(Eurydice_arr_7c *self)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_dsa_hash_functions_portable_squeeze_ಮೊದಲ_ಖಂಡ_shake256(self);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::DsaXof for libcrux_ml_dsa::hash_functions::portable::Shake256}
*/
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_ff
libcrux_ml_dsa_hash_functions_portable_squeeze_ಮುಂದಿನ_ಖಂಡ_61(Eurydice_arr_7c *self)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_dsa_hash_functions_portable_squeeze_ಮುಂದಿನ_ಖಂಡ_shake256(self);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::Xof for libcrux_ml_dsa::hash_functions::portable::Shake256Xof}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_ml_dsa_hash_functions_portable_absorb_26(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *self,
  Eurydice_borrow_ತುಂಡು_u8 ಒಳಹರಿವು
)
{
  libcrux_sha3_portable_incremental_absorb_42(self, ಒಳಹರಿವು);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::Xof for libcrux_ml_dsa::hash_functions::portable::Shake256Xof}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_ml_dsa_hash_functions_portable_absorb_final_26(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *self,
  Eurydice_borrow_ತುಂಡು_u8 ಒಳಹರಿವು
)
{
  libcrux_sha3_portable_incremental_absorb_final_42(self, ಒಳಹರಿವು);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::Xof for libcrux_ml_dsa::hash_functions::portable::Shake256Xof}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
libcrux_ml_dsa_hash_functions_portable_init_26(ಶೂನ್ಯ)
{
  ಹಿಂತಿರುಗಿ libcrux_sha3_portable_incremental_new_42();
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::Xof for libcrux_ml_dsa::hash_functions::portable::Shake256Xof}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_ml_dsa_hash_functions_portable_squeeze_26(
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *self,
  Eurydice_mut_borrow_ತುಂಡು_u8 ಹೊರಹೋಗು
)
{
  libcrux_sha3_portable_incremental_squeeze_42(self, ಹೊರಹೋಗು);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::XofX4 for libcrux_ml_dsa::hash_functions::portable::Shake256X4}
*/
ಸ್ಥಿರ KRML_MUSTINLINE libcrux_ml_dsa_hash_functions_portable_Shake256X4
libcrux_ml_dsa_hash_functions_portable_init_absorb_x4_9b(
  Eurydice_borrow_ತುಂಡು_u8 input0,
  Eurydice_borrow_ತುಂಡು_u8 input1,
  Eurydice_borrow_ತುಂಡು_u8 input2,
  Eurydice_borrow_ತುಂಡು_u8 input3
)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_dsa_hash_functions_portable_init_absorb_x4(input0, input1, input2, input3);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::XofX4 for libcrux_ml_dsa::hash_functions::portable::Shake256X4}
*/
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_ff_x4
libcrux_ml_dsa_hash_functions_portable_squeeze_ಮೊದಲ_ಖಂಡ_x4_9b(
  libcrux_ml_dsa_hash_functions_portable_Shake256X4 *self
)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_dsa_hash_functions_portable_squeeze_ಮೊದಲ_ಖಂಡ_x4(self);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::XofX4 for libcrux_ml_dsa::hash_functions::portable::Shake256X4}
*/
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_ff_x4
libcrux_ml_dsa_hash_functions_portable_squeeze_ಮುಂದಿನ_ಖಂಡ_x4_9b(
  libcrux_ml_dsa_hash_functions_portable_Shake256X4 *self
)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_dsa_hash_functions_portable_squeeze_ಮುಂದಿನ_ಖಂಡ_x4(self);
}

/**
A monomorphic instance of libcrux_ml_dsa.sample.sample_four_error_ring_elements
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_sample_sample_four_error_ring_elements_29(
  libcrux_ml_dsa_constants_Eta eta,
  Eurydice_borrow_ತುಂಡು_u8 ಬೀಜ,
  uint16_t ಆರಂಭ_ಸೂಚ್ಯಂಕ,
  Eurydice_dst_ref_mut_44 re
)
{
  Eurydice_arr_91 seed0 = libcrux_ml_dsa_sample_ಕೂಡಿಸು_error_domain_separator(ಬೀಜ, ಆರಂಭ_ಸೂಚ್ಯಂಕ);
  Eurydice_arr_91
  seed1 = libcrux_ml_dsa_sample_ಕೂಡಿಸು_error_domain_separator(ಬೀಜ, (uint32_t)ಆರಂಭ_ಸೂಚ್ಯಂಕ + 1U);
  Eurydice_arr_91
  seed2 = libcrux_ml_dsa_sample_ಕೂಡಿಸು_error_domain_separator(ಬೀಜ, (uint32_t)ಆರಂಭ_ಸೂಚ್ಯಂಕ + 2U);
  Eurydice_arr_91
  seed3 = libcrux_ml_dsa_sample_ಕೂಡಿಸು_error_domain_separator(ಬೀಜ, (uint32_t)ಆರಂಭ_ಸೂಚ್ಯಂಕ + 3U);
  libcrux_ml_dsa_hash_functions_portable_Shake256X4
  state =
    libcrux_ml_dsa_hash_functions_portable_init_absorb_x4_9b(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_f1(&seed0),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_f1(&seed1),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_f1(&seed2),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_f1(&seed3));
  Eurydice_arr_ff_x4
  randomnesses0 = libcrux_ml_dsa_hash_functions_portable_squeeze_ಮೊದಲ_ಖಂಡ_x4_9b(&state);
  Eurydice_arr_930
  ಹೊರಹೋಗು =
    { .ದತ್ತಾಂಶ = { { .ದತ್ತಾಂಶ = { 0U } }, { .ದತ್ತಾಂಶ = { 0U } }, { .ದತ್ತಾಂಶ = { 0U } }, { .ದತ್ತಾಂಶ = { 0U } } } };
  ಗಾತ್ರ_t sampled0 = (ಗಾತ್ರ_t)0U;
  ಗಾತ್ರ_t sampled1 = (ಗಾತ್ರ_t)0U;
  ಗಾತ್ರ_t sampled2 = (ಗಾತ್ರ_t)0U;
  ಗಾತ್ರ_t sampled3 = (ಗಾತ್ರ_t)0U;
  libcrux_ml_dsa_constants_Eta uu____0 = eta;
  bool
  done0 =
    libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____0,
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_58(&randomnesses0.fst),
      &sampled0,
      ಹೊರಹೋಗು.ದತ್ತಾಂಶ);
  libcrux_ml_dsa_constants_Eta uu____1 = eta;
  bool
  done1 =
    libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____1,
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_58(&randomnesses0.snd),
      &sampled1,
      &ಹೊರಹೋಗು.ದತ್ತಾಂಶ[1U]);
  libcrux_ml_dsa_constants_Eta uu____2 = eta;
  bool
  done2 =
    libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____2,
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_58(&randomnesses0.thd),
      &sampled2,
      &ಹೊರಹೋಗು.ದತ್ತಾಂಶ[2U]);
  libcrux_ml_dsa_constants_Eta uu____3 = eta;
  bool
  done3 =
    libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____3,
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_58(&randomnesses0.f3),
      &sampled3,
      &ಹೊರಹೋಗು.ದತ್ತಾಂಶ[3U]);
  ಆಗ (true)
  {
    ಆದರೆ (done0)
    {
      ಆದರೆ (done1)
      {
        ಆದರೆ (done2)
        {
          ಆದರೆ (done3)
          {
            ನಿಲ್ಲಿಸು;
          }
          ಇಲ್ಲದಿದ್ದರೆ
          {
            Eurydice_arr_ff_x4
            randomnesses = libcrux_ml_dsa_hash_functions_portable_squeeze_ಮುಂದಿನ_ಖಂಡ_x4_9b(&state);
            ಆದರೆ (!done0)
            {
              libcrux_ml_dsa_constants_Eta uu____4 = eta;
              done0 =
                libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____4,
                  Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_58(&randomnesses.fst),
                  &sampled0,
                  ಹೊರಹೋಗು.ದತ್ತಾಂಶ);
            }
            ಆದರೆ (!done1)
            {
              libcrux_ml_dsa_constants_Eta uu____5 = eta;
              done1 =
                libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____5,
                  Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_58(&randomnesses.snd),
                  &sampled1,
                  &ಹೊರಹೋಗು.ದತ್ತಾಂಶ[1U]);
            }
            ಆದರೆ (!done2)
            {
              libcrux_ml_dsa_constants_Eta uu____6 = eta;
              done2 =
                libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____6,
                  Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_58(&randomnesses.thd),
                  &sampled2,
                  &ಹೊರಹೋಗು.ದತ್ತಾಂಶ[2U]);
            }
            ಆದರೆ (!done3)
            {
              libcrux_ml_dsa_constants_Eta uu____7 = eta;
              done3 =
                libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____7,
                  Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_58(&randomnesses.f3),
                  &sampled3,
                  &ಹೊರಹೋಗು.ದತ್ತಾಂಶ[3U]);
            }
          }
        }
        ಇಲ್ಲದಿದ್ದರೆ
        {
          Eurydice_arr_ff_x4
          randomnesses = libcrux_ml_dsa_hash_functions_portable_squeeze_ಮುಂದಿನ_ಖಂಡ_x4_9b(&state);
          ಆದರೆ (!done0)
          {
            libcrux_ml_dsa_constants_Eta uu____8 = eta;
            done0 =
              libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____8,
                Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_58(&randomnesses.fst),
                &sampled0,
                ಹೊರಹೋಗು.ದತ್ತಾಂಶ);
          }
          ಆದರೆ (!done1)
          {
            libcrux_ml_dsa_constants_Eta uu____9 = eta;
            done1 =
              libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____9,
                Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_58(&randomnesses.snd),
                &sampled1,
                &ಹೊರಹೋಗು.ದತ್ತಾಂಶ[1U]);
          }
          ಆದರೆ (!done2)
          {
            libcrux_ml_dsa_constants_Eta uu____10 = eta;
            done2 =
              libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____10,
                Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_58(&randomnesses.thd),
                &sampled2,
                &ಹೊರಹೋಗು.ದತ್ತಾಂಶ[2U]);
          }
          ಆದರೆ (!done3)
          {
            libcrux_ml_dsa_constants_Eta uu____11 = eta;
            done3 =
              libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____11,
                Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_58(&randomnesses.f3),
                &sampled3,
                &ಹೊರಹೋಗು.ದತ್ತಾಂಶ[3U]);
          }
        }
      }
      ಇಲ್ಲದಿದ್ದರೆ
      {
        Eurydice_arr_ff_x4
        randomnesses = libcrux_ml_dsa_hash_functions_portable_squeeze_ಮುಂದಿನ_ಖಂಡ_x4_9b(&state);
        ಆದರೆ (!done0)
        {
          libcrux_ml_dsa_constants_Eta uu____12 = eta;
          done0 =
            libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____12,
              Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_58(&randomnesses.fst),
              &sampled0,
              ಹೊರಹೋಗು.ದತ್ತಾಂಶ);
        }
        ಆದರೆ (!done1)
        {
          libcrux_ml_dsa_constants_Eta uu____13 = eta;
          done1 =
            libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____13,
              Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_58(&randomnesses.snd),
              &sampled1,
              &ಹೊರಹೋಗು.ದತ್ತಾಂಶ[1U]);
        }
        ಆದರೆ (!done2)
        {
          libcrux_ml_dsa_constants_Eta uu____14 = eta;
          done2 =
            libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____14,
              Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_58(&randomnesses.thd),
              &sampled2,
              &ಹೊರಹೋಗು.ದತ್ತಾಂಶ[2U]);
        }
        ಆದರೆ (!done3)
        {
          libcrux_ml_dsa_constants_Eta uu____15 = eta;
          done3 =
            libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____15,
              Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_58(&randomnesses.f3),
              &sampled3,
              &ಹೊರಹೋಗು.ದತ್ತಾಂಶ[3U]);
        }
      }
    }
    ಇಲ್ಲದಿದ್ದರೆ
    {
      Eurydice_arr_ff_x4
      randomnesses = libcrux_ml_dsa_hash_functions_portable_squeeze_ಮುಂದಿನ_ಖಂಡ_x4_9b(&state);
      ಆದರೆ (!done0)
      {
        libcrux_ml_dsa_constants_Eta uu____16 = eta;
        done0 =
          libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____16,
            Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_58(&randomnesses.fst),
            &sampled0,
            ಹೊರಹೋಗು.ದತ್ತಾಂಶ);
      }
      ಆದರೆ (!done1)
      {
        libcrux_ml_dsa_constants_Eta uu____17 = eta;
        done1 =
          libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____17,
            Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_58(&randomnesses.snd),
            &sampled1,
            &ಹೊರಹೋಗು.ದತ್ತಾಂಶ[1U]);
      }
      ಆದರೆ (!done2)
      {
        libcrux_ml_dsa_constants_Eta uu____18 = eta;
        done2 =
          libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____18,
            Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_58(&randomnesses.thd),
            &sampled2,
            &ಹೊರಹೋಗು.ದತ್ತಾಂಶ[2U]);
      }
      ಆದರೆ (!done3)
      {
        libcrux_ml_dsa_constants_Eta uu____19 = eta;
        done3 =
          libcrux_ml_dsa_sample_rejection_sample_less_than_eta_37(uu____19,
            Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_58(&randomnesses.f3),
            &sampled3,
            &ಹೊರಹೋಗು.ದತ್ತಾಂಶ[3U]);
      }
    }
  }
  ಗಾತ್ರ_t max0 = (ಗಾತ್ರ_t)(uint32_t)ಆರಂಭ_ಸೂಚ್ಯಂಕ + (ಗಾತ್ರ_t)4U;
  ಗಾತ್ರ_t max;
  ಆದರೆ (re.meta < max0)
  {
    max = re.meta;
  }
  ಇಲ್ಲದಿದ್ದರೆ
  {
    max = max0;
  }
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)(uint32_t)ಆರಂಭ_ಸೂಚ್ಯಂಕ; i < max; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    libcrux_ml_dsa_polynomial_from_i32_array_ff_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_2c0(&ಹೊರಹೋಗು.ದತ್ತಾಂಶ[i0
        % (ಗಾತ್ರ_t)4U]),
      &re.ptr[i0]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.samplex4.sample_s1_and_s2
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_samplex4_sample_s1_and_s2_29(
  libcrux_ml_dsa_constants_Eta eta,
  Eurydice_borrow_ತುಂಡು_u8 ಬೀಜ,
  Eurydice_dst_ref_mut_44 s1_s2
)
{
  ಗಾತ್ರ_t len = s1_s2.meta;
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < len / (ಗಾತ್ರ_t)4U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    libcrux_ml_dsa_sample_sample_four_error_ring_elements_29(eta,
      ಬೀಜ,
      4U * (uint32_t)(uint16_t)i0,
      s1_s2);
  }
  ಗಾತ್ರ_t remainder = len % (ಗಾತ್ರ_t)4U;
  ಆದರೆ (remainder != (ಗಾತ್ರ_t)0U)
  {
    libcrux_ml_dsa_sample_sample_four_error_ring_elements_29(eta,
      ಬೀಜ,
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_sample_sample_ಮೇಲೆ_ಗಮ್ಯ_four_ring_elements_flat_63(
  ಗಾತ್ರ_t columns,
  Eurydice_borrow_ತುಂಡು_u8 ಬೀಜ,
  Eurydice_dst_ref_mut_44 ಮಾತೃಕೆ,
  Eurydice_arr_d10 *rand_stack0,
  Eurydice_arr_d10 *rand_stack1,
  Eurydice_arr_d10 *rand_stack2,
  Eurydice_arr_d10 *rand_stack3,
  Eurydice_dst_ref_mut_33 tmp_ರಾಶಿ,
  ಗಾತ್ರ_t ಆರಂಭ_ಸೂಚ್ಯಂಕ,
  ಗಾತ್ರ_t elements_requested
)
{
  Eurydice_arr_31
  seed0 =
    libcrux_ml_dsa_sample_ಕೂಡಿಸು_domain_separator(ಬೀಜ,
      libcrux_ml_dsa_sample_sample_ಮೇಲೆ_ಗಮ್ಯ_four_ring_elements_flat_xy(ಆರಂಭ_ಸೂಚ್ಯಂಕ, columns));
  Eurydice_arr_31
  seed1 =
    libcrux_ml_dsa_sample_ಕೂಡಿಸು_domain_separator(ಬೀಜ,
      libcrux_ml_dsa_sample_sample_ಮೇಲೆ_ಗಮ್ಯ_four_ring_elements_flat_xy(ಆರಂಭ_ಸೂಚ್ಯಂಕ + (ಗಾತ್ರ_t)1U,
        columns));
  Eurydice_arr_31
  seed2 =
    libcrux_ml_dsa_sample_ಕೂಡಿಸು_domain_separator(ಬೀಜ,
      libcrux_ml_dsa_sample_sample_ಮೇಲೆ_ಗಮ್ಯ_four_ring_elements_flat_xy(ಆರಂಭ_ಸೂಚ್ಯಂಕ + (ಗಾತ್ರ_t)2U,
        columns));
  Eurydice_arr_31
  seed3 =
    libcrux_ml_dsa_sample_ಕೂಡಿಸು_domain_separator(ಬೀಜ,
      libcrux_ml_dsa_sample_sample_ಮೇಲೆ_ಗಮ್ಯ_four_ring_elements_flat_xy(ಆರಂಭ_ಸೂಚ್ಯಂಕ + (ಗಾತ್ರ_t)3U,
        columns));
  libcrux_ml_dsa_hash_functions_portable_Shake128X4
  state =
    libcrux_ml_dsa_hash_functions_portable_init_absorb_11(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_e9(&seed0),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_e9(&seed1),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_e9(&seed2),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_e9(&seed3));
  libcrux_ml_dsa_hash_functions_portable_squeeze_ಮೊದಲ_five_ಖಂಡಗಳು_11(&state,
    rand_stack0,
    rand_stack1,
    rand_stack2,
    rand_stack3);
  ಗಾತ್ರ_t sampled0 = (ಗಾತ್ರ_t)0U;
  ಗಾತ್ರ_t sampled1 = (ಗಾತ್ರ_t)0U;
  ಗಾತ್ರ_t sampled2 = (ಗಾತ್ರ_t)0U;
  ಗಾತ್ರ_t sampled3 = (ಗಾತ್ರ_t)0U;
  bool
  done0 =
    libcrux_ml_dsa_sample_rejection_sample_less_than_ಕ್ಷೇತ್ರ_modulus_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_4c(rand_stack0),
      &sampled0,
      tmp_ರಾಶಿ.ptr);
  bool
  done1 =
    libcrux_ml_dsa_sample_rejection_sample_less_than_ಕ್ಷೇತ್ರ_modulus_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_4c(rand_stack1),
      &sampled1,
      &tmp_ರಾಶಿ.ptr[1U]);
  bool
  done2 =
    libcrux_ml_dsa_sample_rejection_sample_less_than_ಕ್ಷೇತ್ರ_modulus_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_4c(rand_stack2),
      &sampled2,
      &tmp_ರಾಶಿ.ptr[2U]);
  bool
  done3 =
    libcrux_ml_dsa_sample_rejection_sample_less_than_ಕ್ಷೇತ್ರ_modulus_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_4c(rand_stack3),
      &sampled3,
      &tmp_ರಾಶಿ.ptr[3U]);
  ಆಗ (true)
  {
    ಆದರೆ (done0)
    {
      ಆದರೆ (done1)
      {
        ಆದರೆ (done2)
        {
          ಆದರೆ (done3)
          {
            ನಿಲ್ಲಿಸು;
          }
          ಇಲ್ಲದಿದ್ದರೆ
          {
            Eurydice_arr_c5_x4
            randomnesses = libcrux_ml_dsa_hash_functions_portable_squeeze_ಮುಂದಿನ_ಖಂಡ_11(&state);
            ಆದರೆ (!done0)
            {
              done0 =
                libcrux_ml_dsa_sample_rejection_sample_less_than_ಕ್ಷೇತ್ರ_modulus_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_2c(&randomnesses.fst),
                  &sampled0,
                  tmp_ರಾಶಿ.ptr);
            }
            ಆದರೆ (!done1)
            {
              done1 =
                libcrux_ml_dsa_sample_rejection_sample_less_than_ಕ್ಷೇತ್ರ_modulus_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_2c(&randomnesses.snd),
                  &sampled1,
                  &tmp_ರಾಶಿ.ptr[1U]);
            }
            ಆದರೆ (!done2)
            {
              done2 =
                libcrux_ml_dsa_sample_rejection_sample_less_than_ಕ್ಷೇತ್ರ_modulus_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_2c(&randomnesses.thd),
                  &sampled2,
                  &tmp_ರಾಶಿ.ptr[2U]);
            }
            ಆದರೆ (!done3)
            {
              done3 =
                libcrux_ml_dsa_sample_rejection_sample_less_than_ಕ್ಷೇತ್ರ_modulus_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_2c(&randomnesses.f3),
                  &sampled3,
                  &tmp_ರಾಶಿ.ptr[3U]);
            }
          }
        }
        ಇಲ್ಲದಿದ್ದರೆ
        {
          Eurydice_arr_c5_x4
          randomnesses = libcrux_ml_dsa_hash_functions_portable_squeeze_ಮುಂದಿನ_ಖಂಡ_11(&state);
          ಆದರೆ (!done0)
          {
            done0 =
              libcrux_ml_dsa_sample_rejection_sample_less_than_ಕ್ಷೇತ್ರ_modulus_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_2c(&randomnesses.fst),
                &sampled0,
                tmp_ರಾಶಿ.ptr);
          }
          ಆದರೆ (!done1)
          {
            done1 =
              libcrux_ml_dsa_sample_rejection_sample_less_than_ಕ್ಷೇತ್ರ_modulus_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_2c(&randomnesses.snd),
                &sampled1,
                &tmp_ರಾಶಿ.ptr[1U]);
          }
          ಆದರೆ (!done2)
          {
            done2 =
              libcrux_ml_dsa_sample_rejection_sample_less_than_ಕ್ಷೇತ್ರ_modulus_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_2c(&randomnesses.thd),
                &sampled2,
                &tmp_ರಾಶಿ.ptr[2U]);
          }
          ಆದರೆ (!done3)
          {
            done3 =
              libcrux_ml_dsa_sample_rejection_sample_less_than_ಕ್ಷೇತ್ರ_modulus_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_2c(&randomnesses.f3),
                &sampled3,
                &tmp_ರಾಶಿ.ptr[3U]);
          }
        }
      }
      ಇಲ್ಲದಿದ್ದರೆ
      {
        Eurydice_arr_c5_x4
        randomnesses = libcrux_ml_dsa_hash_functions_portable_squeeze_ಮುಂದಿನ_ಖಂಡ_11(&state);
        ಆದರೆ (!done0)
        {
          done0 =
            libcrux_ml_dsa_sample_rejection_sample_less_than_ಕ್ಷೇತ್ರ_modulus_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_2c(&randomnesses.fst),
              &sampled0,
              tmp_ರಾಶಿ.ptr);
        }
        ಆದರೆ (!done1)
        {
          done1 =
            libcrux_ml_dsa_sample_rejection_sample_less_than_ಕ್ಷೇತ್ರ_modulus_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_2c(&randomnesses.snd),
              &sampled1,
              &tmp_ರಾಶಿ.ptr[1U]);
        }
        ಆದರೆ (!done2)
        {
          done2 =
            libcrux_ml_dsa_sample_rejection_sample_less_than_ಕ್ಷೇತ್ರ_modulus_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_2c(&randomnesses.thd),
              &sampled2,
              &tmp_ರಾಶಿ.ptr[2U]);
        }
        ಆದರೆ (!done3)
        {
          done3 =
            libcrux_ml_dsa_sample_rejection_sample_less_than_ಕ್ಷೇತ್ರ_modulus_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_2c(&randomnesses.f3),
              &sampled3,
              &tmp_ರಾಶಿ.ptr[3U]);
        }
      }
    }
    ಇಲ್ಲದಿದ್ದರೆ
    {
      Eurydice_arr_c5_x4
      randomnesses = libcrux_ml_dsa_hash_functions_portable_squeeze_ಮುಂದಿನ_ಖಂಡ_11(&state);
      ಆದರೆ (!done0)
      {
        done0 =
          libcrux_ml_dsa_sample_rejection_sample_less_than_ಕ್ಷೇತ್ರ_modulus_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_2c(&randomnesses.fst),
            &sampled0,
            tmp_ರಾಶಿ.ptr);
      }
      ಆದರೆ (!done1)
      {
        done1 =
          libcrux_ml_dsa_sample_rejection_sample_less_than_ಕ್ಷೇತ್ರ_modulus_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_2c(&randomnesses.snd),
            &sampled1,
            &tmp_ರಾಶಿ.ptr[1U]);
      }
      ಆದರೆ (!done2)
      {
        done2 =
          libcrux_ml_dsa_sample_rejection_sample_less_than_ಕ್ಷೇತ್ರ_modulus_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_2c(&randomnesses.thd),
            &sampled2,
            &tmp_ರಾಶಿ.ptr[2U]);
      }
      ಆದರೆ (!done3)
      {
        done3 =
          libcrux_ml_dsa_sample_rejection_sample_less_than_ಕ್ಷೇತ್ರ_modulus_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_2c(&randomnesses.f3),
            &sampled3,
            &tmp_ರಾಶಿ.ptr[3U]);
      }
    }
  }
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < elements_requested; i++)
  {
    ಗಾತ್ರ_t k = i;
    libcrux_ml_dsa_polynomial_from_i32_array_ff_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_2c0(&tmp_ರಾಶಿ.ptr[k]),
      &ಮಾತೃಕೆ.ptr[ಆರಂಭ_ಸೂಚ್ಯಂಕ + k]);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.samplex4.matrix_flat
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_hash_functions_portable_Shake128X4
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_samplex4_ಮಾತೃಕೆ_flat_63(
  ಗಾತ್ರ_t columns,
  Eurydice_borrow_ತುಂಡು_u8 ಬೀಜ,
  Eurydice_dst_ref_mut_44 ಮಾತೃಕೆ
)
{
  Eurydice_arr_d10 rand_stack0 = { .ದತ್ತಾಂಶ = { 0U } };
  Eurydice_arr_d10 rand_stack1 = { .ದತ್ತಾಂಶ = { 0U } };
  Eurydice_arr_d10 rand_stack2 = { .ದತ್ತಾಂಶ = { 0U } };
  Eurydice_arr_d10 rand_stack3 = { .ದತ್ತಾಂಶ = { 0U } };
  Eurydice_arr_930
  tmp_ರಾಶಿ =
    { .ದತ್ತಾಂಶ = { { .ದತ್ತಾಂಶ = { 0U } }, { .ದತ್ತಾಂಶ = { 0U } }, { .ದತ್ತಾಂಶ = { 0U } }, { .ದತ್ತಾಂಶ = { 0U } } } };
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < ಮಾತೃಕೆ.meta / (ಗಾತ್ರ_t)4U + (ಗಾತ್ರ_t)1U; i++)
  {
    ಗಾತ್ರ_t ಆರಂಭ_ಸೂಚ್ಯಂಕ = i;
    ಗಾತ್ರ_t ಆರಂಭ_index0 = ಆರಂಭ_ಸೂಚ್ಯಂಕ * (ಗಾತ್ರ_t)4U;
    ಆದರೆ (ಆರಂಭ_index0 >= ಮಾತೃಕೆ.meta)
    {
      ನಿಲ್ಲಿಸು;
    }
    ಗಾತ್ರ_t elements_requested;
    ಆದರೆ (ಆರಂಭ_index0 + (ಗಾತ್ರ_t)4U <= ಮಾತೃಕೆ.meta)
    {
      elements_requested = (ಗಾತ್ರ_t)4U;
    }
    ಇಲ್ಲದಿದ್ದರೆ
    {
      elements_requested = ಮಾತೃಕೆ.meta - ಆರಂಭ_index0;
    }
    libcrux_ml_dsa_sample_sample_ಮೇಲೆ_ಗಮ್ಯ_four_ring_elements_flat_63(columns,
      ಬೀಜ,
      ಮಾತೃಕೆ,
      &rand_stack0,
      &rand_stack1,
      &rand_stack2,
      &rand_stack3,
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_7e(&tmp_ರಾಶಿ),
      ಆರಂಭ_index0,
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_ml_dsa_samplex4_portable_ಮಾತೃಕೆ_flat_a8_37(
  ಗಾತ್ರ_t columns,
  Eurydice_borrow_ತುಂಡು_u8 ಬೀಜ,
  Eurydice_dst_ref_mut_44 ಮಾತೃಕೆ
)
{
  libcrux_ml_dsa_samplex4_ಮಾತೃಕೆ_flat_63(columns, ಬೀಜ, ಮಾತೃಕೆ);
}

/**
A monomorphic instance of libcrux_ml_dsa.hash_functions.portable.shake256
with const generics
- OUTPUT_LENGTH= 64
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_hash_functions_portable_shake256_c9(
  Eurydice_borrow_ತುಂಡು_u8 ಒಳಹರಿವು,
  Eurydice_arr_c7 *ಹೊರಹೋಗು
)
{
  libcrux_sha3_portable_shake256(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_17(ಹೊರಹೋಗು), ಒಳಹರಿವು);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::DsaXof for libcrux_ml_dsa::hash_functions::portable::Shake256}
*/
/**
A monomorphic instance of libcrux_ml_dsa.hash_functions.portable.shake256_61
with const generics
- OUTPUT_LENGTH= 64
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_hash_functions_portable_shake256_61_c9(
  Eurydice_borrow_ತುಂಡು_u8 ಒಳಹರಿವು,
  Eurydice_arr_c7 *ಹೊರಹೋಗು
)
{
  libcrux_ml_dsa_hash_functions_portable_shake256_c9(ಒಳಹರಿವು, ಹೊರಹೋಗು);
}

/**
A monomorphic instance of libcrux_ml_dsa.encoding.signing_key.generate_serialized
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_hash_functions_portable_Shake256
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_encoding_signing_ಕೀಲಿ_generate_serialized_2e(
  libcrux_ml_dsa_constants_Eta eta,
  ಗಾತ್ರ_t error_ring_element_ಗಾತ್ರ,
  Eurydice_borrow_ತುಂಡು_u8 ಬೀಜ_ಮಾತೃಕೆ,
  Eurydice_borrow_ತುಂಡು_u8 ಬೀಜ_signing,
  Eurydice_borrow_ತುಂಡು_u8 verification_ಕೀಲಿ,
  Eurydice_dst_ref_shared_44 s1_2,
  Eurydice_dst_ref_shared_44 t0,
  Eurydice_mut_borrow_ತುಂಡು_u8 signing_ಕೀಲಿ_serialized
)
{
  ಗಾತ್ರ_t ಸ್ಥಾನಾಂತರ = (ಗಾತ್ರ_t)0U;
  Eurydice_ತುಂಡು_copy(Eurydice_ತುಂಡು_subslice_mut_c8(signing_ಕೀಲಿ_serialized,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .ಆರಂಭ = ಸ್ಥಾನಾಂತರ,
          .ಕೊನೆ = ಸ್ಥಾನಾಂತರ + LIBCRUX_ML_DSA_CONSTANTS_ಬೀಜ_FOR_A_ಗಾತ್ರ
        }
      )),
    ಬೀಜ_ಮಾತೃಕೆ,
    uint8_t);
  ಸ್ಥಾನಾಂತರ += LIBCRUX_ML_DSA_CONSTANTS_ಬೀಜ_FOR_A_ಗಾತ್ರ;
  Eurydice_ತುಂಡು_copy(Eurydice_ತುಂಡು_subslice_mut_c8(signing_ಕೀಲಿ_serialized,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .ಆರಂಭ = ಸ್ಥಾನಾಂತರ,
          .ಕೊನೆ = ಸ್ಥಾನಾಂತರ + LIBCRUX_ML_DSA_CONSTANTS_ಬೀಜ_FOR_SIGNING_ಗಾತ್ರ
        }
      )),
    ಬೀಜ_signing,
    uint8_t);
  ಸ್ಥಾನಾಂತರ += LIBCRUX_ML_DSA_CONSTANTS_ಬೀಜ_FOR_SIGNING_ಗಾತ್ರ;
  Eurydice_arr_c7 verification_ಕೀಲಿ_hash = { .ದತ್ತಾಂಶ = { 0U } };
  libcrux_ml_dsa_hash_functions_portable_shake256_61_c9(verification_ಕೀಲಿ,
    &verification_ಕೀಲಿ_hash);
  Eurydice_ತುಂಡು_copy(Eurydice_ತುಂಡು_subslice_mut_c8(signing_ಕೀಲಿ_serialized,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .ಆರಂಭ = ಸ್ಥಾನಾಂತರ,
          .ಕೊನೆ = ಸ್ಥಾನಾಂತರ + LIBCRUX_ML_DSA_CONSTANTS_ಬೈಟುಗಳು_FOR_VERIFICATION_ಕೀಲಿ_HASH
        }
      )),
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_17(&verification_ಕೀಲಿ_hash),
    uint8_t);
  ಸ್ಥಾನಾಂತರ += LIBCRUX_ML_DSA_CONSTANTS_ಬೈಟುಗಳು_FOR_VERIFICATION_ಕೀಲಿ_HASH;
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < s1_2.meta; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    libcrux_ml_dsa_encoding_error_serialize_37(eta,
      &s1_2.ptr[i0],
      Eurydice_ತುಂಡು_subslice_mut_c8(signing_ಕೀಲಿ_serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ಆರಂಭ = ಸ್ಥಾನಾಂತರ,
            .ಕೊನೆ = ಸ್ಥಾನಾಂತರ + error_ring_element_ಗಾತ್ರ
          }
        )));
    ಸ್ಥಾನಾಂತರ += error_ring_element_ಗಾತ್ರ;
  }
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < t0.meta; i++)
  {
    ಗಾತ್ರ_t _cloop_j = i;
    ಸ್ಥಿರಾಂಕ Eurydice_arr_a3 *ring_element = &t0.ptr[_cloop_j];
    libcrux_ml_dsa_encoding_t0_serialize_37(ring_element,
      Eurydice_ತುಂಡು_subslice_mut_c8(signing_ಕೀಲಿ_serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ಆರಂಭ = ಸ್ಥಾನಾಂತರ,
            .ಕೊನೆ = ಸ್ಥಾನಾಂತರ + LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_ದ_T0_S_ಗಾತ್ರ
          }
        )));
    ಸ್ಥಾನಾಂತರ += LIBCRUX_ML_DSA_CONSTANTS_RING_ELEMENT_ದ_T0_S_ಗಾತ್ರ;
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_44.generate_key_pair
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_generate_ಕೀಲಿ_pair_5a(
  Eurydice_arr_ec randomness,
  Eurydice_mut_borrow_ತುಂಡು_u8 signing_ಕೀಲಿ,
  Eurydice_mut_borrow_ತುಂಡು_u8 verification_ಕೀಲಿ
)
{
  Eurydice_arr_89 ಬೀಜ_expanded0 = { .ದತ್ತಾಂಶ = { 0U } };
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
  shake = libcrux_ml_dsa_hash_functions_portable_init_26();
  libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_01(&randomness));
  /* original Rust expression is not an lvalue in C */
  Eurydice_array_u8x2
  lvalue =
    {
      .ದತ್ತಾಂಶ = {
        (uint8_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A,
        (uint8_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_ಒಳ_A
      }
    };
  libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_82(&lvalue));
  libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_78(&ಬೀಜ_expanded0));
  Eurydice_borrow_ತುಂಡು_u8_x2
  uu____0 =
    Eurydice_ತುಂಡು_ವಿಭಜಿಸು_at(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_78(&ಬೀಜ_expanded0),
      LIBCRUX_ML_DSA_CONSTANTS_ಬೀಜ_FOR_A_ಗಾತ್ರ,
      uint8_t,
      Eurydice_borrow_ತುಂಡು_u8_x2);
  Eurydice_borrow_ತುಂಡು_u8 ಬೀಜ_for_a = uu____0.fst;
  Eurydice_borrow_ತುಂಡು_u8 ಬೀಜ_expanded = uu____0.snd;
  Eurydice_borrow_ತುಂಡು_u8_x2
  uu____1 =
    Eurydice_ತುಂಡು_ವಿಭಜಿಸು_at(ಬೀಜ_expanded,
      LIBCRUX_ML_DSA_CONSTANTS_ಬೀಜ_FOR_ERROR_VECTORS_ಗಾತ್ರ,
      uint8_t,
      Eurydice_borrow_ತುಂಡು_u8_x2);
  Eurydice_borrow_ತುಂಡು_u8 ಬೀಜ_for_error_vectors = uu____1.fst;
  Eurydice_borrow_ತುಂಡು_u8 ಬೀಜ_for_signing = uu____1.snd;
  Eurydice_arr_8f s1_s2;
  Eurydice_arr_a3 repeat_expression0[8U];
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)8U; i++)
  {
    repeat_expression0[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  ಸ್ಮರಣೆ_ನಕಲು(s1_s2.ದತ್ತಾಂಶ, repeat_expression0, (ಗಾತ್ರ_t)8U * ಗಾತ್ರ (Eurydice_arr_a3));
  libcrux_ml_dsa_samplex4_sample_s1_and_s2_29(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ETA,
    ಬೀಜ_for_error_vectors,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_20(&s1_s2));
  Eurydice_arr_9d t0;
  Eurydice_arr_a3 repeat_expression1[4U];
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)4U; i++)
  {
    repeat_expression1[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  ಸ್ಮರಣೆ_ನಕಲು(t0.ದತ್ತಾಂಶ, repeat_expression1, (ಗಾತ್ರ_t)4U * ಗಾತ್ರ (Eurydice_arr_a3));
  Eurydice_arr_2f a_as_ntt;
  Eurydice_arr_a3 repeat_expression2[16U];
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)16U; i++)
  {
    repeat_expression2[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  ಸ್ಮರಣೆ_ನಕಲು(a_as_ntt.ದತ್ತಾಂಶ, repeat_expression2, (ಗಾತ್ರ_t)16U * ಗಾತ್ರ (Eurydice_arr_a3));
  libcrux_ml_dsa_samplex4_portable_ಮಾತೃಕೆ_flat_a8_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_ಒಳ_A,
    ಬೀಜ_for_a,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_200(&a_as_ntt));
  Eurydice_arr_9d s1_ntt;
  Eurydice_arr_a3 repeat_expression3[4U];
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)4U; i++)
  {
    repeat_expression3[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  ಸ್ಮರಣೆ_ನಕಲು(s1_ntt.ದತ್ತಾಂಶ, repeat_expression3, (ಗಾತ್ರ_t)4U * ಗಾತ್ರ (Eurydice_arr_a3));
  Eurydice_ತುಂಡು_copy(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_201(&s1_ntt),
    Eurydice_array_ಗಮ್ಯ_subslice_shared_25(&s1_s2,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .ಆರಂಭ = (ಗಾತ್ರ_t)0U,
          .ಕೊನೆ = LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_ಒಳ_A
        }
      )),
    Eurydice_arr_a3);
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)4U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    libcrux_ml_dsa_ntt_ntt_37(&s1_ntt.ದತ್ತಾಂಶ[i0]);
  }
  libcrux_ml_dsa_ಮಾತೃಕೆ_compute_as1_plus_s2_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A,
    LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_ಒಳ_A,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_200(&a_as_ntt),
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_20(&s1_ntt),
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_200(&s1_s2),
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_201(&t0));
  Eurydice_arr_9d t1;
  Eurydice_arr_a3 repeat_ಅಭಿವ್ಯಕ್ತಿ[4U];
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)4U; i++)
  {
    repeat_ಅಭಿವ್ಯಕ್ತಿ[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  ಸ್ಮರಣೆ_ನಕಲು(t1.ದತ್ತಾಂಶ, repeat_ಅಭಿವ್ಯಕ್ತಿ, (ಗಾತ್ರ_t)4U * ಗಾತ್ರ (Eurydice_arr_a3));
  libcrux_ml_dsa_arithmetic_power2round_ಸದಿಶ_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_201(&t0),
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_201(&t1));
  libcrux_ml_dsa_encoding_verification_ಕೀಲಿ_generate_serialized_37(ಬೀಜ_for_a,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_20(&t1),
    verification_ಕೀಲಿ);
  libcrux_ml_dsa_encoding_signing_ಕೀಲಿ_generate_serialized_2e(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ETA,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_ERROR_RING_ELEMENT_ಗಾತ್ರ,
    ಬೀಜ_for_a,
    ಬೀಜ_for_signing,
    (
      KRML_CLITERAL(Eurydice_borrow_ತುಂಡು_u8){
        .ptr = verification_ಕೀಲಿ.ptr,
        .meta = verification_ಕೀಲಿ.meta
      }
    ),
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_200(&s1_s2),
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_20(&t0),
    signing_ಕೀಲಿ);
}

/**
 Generate key pair.
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_44_generate_ಕೀಲಿ_pair(
  Eurydice_arr_ec randomness,
  Eurydice_arr_10 *signing_ಕೀಲಿ,
  Eurydice_arr_02 *verification_ಕೀಲಿ
)
{
  libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_generate_ಕೀಲಿ_pair_5a(randomness,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_34(signing_ಕೀಲಿ),
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_9f0(verification_ಕೀಲಿ));
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_ml_dsa_generic_derive_ಸಂದೇಶ_representative_43(
  Eurydice_borrow_ತುಂಡು_u8 verification_ಕೀಲಿ_hash,
  ಸ್ಥಿರಾಂಕ core_option_Option_84 *domain_separation_context,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_arr_c7 *ಸಂದೇಶ_representative
)
{
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
  shake = libcrux_ml_dsa_hash_functions_portable_init_26();
  libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake, verification_ಕೀಲಿ_hash);
  ಆದರೆ (domain_separation_context->ಟ್ಯಾಗ್ == core_option_Some)
  {
    ಸ್ಥಿರಾಂಕ
    libcrux_ml_dsa_pre_hash_DomainSeparationContext
    *domain_separation_context0 = &domain_separation_context->f0;
    libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *uu____0 = &shake;
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_82
    lvalue0 =
      {
        .ದತ್ತಾಂಶ = {
          (uint8_t)core_option__core__option__Option_T__TraitClause_0___is_some(libcrux_ml_dsa_pre_hash_pre_hash_oid_88(domain_separation_context0),
            Eurydice_arr_c9,
            bool)
        }
      };
    libcrux_ml_dsa_hash_functions_portable_absorb_26(uu____0,
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_79(&lvalue0));
    libcrux_sha3_generic_keccak_xof_KeccakXofState_8d *uu____1 = &shake;
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_82
    lvalue =
      { .ದತ್ತಾಂಶ = { (uint8_t)libcrux_ml_dsa_pre_hash_context_88(domain_separation_context0).meta } };
    libcrux_ml_dsa_hash_functions_portable_absorb_26(uu____1,
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_79(&lvalue));
    libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake,
      libcrux_ml_dsa_pre_hash_context_88(domain_separation_context0));
    ಸ್ಥಿರಾಂಕ
    core_option_Option_57
    *uu____2 = libcrux_ml_dsa_pre_hash_pre_hash_oid_88(domain_separation_context0);
    ಆದರೆ (uu____2->ಟ್ಯಾಗ್ == core_option_Some)
    {
      ಸ್ಥಿರಾಂಕ Eurydice_arr_c9 *pre_hash_oid = &uu____2->f0;
      libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake,
        Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_2f(pre_hash_oid));
    }
  }
  libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake, ಸಂದೇಶ_2);
  libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_17(ಸಂದೇಶ_representative));
}

/**
A monomorphic instance of libcrux_ml_dsa.hash_functions.portable.shake256
with const generics
- OUTPUT_LENGTH= 576
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_hash_functions_portable_shake256_5a(
  Eurydice_borrow_ತುಂಡು_u8 ಒಳಹರಿವು,
  Eurydice_arr_220 *ಹೊರಹೋಗು
)
{
  libcrux_sha3_portable_shake256(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_8a(ಹೊರಹೋಗು), ಒಳಹರಿವು);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::XofX4 for libcrux_ml_dsa::hash_functions::portable::Shake256X4}
*/
/**
A monomorphic instance of libcrux_ml_dsa.hash_functions.portable.shake256_x4_9b
with const generics
- OUT_LEN= 576
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_hash_functions_portable_shake256_x4_9b_5a(
  Eurydice_borrow_ತುಂಡು_u8 input0,
  Eurydice_borrow_ತುಂಡು_u8 input1,
  Eurydice_borrow_ತುಂಡು_u8 input2,
  Eurydice_borrow_ತುಂಡು_u8 input3,
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_hash_functions_portable_shake256_0e(
  Eurydice_borrow_ತುಂಡು_u8 ಒಳಹರಿವು,
  Eurydice_arr_20 *ಹೊರಹೋಗು
)
{
  libcrux_sha3_portable_shake256(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_4f(ಹೊರಹೋಗು), ಒಳಹರಿವು);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::XofX4 for libcrux_ml_dsa::hash_functions::portable::Shake256X4}
*/
/**
A monomorphic instance of libcrux_ml_dsa.hash_functions.portable.shake256_x4_9b
with const generics
- OUT_LEN= 640
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_hash_functions_portable_shake256_x4_9b_0e(
  Eurydice_borrow_ತುಂಡು_u8 input0,
  Eurydice_borrow_ತುಂಡು_u8 input1,
  Eurydice_borrow_ತುಂಡು_u8 input2,
  Eurydice_borrow_ತುಂಡು_u8 input3,
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_hash_functions_portable_shake256_61_0e(
  Eurydice_borrow_ತುಂಡು_u8 ಒಳಹರಿವು,
  Eurydice_arr_20 *ಹೊರಹೋಗು
)
{
  libcrux_ml_dsa_hash_functions_portable_shake256_0e(ಒಳಹರಿವು, ಹೊರಹೋಗು);
}

/**
This function found in impl {libcrux_ml_dsa::hash_functions::shake256::DsaXof for libcrux_ml_dsa::hash_functions::portable::Shake256}
*/
/**
A monomorphic instance of libcrux_ml_dsa.hash_functions.portable.shake256_61
with const generics
- OUTPUT_LENGTH= 576
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_hash_functions_portable_shake256_61_5a(
  Eurydice_borrow_ತುಂಡು_u8 ಒಳಹರಿವು,
  Eurydice_arr_220 *ಹೊರಹೋಗು
)
{
  libcrux_ml_dsa_hash_functions_portable_shake256_5a(ಒಳಹರಿವು, ಹೊರಹೋಗು);
}

/**
A monomorphic instance of libcrux_ml_dsa.sample.sample_mask_ring_element
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_hash_functions_portable_Shake256
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_sample_sample_ಮುಖವಾಡ_ring_element_2e(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_91 *ಬೀಜ,
  Eurydice_arr_a3 *ಫಲಿತಾಂಶ,
  ಗಾತ್ರ_t gamma1_exponent
)
{
  ಆಯ್ಕೆ (gamma1_exponent)
  {
    ಸ್ಥಿತಿ 17U:
      {
        ನಿಲ್ಲಿಸು;
      }
    ಸ್ಥಿತಿ 19U:
      {
        Eurydice_arr_20 ಹೊರಹೋಗು = { .ದತ್ತಾಂಶ = { 0U } };
        libcrux_ml_dsa_hash_functions_portable_shake256_61_0e(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_f1(ಬೀಜ),
          &ಹೊರಹೋಗು);
        libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
          Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_4f(&ಹೊರಹೋಗು),
          ಫಲಿತಾಂಶ);
        ಹಿಂತಿರುಗಿ;
      }
    ಪೂರ್ವನಿಯೋಜಿತ:
      {
        KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __FILE__, __LINE__, "panic!");
        KRML_HOST_EXIT(255U);
      }
  }
  Eurydice_arr_220 ಹೊರಹೋಗು = { .ದತ್ತಾಂಶ = { 0U } };
  libcrux_ml_dsa_hash_functions_portable_shake256_61_5a(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_f1(ಬೀಜ),
    &ಹೊರಹೋಗು);
  libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_8a(&ಹೊರಹೋಗು),
    ಫಲಿತಾಂಶ);
}

/**
A monomorphic instance of libcrux_ml_dsa.sample.sample_mask_vector
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_sample_sample_ಮುಖವಾಡ_ಸದಿಶ_67(
  ಗಾತ್ರ_t dimension,
  ಗಾತ್ರ_t gamma1_exponent,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_c7 *ಬೀಜ,
  uint16_t *domain_separator,
  Eurydice_dst_ref_mut_44 ಮುಖವಾಡ
)
{
  Eurydice_arr_91
  seed0 =
    libcrux_ml_dsa_sample_ಕೂಡಿಸು_error_domain_separator(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_17(ಬೀಜ),
      domain_separator[0U]);
  Eurydice_arr_91
  seed1 =
    libcrux_ml_dsa_sample_ಕೂಡಿಸು_error_domain_separator(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_17(ಬೀಜ),
      (uint32_t)domain_separator[0U] + 1U);
  Eurydice_arr_91
  seed2 =
    libcrux_ml_dsa_sample_ಕೂಡಿಸು_error_domain_separator(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_17(ಬೀಜ),
      (uint32_t)domain_separator[0U] + 2U);
  Eurydice_arr_91
  seed3 =
    libcrux_ml_dsa_sample_ಕೂಡಿಸು_error_domain_separator(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_17(ಬೀಜ),
      (uint32_t)domain_separator[0U] + 3U);
  domain_separator[0U] = (uint32_t)domain_separator[0U] + 4U;
  ಆಯ್ಕೆ (gamma1_exponent)
  {
    ಸ್ಥಿತಿ 17U:
      {
        Eurydice_arr_220 out0 = { .ದತ್ತಾಂಶ = { 0U } };
        Eurydice_arr_220 out1 = { .ದತ್ತಾಂಶ = { 0U } };
        Eurydice_arr_220 out2 = { .ದತ್ತಾಂಶ = { 0U } };
        Eurydice_arr_220 out3 = { .ದತ್ತಾಂಶ = { 0U } };
        libcrux_ml_dsa_hash_functions_portable_shake256_x4_9b_5a(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_f1(&seed0),
          Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_f1(&seed1),
          Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_f1(&seed2),
          Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_f1(&seed3),
          &out0,
          &out1,
          &out2,
          &out3);
        libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
          Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_8a(&out0),
          ಮುಖವಾಡ.ptr);
        libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
          Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_8a(&out1),
          &ಮುಖವಾಡ.ptr[1U]);
        libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
          Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_8a(&out2),
          &ಮುಖವಾಡ.ptr[2U]);
        libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
          Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_8a(&out3),
          &ಮುಖವಾಡ.ptr[3U]);
        ನಿಲ್ಲಿಸು;
      }
    ಸ್ಥಿತಿ 19U:
      {
        Eurydice_arr_20 out0 = { .ದತ್ತಾಂಶ = { 0U } };
        Eurydice_arr_20 out1 = { .ದತ್ತಾಂಶ = { 0U } };
        Eurydice_arr_20 out2 = { .ದತ್ತಾಂಶ = { 0U } };
        Eurydice_arr_20 out3 = { .ದತ್ತಾಂಶ = { 0U } };
        libcrux_ml_dsa_hash_functions_portable_shake256_x4_9b_0e(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_f1(&seed0),
          Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_f1(&seed1),
          Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_f1(&seed2),
          Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_f1(&seed3),
          &out0,
          &out1,
          &out2,
          &out3);
        libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
          Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_4f(&out0),
          ಮುಖವಾಡ.ptr);
        libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
          Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_4f(&out1),
          &ಮುಖವಾಡ.ptr[1U]);
        libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
          Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_4f(&out2),
          &ಮುಖವಾಡ.ptr[2U]);
        libcrux_ml_dsa_encoding_gamma1_deserialize_37(gamma1_exponent,
          Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_4f(&out3),
          &ಮುಖವಾಡ.ptr[3U]);
        ನಿಲ್ಲಿಸು;
      }
    ಪೂರ್ವನಿಯೋಜಿತ:
      {
        KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n", __FILE__, __LINE__, "panic!");
        KRML_HOST_EXIT(255U);
      }
  }
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)4U; i < dimension; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    Eurydice_arr_91
    seed4 =
      libcrux_ml_dsa_sample_ಕೂಡಿಸು_error_domain_separator(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_17(ಬೀಜ),
        domain_separator[0U]);
    domain_separator[0U] = (uint32_t)domain_separator[0U] + 1U;
    libcrux_ml_dsa_sample_sample_ಮುಖವಾಡ_ring_element_2e(&seed4, &ಮುಖವಾಡ.ptr[i0], gamma1_exponent);
  }
}

/**
A monomorphic instance of libcrux_ml_dsa.sample.sample_challenge_ring_element
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_hash_functions_portable_Shake256
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_sample_sample_challenge_ring_element_2e(
  Eurydice_borrow_ತುಂಡು_u8 ಬೀಜ,
  ಗಾತ್ರ_t ಸಂಖ್ಯೆ_ದ_ones,
  Eurydice_arr_a3 *re
)
{
  Eurydice_arr_7c state = libcrux_ml_dsa_hash_functions_portable_init_absorb_final_61(ಬೀಜ);
  Eurydice_arr_ff
  randomness0 = libcrux_ml_dsa_hash_functions_portable_squeeze_ಮೊದಲ_ಖಂಡ_61(&state);
  Eurydice_array_u8x8 arr;
  ಸ್ಮರಣೆ_ನಕಲು(arr.ದತ್ತಾಂಶ,
    Eurydice_array_ಗಮ್ಯ_subslice_shared_d40(&randomness0,
      (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = (ಗಾತ್ರ_t)0U, .ಕೊನೆ = (ಗಾತ್ರ_t)8U })).ptr,
    (ಗಾತ್ರ_t)8U * ಗಾತ್ರ (uint8_t));
  uint64_t
  signs =
    core_ಅಂಕೆ_u64_from_le_ಬೈಟುಗಳು(core_ಫಲಿತಾಂಶ_unwrap_26_e0((
          KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_8e){ .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Ok, .val = { .case_Ok = arr } }
        )));
  Eurydice_arr_6c ಫಲಿತಾಂಶ = { .ದತ್ತಾಂಶ = { 0U } };
  ಗಾತ್ರ_t ಹೊರಹೋಗು_ಸೂಚ್ಯಂಕ = (ಗಾತ್ರ_t)256U - ಸಂಖ್ಯೆ_ದ_ones;
  bool
  ಮುಗಿದ =
    libcrux_ml_dsa_sample_inside_ಹೊರಹೋಗು_shuffle(Eurydice_array_ಗಮ್ಯ_subslice_from_shared_5f(&randomness0,
        (ಗಾತ್ರ_t)8U),
      &ಹೊರಹೋಗು_ಸೂಚ್ಯಂಕ,
      &signs,
      &ಫಲಿತಾಂಶ);
  ಆಗ (true)
  {
    ಆದರೆ (ಮುಗಿದ)
    {
      ನಿಲ್ಲಿಸು;
    }
    ಇಲ್ಲದಿದ್ದರೆ
    {
      Eurydice_arr_ff
      randomness = libcrux_ml_dsa_hash_functions_portable_squeeze_ಮುಂದಿನ_ಖಂಡ_61(&state);
      ಮುಗಿದ =
        libcrux_ml_dsa_sample_inside_ಹೊರಹೋಗು_shuffle(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_58(&randomness),
          &ಹೊರಹೋಗು_ಸೂಚ್ಯಂಕ,
          &signs,
          &ಫಲಿತಾಂಶ);
    }
  }
  libcrux_ml_dsa_polynomial_from_i32_array_ff_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_af(&ಫಲಿತಾಂಶ), re);
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_44.sign_internal
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_53
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_sign_ಆಂತರಿಕ_5a(
  Eurydice_borrow_ತುಂಡು_u8 signing_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  core_option_Option_84 domain_separation_context,
  Eurydice_arr_ec randomness,
  Eurydice_arr_85 *signature
)
{
  Eurydice_borrow_ತುಂಡು_u8_x2
  uu____0 =
    Eurydice_ತುಂಡು_ವಿಭಜಿಸು_at(signing_ಕೀಲಿ,
      LIBCRUX_ML_DSA_CONSTANTS_ಬೀಜ_FOR_A_ಗಾತ್ರ,
      uint8_t,
      Eurydice_borrow_ತುಂಡು_u8_x2);
  Eurydice_borrow_ತುಂಡು_u8 ಬೀಜ_for_a = uu____0.fst;
  Eurydice_borrow_ತುಂಡು_u8 ಉಳಿದ_serialized0 = uu____0.snd;
  Eurydice_borrow_ತುಂಡು_u8_x2
  uu____1 =
    Eurydice_ತುಂಡು_ವಿಭಜಿಸು_at(ಉಳಿದ_serialized0,
      LIBCRUX_ML_DSA_CONSTANTS_ಬೀಜ_FOR_SIGNING_ಗಾತ್ರ,
      uint8_t,
      Eurydice_borrow_ತುಂಡು_u8_x2);
  Eurydice_borrow_ತುಂಡು_u8 ಬೀಜ_for_signing = uu____1.fst;
  Eurydice_borrow_ತುಂಡು_u8 ಉಳಿದ_serialized1 = uu____1.snd;
  Eurydice_borrow_ತುಂಡು_u8_x2
  uu____2 =
    Eurydice_ತುಂಡು_ವಿಭಜಿಸು_at(ಉಳಿದ_serialized1,
      LIBCRUX_ML_DSA_CONSTANTS_ಬೈಟುಗಳು_FOR_VERIFICATION_ಕೀಲಿ_HASH,
      uint8_t,
      Eurydice_borrow_ತುಂಡು_u8_x2);
  Eurydice_borrow_ತುಂಡು_u8 verification_ಕೀಲಿ_hash = uu____2.fst;
  Eurydice_borrow_ತುಂಡು_u8 ಉಳಿದ_serialized2 = uu____2.snd;
  Eurydice_borrow_ತುಂಡು_u8_x2
  uu____3 =
    Eurydice_ತುಂಡು_ವಿಭಜಿಸು_at(ಉಳಿದ_serialized2,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_ERROR_RING_ELEMENT_ಗಾತ್ರ *
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_ಒಳ_A,
      uint8_t,
      Eurydice_borrow_ತುಂಡು_u8_x2);
  Eurydice_borrow_ತುಂಡು_u8 s1_serialized = uu____3.fst;
  Eurydice_borrow_ತುಂಡು_u8 ಉಳಿದ_serialized = uu____3.snd;
  Eurydice_borrow_ತುಂಡು_u8_x2
  uu____4 =
    Eurydice_ತುಂಡು_ವಿಭಜಿಸು_at(ಉಳಿದ_serialized,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_ERROR_RING_ELEMENT_ಗಾತ್ರ *
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A,
      uint8_t,
      Eurydice_borrow_ತುಂಡು_u8_x2);
  Eurydice_borrow_ತುಂಡು_u8 s2_serialized = uu____4.fst;
  Eurydice_borrow_ತುಂಡು_u8 t0_serialized = uu____4.snd;
  Eurydice_arr_9d s1_as_ntt;
  Eurydice_arr_a3 repeat_expression0[4U];
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)4U; i++)
  {
    repeat_expression0[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  ಸ್ಮರಣೆ_ನಕಲು(s1_as_ntt.ದತ್ತಾಂಶ, repeat_expression0, (ಗಾತ್ರ_t)4U * ಗಾತ್ರ (Eurydice_arr_a3));
  Eurydice_arr_9d s2_as_ntt;
  Eurydice_arr_a3 repeat_expression1[4U];
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)4U; i++)
  {
    repeat_expression1[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  ಸ್ಮರಣೆ_ನಕಲು(s2_as_ntt.ದತ್ತಾಂಶ, repeat_expression1, (ಗಾತ್ರ_t)4U * ಗಾತ್ರ (Eurydice_arr_a3));
  Eurydice_arr_9d t0_as_ntt;
  Eurydice_arr_a3 repeat_expression2[4U];
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)4U; i++)
  {
    repeat_expression2[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  ಸ್ಮರಣೆ_ನಕಲು(t0_as_ntt.ದತ್ತಾಂಶ, repeat_expression2, (ಗಾತ್ರ_t)4U * ಗಾತ್ರ (Eurydice_arr_a3));
  libcrux_ml_dsa_encoding_error_deserialize_ಗಮ್ಯ_ಸದಿಶ_then_ntt_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ETA,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_ERROR_RING_ELEMENT_ಗಾತ್ರ,
    s1_serialized,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_201(&s1_as_ntt));
  libcrux_ml_dsa_encoding_error_deserialize_ಗಮ್ಯ_ಸದಿಶ_then_ntt_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ETA,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_ERROR_RING_ELEMENT_ಗಾತ್ರ,
    s2_serialized,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_201(&s2_as_ntt));
  libcrux_ml_dsa_encoding_t0_deserialize_ಗಮ್ಯ_ಸದಿಶ_then_ntt_37(t0_serialized,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_201(&t0_as_ntt));
  Eurydice_arr_2f ಮಾತೃಕೆ;
  Eurydice_arr_a3 repeat_expression3[16U];
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)16U; i++)
  {
    repeat_expression3[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  ಸ್ಮರಣೆ_ನಕಲು(ಮಾತೃಕೆ.ದತ್ತಾಂಶ, repeat_expression3, (ಗಾತ್ರ_t)16U * ಗಾತ್ರ (Eurydice_arr_a3));
  libcrux_ml_dsa_samplex4_portable_ಮಾತೃಕೆ_flat_a8_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_ಒಳ_A,
    ಬೀಜ_for_a,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_200(&ಮಾತೃಕೆ));
  Eurydice_arr_c7 ಸಂದೇಶ_representative = { .ದತ್ತಾಂಶ = { 0U } };
  libcrux_ml_dsa_ml_dsa_generic_derive_ಸಂದೇಶ_representative_43(verification_ಕೀಲಿ_hash,
    &domain_separation_context,
    ಸಂದೇಶ_2,
    &ಸಂದೇಶ_representative);
  Eurydice_arr_c7 ಮುಖವಾಡ_ಬೀಜ = { .ದತ್ತಾಂಶ = { 0U } };
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
  shake0 = libcrux_ml_dsa_hash_functions_portable_init_26();
  libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake0, ಬೀಜ_for_signing);
  libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake0,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_01(&randomness));
  libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake0,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_17(&ಸಂದೇಶ_representative));
  libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake0,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_17(&ಮುಖವಾಡ_ಬೀಜ));
  uint16_t domain_separator_for_ಮುಖವಾಡ = 0U;
  ಗಾತ್ರ_t attempt = (ಗಾತ್ರ_t)0U;
  core_option_Option_14 commitment_hash0 = { .ಟ್ಯಾಗ್ = core_option_None };
  core_option_Option_d9 signer_response0 = { .ಟ್ಯಾಗ್ = core_option_None };
  core_option_Option_51 hint0 = { .ಟ್ಯಾಗ್ = core_option_None };
  ಆಗ (attempt < LIBCRUX_ML_DSA_CONSTANTS_REJECTION_SAMPLE_BOUND_SIGN)
  {
    attempt++;
    Eurydice_arr_9d ಮುಖವಾಡ;
    Eurydice_arr_a3 repeat_expression4[4U];
    ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)4U; i++)
    {
      repeat_expression4[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    ಸ್ಮರಣೆ_ನಕಲು(ಮುಖವಾಡ.ದತ್ತಾಂಶ, repeat_expression4, (ಗಾತ್ರ_t)4U * ಗಾತ್ರ (Eurydice_arr_a3));
    Eurydice_arr_9d w0;
    Eurydice_arr_a3 repeat_expression5[4U];
    ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)4U; i++)
    {
      repeat_expression5[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    ಸ್ಮರಣೆ_ನಕಲು(w0.ದತ್ತಾಂಶ, repeat_expression5, (ಗಾತ್ರ_t)4U * ಗಾತ್ರ (Eurydice_arr_a3));
    Eurydice_arr_9d commitment;
    Eurydice_arr_a3 repeat_expression6[4U];
    ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)4U; i++)
    {
      repeat_expression6[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    ಸ್ಮರಣೆ_ನಕಲು(commitment.ದತ್ತಾಂಶ, repeat_expression6, (ಗಾತ್ರ_t)4U * ಗಾತ್ರ (Eurydice_arr_a3));
    libcrux_ml_dsa_sample_sample_ಮುಖವಾಡ_ಸದಿಶ_67(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_ಒಳ_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_GAMMA1_EXPONENT,
      &ಮುಖವಾಡ_ಬೀಜ,
      &domain_separator_for_ಮುಖವಾಡ,
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_201(&ಮುಖವಾಡ));
    Eurydice_arr_9d a_x_ಮುಖವಾಡ;
    Eurydice_arr_a3 repeat_ಅಭಿವ್ಯಕ್ತಿ[4U];
    ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)4U; i++)
    {
      repeat_ಅಭಿವ್ಯಕ್ತಿ[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    ಸ್ಮರಣೆ_ನಕಲು(a_x_ಮುಖವಾಡ.ದತ್ತಾಂಶ, repeat_ಅಭಿವ್ಯಕ್ತಿ, (ಗಾತ್ರ_t)4U * ಗಾತ್ರ (Eurydice_arr_a3));
    Eurydice_arr_9d
    ಮುಖವಾಡ_ntt =
      core_array__core__clone__Clone_for__T__N___clone((ಗಾತ್ರ_t)4U,
        &ಮುಖವಾಡ,
        Eurydice_arr_a3,
        Eurydice_arr_9d);
    ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)4U; i++)
    {
      ಗಾತ್ರ_t i0 = i;
      libcrux_ml_dsa_ntt_ntt_37(&ಮುಖವಾಡ_ntt.ದತ್ತಾಂಶ[i0]);
    }
    libcrux_ml_dsa_ಮಾತೃಕೆ_compute_ಮಾತೃಕೆ_x_ಮುಖವಾಡ_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_ಒಳ_A,
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_201(&ಮಾತೃಕೆ),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_20(&ಮುಖವಾಡ_ntt),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_201(&a_x_ಮುಖವಾಡ));
    libcrux_ml_dsa_arithmetic_decompose_ಸದಿಶ_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_GAMMA2,
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_20(&a_x_ಮುಖವಾಡ),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_201(&w0),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_201(&commitment));
    Eurydice_arr_ec commitment_hash_candidate = { .ದತ್ತಾಂಶ = { 0U } };
    Eurydice_arr_d2 commitment_serialized = { .ದತ್ತಾಂಶ = { 0U } };
    libcrux_ml_dsa_encoding_commitment_serialize_ಸದಿಶ_37(LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_COMMITMENT_RING_ELEMENT_ಗಾತ್ರ,
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_20(&commitment),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_27(&commitment_serialized));
    libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
    shake = libcrux_ml_dsa_hash_functions_portable_init_26();
    libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake,
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_17(&ಸಂದೇಶ_representative));
    libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake,
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_27(&commitment_serialized));
    libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake,
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_01(&commitment_hash_candidate));
    Eurydice_arr_a3 verifier_challenge = libcrux_ml_dsa_polynomial_zero_ff_37();
    libcrux_ml_dsa_sample_sample_challenge_ring_element_2e(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_01(&commitment_hash_candidate),
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ONES_ಒಳ_VERIFIER_CHALLENGE,
      &verifier_challenge);
    libcrux_ml_dsa_ntt_ntt_37(&verifier_challenge);
    Eurydice_arr_9d
    challenge_times_s1 =
      core_array__core__clone__Clone_for__T__N___clone((ಗಾತ್ರ_t)4U,
        &s1_as_ntt,
        Eurydice_arr_a3,
        Eurydice_arr_9d);
    Eurydice_arr_9d
    challenge_times_s2 =
      core_array__core__clone__Clone_for__T__N___clone((ಗಾತ್ರ_t)4U,
        &s2_as_ntt,
        Eurydice_arr_a3,
        Eurydice_arr_9d);
    libcrux_ml_dsa_ಮಾತೃಕೆ_ಸದಿಶ_times_ring_element_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_201(&challenge_times_s1),
      &verifier_challenge);
    libcrux_ml_dsa_ಮಾತೃಕೆ_ಸದಿಶ_times_ring_element_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_201(&challenge_times_s2),
      &verifier_challenge);
    libcrux_ml_dsa_ಮಾತೃಕೆ_ಕೂಡಿಸು_vectors_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_ಒಳ_A,
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_201(&ಮುಖವಾಡ),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_20(&challenge_times_s1));
    libcrux_ml_dsa_ಮಾತೃಕೆ_ಕಳೆ_vectors_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A,
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_201(&w0),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_20(&challenge_times_s2));
    ಆದರೆ
    (
      !libcrux_ml_dsa_arithmetic_ಸದಿಶ_infinity_norm_exceeds_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_20(&ಮುಖವಾಡ),
        (int32_t)((uint32_t)1 << (uint32_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_GAMMA1_EXPONENT) -
          LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_BETA)
    )
    {
      ಆದರೆ
      (
        !libcrux_ml_dsa_arithmetic_ಸದಿಶ_infinity_norm_exceeds_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_20(&w0),
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_GAMMA2 - LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_BETA)
      )
      {
        Eurydice_arr_9d
        challenge_times_t0 =
          core_array__core__clone__Clone_for__T__N___clone((ಗಾತ್ರ_t)4U,
            &t0_as_ntt,
            Eurydice_arr_a3,
            Eurydice_arr_9d);
        libcrux_ml_dsa_ಮಾತೃಕೆ_ಸದಿಶ_times_ring_element_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_201(&challenge_times_t0),
          &verifier_challenge);
        ಆದರೆ
        (
          !libcrux_ml_dsa_arithmetic_ಸದಿಶ_infinity_norm_exceeds_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_20(&challenge_times_t0),
            LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_GAMMA2)
        )
        {
          libcrux_ml_dsa_ಮಾತೃಕೆ_ಕೂಡಿಸು_vectors_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A,
            Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_201(&w0),
            Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_20(&challenge_times_t0));
          Eurydice_arr_b7
          hint_candidate =
            {
              .ದತ್ತಾಂಶ = {
                { .ದತ್ತಾಂಶ = { 0U } },
                { .ದತ್ತಾಂಶ = { 0U } },
                { .ದತ್ತಾಂಶ = { 0U } },
                { .ದತ್ತಾಂಶ = { 0U } }
              }
            };
          ಗಾತ್ರ_t
          ones_ಒಳ_hint =
            libcrux_ml_dsa_arithmetic_make_hint_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_20(&w0),
              Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_20(&commitment),
              LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_GAMMA2,
              Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_86(&hint_candidate));
          ಆದರೆ (!(ones_ಒಳ_hint > LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_MAX_ONES_ಒಳ_HINT))
          {
            attempt = LIBCRUX_ML_DSA_CONSTANTS_REJECTION_SAMPLE_BOUND_SIGN;
            commitment_hash0 =
              (
                KRML_CLITERAL(core_option_Option_14){
                  .ಟ್ಯಾಗ್ = core_option_Some,
                  .f0 = commitment_hash_candidate
                }
              );
            signer_response0 =
              (KRML_CLITERAL(core_option_Option_d9){ .ಟ್ಯಾಗ್ = core_option_Some, .f0 = ಮುಖವಾಡ });
            hint0 =
              (
                KRML_CLITERAL(core_option_Option_51){
                  .ಟ್ಯಾಗ್ = core_option_Some,
                  .f0 = hint_candidate
                }
              );
          }
        }
      }
    }
  }
  core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_53 uu____5;
  ಆದರೆ (commitment_hash0.ಟ್ಯಾಗ್ == core_option_None)
  {
    uu____5 =
      (
        KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_53){
          .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Err,
          .f0 = libcrux_ml_dsa_types_SigningError_RejectionSamplingError
        }
      );
  }
  ಇಲ್ಲದಿದ್ದರೆ
  {
    Eurydice_arr_ec commitment_hash = commitment_hash0.f0;
    Eurydice_arr_ec commitment_hash1 = commitment_hash;
    ಆದರೆ (signer_response0.ಟ್ಯಾಗ್ == core_option_None)
    {
      uu____5 =
        (
          KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_53){
            .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Err,
            .f0 = libcrux_ml_dsa_types_SigningError_RejectionSamplingError
          }
        );
    }
    ಇಲ್ಲದಿದ್ದರೆ
    {
      Eurydice_arr_9d signer_response = signer_response0.f0;
      Eurydice_arr_9d signer_response1 = signer_response;
      ಆದರೆ (!(hint0.ಟ್ಯಾಗ್ == core_option_None))
      {
        Eurydice_arr_b7 hint = hint0.f0;
        Eurydice_arr_b7 hint1 = hint;
        libcrux_ml_dsa_encoding_signature_serialize_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_01(&commitment_hash1),
          Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_20(&signer_response1),
          Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_86(&hint1),
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COMMITMENT_HASH_ಗಾತ್ರ,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_ಒಳ_A,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_GAMMA1_EXPONENT,
          LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_GAMMA1_RING_ELEMENT_ಗಾತ್ರ,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_MAX_ONES_ಒಳ_HINT,
          Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_0d(signature));
        ಹಿಂತಿರುಗಿ (KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_53){ .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Ok });
      }
      uu____5 =
        (
          KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_53){
            .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Err,
            .f0 = libcrux_ml_dsa_types_SigningError_RejectionSamplingError
          }
        );
    }
  }
  ಹಿಂತಿರುಗಿ uu____5;
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_44.sign_mut
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_53
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_sign_mut_5a(
  Eurydice_borrow_ತುಂಡು_u8 signing_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 context,
  Eurydice_arr_ec randomness,
  Eurydice_arr_85 *signature
)
{
  core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_a8
  uu____0 =
    libcrux_ml_dsa_pre_hash_new_88(context,
      (KRML_CLITERAL(core_option_Option_57){ .ಟ್ಯಾಗ್ = core_option_None }));
  ಆದರೆ (!(uu____0.ಟ್ಯಾಗ್ == core_ಫಲಿತಾಂಶ_Ok))
  {
    ಹಿಂತಿರುಗಿ
      (
        KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_53){
          .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Err,
          .f0 = libcrux_ml_dsa_types_SigningError_ContextTooLongError
        }
      );
  }
  libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
  libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
  ಹಿಂತಿರುಗಿ
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_sign_ಆಂತರಿಕ_5a(signing_ಕೀಲಿ,
      ಸಂದೇಶ_2,
      (
        KRML_CLITERAL(core_option_Option_84){
          .ಟ್ಯಾಗ್ = core_option_Some,
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
ಸ್ಥಿರ KRML_MUSTINLINE core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_48
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_sign_5a(
  Eurydice_borrow_ತುಂಡು_u8 signing_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 context,
  Eurydice_arr_ec randomness
)
{
  Eurydice_arr_85 signature = libcrux_ml_dsa_types_zero_c5_37();
  core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_53
  uu____0 =
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_sign_mut_5a(signing_ಕೀಲಿ,
      ಸಂದೇಶ_2,
      context,
      randomness,
      &signature);
  core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_48 uu____1;
  ಆದರೆ (uu____0.ಟ್ಯಾಗ್ == core_ಫಲಿತಾಂಶ_Ok)
  {
    uu____1 =
      (
        KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_48){
          .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Ok,
          .val = { .case_Ok = signature }
        }
      );
  }
  ಇಲ್ಲದಿದ್ದರೆ
  {
    libcrux_ml_dsa_types_SigningError e = uu____0.f0;
    uu____1 =
      (KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_48){ .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Err, .val = { .case_Err = e } });
  }
  ಹಿಂತಿರುಗಿ uu____1;
}

/**
 Sign.
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_48
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_44_sign(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_10 *signing_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 context,
  Eurydice_arr_ec randomness
)
{
  ಹಿಂತಿರುಗಿ
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_sign_5a(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_34(signing_ಕೀಲಿ),
      ಸಂದೇಶ_2,
      context,
      randomness);
}

/**
 Sign.
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_53
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_44_sign_mut(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_10 *signing_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 context,
  Eurydice_arr_ec randomness,
  Eurydice_arr_85 *signature
)
{
  ಹಿಂತಿರುಗಿ
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_sign_mut_5a(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_34(signing_ಕೀಲಿ),
      ಸಂದೇಶ_2,
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_pre_hash_hash_30_83(
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_mut_borrow_ತುಂಡು_u8 output
)
{
  libcrux_ml_dsa_hash_functions_portable_shake128_7b(ಸಂದೇಶ_2, output);
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_44.sign_pre_hashed_mut
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4, libcrux_ml_dsa_pre_hash_SHAKE128_PH
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_53
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_sign_pre_hashed_mut_3f(
  Eurydice_borrow_ತುಂಡು_u8 signing_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 context,
  Eurydice_mut_borrow_ತುಂಡು_u8 pre_hash_ಬಫರ್,
  Eurydice_arr_ec randomness,
  Eurydice_arr_85 *signature
)
{
  ಆದರೆ (!(context.meta > LIBCRUX_ML_DSA_CONSTANTS_CONTEXT_MAX_LEN))
  {
    libcrux_ml_dsa_pre_hash_hash_30_83(ಸಂದೇಶ_2, pre_hash_ಬಫರ್);
    core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_a8
    uu____0 =
      libcrux_ml_dsa_pre_hash_new_88(context,
        (
          KRML_CLITERAL(core_option_Option_57){
            .ಟ್ಯಾಗ್ = core_option_Some,
            .f0 = libcrux_ml_dsa_pre_hash_oid_30()
          }
        ));
    ಆದರೆ (!(uu____0.ಟ್ಯಾಗ್ == core_ಫಲಿತಾಂಶ_Ok))
    {
      ಹಿಂತಿರುಗಿ
        (
          KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_53){
            .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Err,
            .f0 = libcrux_ml_dsa_types_SigningError_ContextTooLongError
          }
        );
    }
    libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
    libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
    ಹಿಂತಿರುಗಿ
      libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_sign_ಆಂತರಿಕ_5a(signing_ಕೀಲಿ,
        (
          KRML_CLITERAL(Eurydice_borrow_ತುಂಡು_u8){
            .ptr = pre_hash_ಬಫರ್.ptr,
            .meta = pre_hash_ಬಫರ್.meta
          }
        ),
        (
          KRML_CLITERAL(core_option_Option_84){
            .ಟ್ಯಾಗ್ = core_option_Some,
            .f0 = domain_separation_context
          }
        ),
        randomness,
        signature);
  }
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_53){
        .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Err,
        .f0 = libcrux_ml_dsa_types_SigningError_ContextTooLongError
      }
    );
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_44.sign_pre_hashed
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4, libcrux_ml_dsa_pre_hash_SHAKE128_PH
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_48
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_sign_pre_hashed_3f(
  Eurydice_borrow_ತುಂಡು_u8 signing_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 context,
  Eurydice_mut_borrow_ತುಂಡು_u8 pre_hash_ಬಫರ್,
  Eurydice_arr_ec randomness
)
{
  Eurydice_arr_85 signature = libcrux_ml_dsa_types_zero_c5_37();
  core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_53
  uu____0 =
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_sign_pre_hashed_mut_3f(signing_ಕೀಲಿ,
      ಸಂದೇಶ_2,
      context,
      pre_hash_ಬಫರ್,
      randomness,
      &signature);
  core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_48 uu____1;
  ಆದರೆ (uu____0.ಟ್ಯಾಗ್ == core_ಫಲಿತಾಂಶ_Ok)
  {
    uu____1 =
      (
        KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_48){
          .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Ok,
          .val = { .case_Ok = signature }
        }
      );
  }
  ಇಲ್ಲದಿದ್ದರೆ
  {
    libcrux_ml_dsa_types_SigningError e = uu____0.f0;
    uu____1 =
      (KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_48){ .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Err, .val = { .case_Err = e } });
  }
  ಹಿಂತಿರುಗಿ uu____1;
}

/**
 Sign (pre-hashed).
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_48
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_44_sign_pre_hashed_shake128(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_10 *signing_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 context,
  Eurydice_mut_borrow_ತುಂಡು_u8 pre_hash_ಬಫರ್,
  Eurydice_arr_ec randomness
)
{
  ಹಿಂತಿರುಗಿ
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_sign_pre_hashed_3f(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_34(signing_ಕೀಲಿ),
      ಸಂದೇಶ_2,
      context,
      pre_hash_ಬಫರ್,
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
ಸ್ಥಿರ KRML_MUSTINLINE core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_verify_ಆಂತರಿಕ_5a(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_02 *verification_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  core_option_Option_84 domain_separation_context,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_85 *signature_serialized
)
{
  Eurydice_borrow_ತುಂಡು_u8_x2
  uu____0 =
    Eurydice_ತುಂಡು_ವಿಭಜಿಸು_at(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_9f(verification_ಕೀಲಿ),
      LIBCRUX_ML_DSA_CONSTANTS_ಬೀಜ_FOR_A_ಗಾತ್ರ,
      uint8_t,
      Eurydice_borrow_ತುಂಡು_u8_x2);
  Eurydice_borrow_ತುಂಡು_u8 ಬೀಜ_for_a = uu____0.fst;
  Eurydice_borrow_ತುಂಡು_u8 t1_serialized = uu____0.snd;
  Eurydice_arr_9d t1;
  Eurydice_arr_a3 repeat_expression0[4U];
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)4U; i++)
  {
    repeat_expression0[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  ಸ್ಮರಣೆ_ನಕಲು(t1.ದತ್ತಾಂಶ, repeat_expression0, (ಗಾತ್ರ_t)4U * ಗಾತ್ರ (Eurydice_arr_a3));
  libcrux_ml_dsa_encoding_verification_ಕೀಲಿ_deserialize_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_VERIFICATION_ಕೀಲಿ_ಗಾತ್ರ,
    t1_serialized,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_201(&t1));
  Eurydice_arr_ec deserialized_commitment_hash = { .ದತ್ತಾಂಶ = { 0U } };
  Eurydice_arr_9d deserialized_signer_response;
  Eurydice_arr_a3 repeat_expression1[4U];
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)4U; i++)
  {
    repeat_expression1[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  ಸ್ಮರಣೆ_ನಕಲು(deserialized_signer_response.ದತ್ತಾಂಶ,
    repeat_expression1,
    (ಗಾತ್ರ_t)4U * ಗಾತ್ರ (Eurydice_arr_a3));
  Eurydice_arr_b7
  deserialized_hint =
    { .ದತ್ತಾಂಶ = { { .ದತ್ತಾಂಶ = { 0U } }, { .ದತ್ತಾಂಶ = { 0U } }, { .ದತ್ತಾಂಶ = { 0U } }, { .ದತ್ತಾಂಶ = { 0U } } } };
  core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41
  uu____1 =
    libcrux_ml_dsa_encoding_signature_deserialize_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_ಒಳ_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COMMITMENT_HASH_ಗಾತ್ರ,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_GAMMA1_EXPONENT,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_GAMMA1_RING_ELEMENT_ಗಾತ್ರ,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_MAX_ONES_ಒಳ_HINT,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_SIGNATURE_ಗಾತ್ರ,
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_0d(signature_serialized),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_01(&deserialized_commitment_hash),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_201(&deserialized_signer_response),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_86(&deserialized_hint));
  core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41 uu____2;
  ಆದರೆ (uu____1.ಟ್ಯಾಗ್ == core_ಫಲಿತಾಂಶ_Ok)
  {
    ಆದರೆ
    (
      libcrux_ml_dsa_arithmetic_ಸದಿಶ_infinity_norm_exceeds_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_20(&deserialized_signer_response),
        (int32_t)((uint32_t)1 << (uint32_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_GAMMA1_EXPONENT) -
          LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_BETA)
    )
    {
      uu____2 =
        (
          KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41){
            .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Err,
            .f0 = libcrux_ml_dsa_types_VerificationError_SignerResponseExceedsBoundError
          }
        );
    }
    ಇಲ್ಲದಿದ್ದರೆ
    {
      Eurydice_arr_2f ಮಾತೃಕೆ;
      Eurydice_arr_a3 repeat_ಅಭಿವ್ಯಕ್ತಿ[16U];
      ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)16U; i++)
      {
        repeat_ಅಭಿವ್ಯಕ್ತಿ[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
      }
      ಸ್ಮರಣೆ_ನಕಲು(ಮಾತೃಕೆ.ದತ್ತಾಂಶ, repeat_ಅಭಿವ್ಯಕ್ತಿ, (ಗಾತ್ರ_t)16U * ಗಾತ್ರ (Eurydice_arr_a3));
      libcrux_ml_dsa_samplex4_portable_ಮಾತೃಕೆ_flat_a8_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_ಒಳ_A,
        ಬೀಜ_for_a,
        Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_200(&ಮಾತೃಕೆ));
      Eurydice_arr_c7 verification_ಕೀಲಿ_hash = { .ದತ್ತಾಂಶ = { 0U } };
      libcrux_ml_dsa_hash_functions_portable_shake256_61_c9(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_9f(verification_ಕೀಲಿ),
        &verification_ಕೀಲಿ_hash);
      Eurydice_arr_c7 ಸಂದೇಶ_representative = { .ದತ್ತಾಂಶ = { 0U } };
      libcrux_ml_dsa_ml_dsa_generic_derive_ಸಂದೇಶ_representative_43(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_17(&verification_ಕೀಲಿ_hash),
        &domain_separation_context,
        ಸಂದೇಶ_2,
        &ಸಂದೇಶ_representative);
      Eurydice_arr_a3 verifier_challenge = libcrux_ml_dsa_polynomial_zero_ff_37();
      libcrux_ml_dsa_sample_sample_challenge_ring_element_2e(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_01(&deserialized_commitment_hash),
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ONES_ಒಳ_VERIFIER_CHALLENGE,
        &verifier_challenge);
      libcrux_ml_dsa_ntt_ntt_37(&verifier_challenge);
      ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)4U; i++)
      {
        ಗಾತ್ರ_t i0 = i;
        libcrux_ml_dsa_ntt_ntt_37(&deserialized_signer_response.ದತ್ತಾಂಶ[i0]);
      }
      libcrux_ml_dsa_ಮಾತೃಕೆ_compute_w_approx_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A,
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_COLUMNS_ಒಳ_A,
        Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_201(&ಮಾತೃಕೆ),
        Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_20(&deserialized_signer_response),
        &verifier_challenge,
        Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_201(&t1));
      Eurydice_arr_ec recomputed_commitment_hash = { .ದತ್ತಾಂಶ = { 0U } };
      libcrux_ml_dsa_arithmetic_use_hint_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_44_GAMMA2,
        Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_86(&deserialized_hint),
        Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_201(&t1));
      Eurydice_arr_d2 commitment_serialized = { .ದತ್ತಾಂಶ = { 0U } };
      libcrux_ml_dsa_encoding_commitment_serialize_ಸದಿಶ_37(LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_44_COMMITMENT_RING_ELEMENT_ಗಾತ್ರ,
        Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_20(&t1),
        Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_27(&commitment_serialized));
      libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
      shake = libcrux_ml_dsa_hash_functions_portable_init_26();
      libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake,
        Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_17(&ಸಂದೇಶ_representative));
      libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake,
        Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_27(&commitment_serialized));
      libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake,
        Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_01(&recomputed_commitment_hash));
      ಆದರೆ
      (
        Eurydice_array_eq((ಗಾತ್ರ_t)32U,
          &deserialized_commitment_hash,
          &recomputed_commitment_hash,
          uint8_t)
      )
      {
        uu____2 = (KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41){ .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Ok });
      }
      ಇಲ್ಲದಿದ್ದರೆ
      {
        uu____2 =
          (
            KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41){
              .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Err,
              .f0 = libcrux_ml_dsa_types_Verification_Error_Commitment_Hashes_Dont_ಹೊಂದಿಕೆ_Error
            }
          );
      }
    }
  }
  ಇಲ್ಲದಿದ್ದರೆ
  {
    libcrux_ml_dsa_types_VerificationError e = uu____1.f0;
    uu____2 = (KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41){ .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Err, .f0 = e });
  }
  ಹಿಂತಿರುಗಿ uu____2;
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_44.verify
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_verify_5a(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_02 *verification_ಕೀಲಿ_serialized,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 context,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_85 *signature_serialized
)
{
  core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_a8
  uu____0 =
    libcrux_ml_dsa_pre_hash_new_88(context,
      (KRML_CLITERAL(core_option_Option_57){ .ಟ್ಯಾಗ್ = core_option_None }));
  ಆದರೆ (!(uu____0.ಟ್ಯಾಗ್ == core_ಫಲಿತಾಂಶ_Ok))
  {
    ಹಿಂತಿರುಗಿ
      (
        KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41){
          .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Err,
          .f0 = libcrux_ml_dsa_types_VerificationError_VerificationContextTooLongError
        }
      );
  }
  libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
  libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
  ಹಿಂತಿರುಗಿ
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_verify_ಆಂತರಿಕ_5a(verification_ಕೀಲಿ_serialized,
      ಸಂದೇಶ_2,
      (
        KRML_CLITERAL(core_option_Option_84){
          .ಟ್ಯಾಗ್ = core_option_Some,
          .f0 = domain_separation_context
        }
      ),
      signature_serialized);
}

/**
 Verify.
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_44_verify(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_02 *verification_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 context,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_85 *signature
)
{
  ಹಿಂತಿರುಗಿ
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_verify_5a(verification_ಕೀಲಿ,
      ಸಂದೇಶ_2,
      context,
      signature);
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_44.verify_pre_hashed
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_pre_hash_SHAKE128_PH
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_verify_pre_hashed_3f(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_02 *verification_ಕೀಲಿ_serialized,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 context,
  Eurydice_mut_borrow_ತುಂಡು_u8 pre_hash_ಬಫರ್,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_85 *signature_serialized
)
{
  libcrux_ml_dsa_pre_hash_hash_30_83(ಸಂದೇಶ_2, pre_hash_ಬಫರ್);
  core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_a8
  uu____0 =
    libcrux_ml_dsa_pre_hash_new_88(context,
      (
        KRML_CLITERAL(core_option_Option_57){
          .ಟ್ಯಾಗ್ = core_option_Some,
          .f0 = libcrux_ml_dsa_pre_hash_oid_30()
        }
      ));
  ಆದರೆ (!(uu____0.ಟ್ಯಾಗ್ == core_ಫಲಿತಾಂಶ_Ok))
  {
    ಹಿಂತಿರುಗಿ
      (
        KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41){
          .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Err,
          .f0 = libcrux_ml_dsa_types_VerificationError_VerificationContextTooLongError
        }
      );
  }
  libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
  libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
  ಹಿಂತಿರುಗಿ
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_verify_ಆಂತರಿಕ_5a(verification_ಕೀಲಿ_serialized,
      (
        KRML_CLITERAL(Eurydice_borrow_ತುಂಡು_u8){
          .ptr = pre_hash_ಬಫರ್.ptr,
          .meta = pre_hash_ಬಫರ್.meta
        }
      ),
      (
        KRML_CLITERAL(core_option_Option_84){
          .ಟ್ಯಾಗ್ = core_option_Some,
          .f0 = domain_separation_context
        }
      ),
      signature_serialized);
}

/**
 Verify (pre-hashed with SHAKE-128).
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_44_verify_pre_hashed_shake128(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_02 *verification_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 context,
  Eurydice_mut_borrow_ತುಂಡು_u8 pre_hash_ಬಫರ್,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_85 *signature
)
{
  ಹಿಂತಿರುಗಿ
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_verify_pre_hashed_3f(verification_ಕೀಲಿ,
      ಸಂದೇಶ_2,
      context,
      pre_hash_ಬಫರ್,
      signature);
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_65.generate_key_pair
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_generate_ಕೀಲಿ_pair_5a(
  Eurydice_arr_ec randomness,
  Eurydice_mut_borrow_ತುಂಡು_u8 signing_ಕೀಲಿ,
  Eurydice_mut_borrow_ತುಂಡು_u8 verification_ಕೀಲಿ
)
{
  Eurydice_arr_89 ಬೀಜ_expanded0 = { .ದತ್ತಾಂಶ = { 0U } };
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
  shake = libcrux_ml_dsa_hash_functions_portable_init_26();
  libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_01(&randomness));
  /* original Rust expression is not an lvalue in C */
  Eurydice_array_u8x2
  lvalue =
    {
      .ದತ್ತಾಂಶ = {
        (uint8_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A,
        (uint8_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_ಒಳ_A
      }
    };
  libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_82(&lvalue));
  libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_78(&ಬೀಜ_expanded0));
  Eurydice_borrow_ತುಂಡು_u8_x2
  uu____0 =
    Eurydice_ತುಂಡು_ವಿಭಜಿಸು_at(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_78(&ಬೀಜ_expanded0),
      LIBCRUX_ML_DSA_CONSTANTS_ಬೀಜ_FOR_A_ಗಾತ್ರ,
      uint8_t,
      Eurydice_borrow_ತುಂಡು_u8_x2);
  Eurydice_borrow_ತುಂಡು_u8 ಬೀಜ_for_a = uu____0.fst;
  Eurydice_borrow_ತುಂಡು_u8 ಬೀಜ_expanded = uu____0.snd;
  Eurydice_borrow_ತುಂಡು_u8_x2
  uu____1 =
    Eurydice_ತುಂಡು_ವಿಭಜಿಸು_at(ಬೀಜ_expanded,
      LIBCRUX_ML_DSA_CONSTANTS_ಬೀಜ_FOR_ERROR_VECTORS_ಗಾತ್ರ,
      uint8_t,
      Eurydice_borrow_ತುಂಡು_u8_x2);
  Eurydice_borrow_ತುಂಡು_u8 ಬೀಜ_for_error_vectors = uu____1.fst;
  Eurydice_borrow_ತುಂಡು_u8 ಬೀಜ_for_signing = uu____1.snd;
  Eurydice_arr_47 s1_s2;
  Eurydice_arr_a3 repeat_expression0[11U];
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)11U; i++)
  {
    repeat_expression0[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  ಸ್ಮರಣೆ_ನಕಲು(s1_s2.ದತ್ತಾಂಶ, repeat_expression0, (ಗಾತ್ರ_t)11U * ಗಾತ್ರ (Eurydice_arr_a3));
  libcrux_ml_dsa_samplex4_sample_s1_and_s2_29(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ETA,
    ಬೀಜ_for_error_vectors,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_202(&s1_s2));
  Eurydice_arr_dc1 t0;
  Eurydice_arr_a3 repeat_expression1[6U];
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)6U; i++)
  {
    repeat_expression1[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  ಸ್ಮರಣೆ_ನಕಲು(t0.ದತ್ತಾಂಶ, repeat_expression1, (ಗಾತ್ರ_t)6U * ಗಾತ್ರ (Eurydice_arr_a3));
  Eurydice_arr_5a a_as_ntt;
  Eurydice_arr_a3 repeat_expression2[30U];
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)30U; i++)
  {
    repeat_expression2[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  ಸ್ಮರಣೆ_ನಕಲು(a_as_ntt.ದತ್ತಾಂಶ, repeat_expression2, (ಗಾತ್ರ_t)30U * ಗಾತ್ರ (Eurydice_arr_a3));
  libcrux_ml_dsa_samplex4_portable_ಮಾತೃಕೆ_flat_a8_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_ಒಳ_A,
    ಬೀಜ_for_a,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_203(&a_as_ntt));
  Eurydice_arr_5d s1_ntt;
  Eurydice_arr_a3 repeat_expression3[5U];
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)5U; i++)
  {
    repeat_expression3[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  ಸ್ಮರಣೆ_ನಕಲು(s1_ntt.ದತ್ತಾಂಶ, repeat_expression3, (ಗಾತ್ರ_t)5U * ಗಾತ್ರ (Eurydice_arr_a3));
  Eurydice_ತುಂಡು_copy(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_204(&s1_ntt),
    Eurydice_array_ಗಮ್ಯ_subslice_shared_250(&s1_s2,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .ಆರಂಭ = (ಗಾತ್ರ_t)0U,
          .ಕೊನೆ = LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_ಒಳ_A
        }
      )),
    Eurydice_arr_a3);
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)5U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    libcrux_ml_dsa_ntt_ntt_37(&s1_ntt.ದತ್ತಾಂಶ[i0]);
  }
  libcrux_ml_dsa_ಮಾತೃಕೆ_compute_as1_plus_s2_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A,
    LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_ಒಳ_A,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_203(&a_as_ntt),
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_202(&s1_ntt),
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_203(&s1_s2),
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_205(&t0));
  Eurydice_arr_dc1 t1;
  Eurydice_arr_a3 repeat_ಅಭಿವ್ಯಕ್ತಿ[6U];
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)6U; i++)
  {
    repeat_ಅಭಿವ್ಯಕ್ತಿ[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  ಸ್ಮರಣೆ_ನಕಲು(t1.ದತ್ತಾಂಶ, repeat_ಅಭಿವ್ಯಕ್ತಿ, (ಗಾತ್ರ_t)6U * ಗಾತ್ರ (Eurydice_arr_a3));
  libcrux_ml_dsa_arithmetic_power2round_ಸದಿಶ_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_205(&t0),
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_205(&t1));
  libcrux_ml_dsa_encoding_verification_ಕೀಲಿ_generate_serialized_37(ಬೀಜ_for_a,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_204(&t1),
    verification_ಕೀಲಿ);
  libcrux_ml_dsa_encoding_signing_ಕೀಲಿ_generate_serialized_2e(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ETA,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_ERROR_RING_ELEMENT_ಗಾತ್ರ,
    ಬೀಜ_for_a,
    ಬೀಜ_for_signing,
    (
      KRML_CLITERAL(Eurydice_borrow_ತುಂಡು_u8){
        .ptr = verification_ಕೀಲಿ.ptr,
        .meta = verification_ಕೀಲಿ.meta
      }
    ),
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_203(&s1_s2),
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_204(&t0),
    signing_ಕೀಲಿ);
}

/**
 Generate key pair.
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_generate_ಕೀಲಿ_pair(
  Eurydice_arr_ec randomness,
  Eurydice_arr_24 *signing_ಕೀಲಿ,
  Eurydice_arr_29 *verification_ಕೀಲಿ
)
{
  libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_generate_ಕೀಲಿ_pair_5a(randomness,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_98(signing_ಕೀಲಿ),
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_37(verification_ಕೀಲಿ));
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_65.sign_internal
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_53
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_ಆಂತರಿಕ_5a(
  Eurydice_borrow_ತುಂಡು_u8 signing_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  core_option_Option_84 domain_separation_context,
  Eurydice_arr_ec randomness,
  Eurydice_arr_0c *signature
)
{
  Eurydice_borrow_ತುಂಡು_u8_x2
  uu____0 =
    Eurydice_ತುಂಡು_ವಿಭಜಿಸು_at(signing_ಕೀಲಿ,
      LIBCRUX_ML_DSA_CONSTANTS_ಬೀಜ_FOR_A_ಗಾತ್ರ,
      uint8_t,
      Eurydice_borrow_ತುಂಡು_u8_x2);
  Eurydice_borrow_ತುಂಡು_u8 ಬೀಜ_for_a = uu____0.fst;
  Eurydice_borrow_ತುಂಡು_u8 ಉಳಿದ_serialized0 = uu____0.snd;
  Eurydice_borrow_ತುಂಡು_u8_x2
  uu____1 =
    Eurydice_ತುಂಡು_ವಿಭಜಿಸು_at(ಉಳಿದ_serialized0,
      LIBCRUX_ML_DSA_CONSTANTS_ಬೀಜ_FOR_SIGNING_ಗಾತ್ರ,
      uint8_t,
      Eurydice_borrow_ತುಂಡು_u8_x2);
  Eurydice_borrow_ತುಂಡು_u8 ಬೀಜ_for_signing = uu____1.fst;
  Eurydice_borrow_ತುಂಡು_u8 ಉಳಿದ_serialized1 = uu____1.snd;
  Eurydice_borrow_ತುಂಡು_u8_x2
  uu____2 =
    Eurydice_ತುಂಡು_ವಿಭಜಿಸು_at(ಉಳಿದ_serialized1,
      LIBCRUX_ML_DSA_CONSTANTS_ಬೈಟುಗಳು_FOR_VERIFICATION_ಕೀಲಿ_HASH,
      uint8_t,
      Eurydice_borrow_ತುಂಡು_u8_x2);
  Eurydice_borrow_ತುಂಡು_u8 verification_ಕೀಲಿ_hash = uu____2.fst;
  Eurydice_borrow_ತುಂಡು_u8 ಉಳಿದ_serialized2 = uu____2.snd;
  Eurydice_borrow_ತುಂಡು_u8_x2
  uu____3 =
    Eurydice_ತುಂಡು_ವಿಭಜಿಸು_at(ಉಳಿದ_serialized2,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_ERROR_RING_ELEMENT_ಗಾತ್ರ *
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_ಒಳ_A,
      uint8_t,
      Eurydice_borrow_ತುಂಡು_u8_x2);
  Eurydice_borrow_ತುಂಡು_u8 s1_serialized = uu____3.fst;
  Eurydice_borrow_ತುಂಡು_u8 ಉಳಿದ_serialized = uu____3.snd;
  Eurydice_borrow_ತುಂಡು_u8_x2
  uu____4 =
    Eurydice_ತುಂಡು_ವಿಭಜಿಸು_at(ಉಳಿದ_serialized,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_ERROR_RING_ELEMENT_ಗಾತ್ರ *
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A,
      uint8_t,
      Eurydice_borrow_ತುಂಡು_u8_x2);
  Eurydice_borrow_ತುಂಡು_u8 s2_serialized = uu____4.fst;
  Eurydice_borrow_ತುಂಡು_u8 t0_serialized = uu____4.snd;
  Eurydice_arr_5d s1_as_ntt;
  Eurydice_arr_a3 repeat_expression0[5U];
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)5U; i++)
  {
    repeat_expression0[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  ಸ್ಮರಣೆ_ನಕಲು(s1_as_ntt.ದತ್ತಾಂಶ, repeat_expression0, (ಗಾತ್ರ_t)5U * ಗಾತ್ರ (Eurydice_arr_a3));
  Eurydice_arr_dc1 s2_as_ntt;
  Eurydice_arr_a3 repeat_expression1[6U];
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)6U; i++)
  {
    repeat_expression1[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  ಸ್ಮರಣೆ_ನಕಲು(s2_as_ntt.ದತ್ತಾಂಶ, repeat_expression1, (ಗಾತ್ರ_t)6U * ಗಾತ್ರ (Eurydice_arr_a3));
  Eurydice_arr_dc1 t0_as_ntt;
  Eurydice_arr_a3 repeat_expression2[6U];
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)6U; i++)
  {
    repeat_expression2[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  ಸ್ಮರಣೆ_ನಕಲು(t0_as_ntt.ದತ್ತಾಂಶ, repeat_expression2, (ಗಾತ್ರ_t)6U * ಗಾತ್ರ (Eurydice_arr_a3));
  libcrux_ml_dsa_encoding_error_deserialize_ಗಮ್ಯ_ಸದಿಶ_then_ntt_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ETA,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_ERROR_RING_ELEMENT_ಗಾತ್ರ,
    s1_serialized,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_204(&s1_as_ntt));
  libcrux_ml_dsa_encoding_error_deserialize_ಗಮ್ಯ_ಸದಿಶ_then_ntt_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ETA,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_ERROR_RING_ELEMENT_ಗಾತ್ರ,
    s2_serialized,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_205(&s2_as_ntt));
  libcrux_ml_dsa_encoding_t0_deserialize_ಗಮ್ಯ_ಸದಿಶ_then_ntt_37(t0_serialized,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_205(&t0_as_ntt));
  Eurydice_arr_5a ಮಾತೃಕೆ;
  Eurydice_arr_a3 repeat_expression3[30U];
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)30U; i++)
  {
    repeat_expression3[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  ಸ್ಮರಣೆ_ನಕಲು(ಮಾತೃಕೆ.ದತ್ತಾಂಶ, repeat_expression3, (ಗಾತ್ರ_t)30U * ಗಾತ್ರ (Eurydice_arr_a3));
  libcrux_ml_dsa_samplex4_portable_ಮಾತೃಕೆ_flat_a8_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_ಒಳ_A,
    ಬೀಜ_for_a,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_203(&ಮಾತೃಕೆ));
  Eurydice_arr_c7 ಸಂದೇಶ_representative = { .ದತ್ತಾಂಶ = { 0U } };
  libcrux_ml_dsa_ml_dsa_generic_derive_ಸಂದೇಶ_representative_43(verification_ಕೀಲಿ_hash,
    &domain_separation_context,
    ಸಂದೇಶ_2,
    &ಸಂದೇಶ_representative);
  Eurydice_arr_c7 ಮುಖವಾಡ_ಬೀಜ = { .ದತ್ತಾಂಶ = { 0U } };
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
  shake0 = libcrux_ml_dsa_hash_functions_portable_init_26();
  libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake0, ಬೀಜ_for_signing);
  libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake0,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_01(&randomness));
  libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake0,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_17(&ಸಂದೇಶ_representative));
  libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake0,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_17(&ಮುಖವಾಡ_ಬೀಜ));
  uint16_t domain_separator_for_ಮುಖವಾಡ = 0U;
  ಗಾತ್ರ_t attempt = (ಗಾತ್ರ_t)0U;
  core_option_Option_81 commitment_hash0 = { .ಟ್ಯಾಗ್ = core_option_None };
  core_option_Option_1e signer_response0 = { .ಟ್ಯಾಗ್ = core_option_None };
  core_option_Option_05 hint0 = { .ಟ್ಯಾಗ್ = core_option_None };
  ಆಗ (attempt < LIBCRUX_ML_DSA_CONSTANTS_REJECTION_SAMPLE_BOUND_SIGN)
  {
    attempt++;
    Eurydice_arr_5d ಮುಖವಾಡ;
    Eurydice_arr_a3 repeat_expression4[5U];
    ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)5U; i++)
    {
      repeat_expression4[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    ಸ್ಮರಣೆ_ನಕಲು(ಮುಖವಾಡ.ದತ್ತಾಂಶ, repeat_expression4, (ಗಾತ್ರ_t)5U * ಗಾತ್ರ (Eurydice_arr_a3));
    Eurydice_arr_dc1 w0;
    Eurydice_arr_a3 repeat_expression5[6U];
    ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)6U; i++)
    {
      repeat_expression5[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    ಸ್ಮರಣೆ_ನಕಲು(w0.ದತ್ತಾಂಶ, repeat_expression5, (ಗಾತ್ರ_t)6U * ಗಾತ್ರ (Eurydice_arr_a3));
    Eurydice_arr_dc1 commitment;
    Eurydice_arr_a3 repeat_expression6[6U];
    ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)6U; i++)
    {
      repeat_expression6[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    ಸ್ಮರಣೆ_ನಕಲು(commitment.ದತ್ತಾಂಶ, repeat_expression6, (ಗಾತ್ರ_t)6U * ಗಾತ್ರ (Eurydice_arr_a3));
    libcrux_ml_dsa_sample_sample_ಮುಖವಾಡ_ಸದಿಶ_67(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_ಒಳ_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA1_EXPONENT,
      &ಮುಖವಾಡ_ಬೀಜ,
      &domain_separator_for_ಮುಖವಾಡ,
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_204(&ಮುಖವಾಡ));
    Eurydice_arr_dc1 a_x_ಮುಖವಾಡ;
    Eurydice_arr_a3 repeat_ಅಭಿವ್ಯಕ್ತಿ[6U];
    ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)6U; i++)
    {
      repeat_ಅಭಿವ್ಯಕ್ತಿ[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    ಸ್ಮರಣೆ_ನಕಲು(a_x_ಮುಖವಾಡ.ದತ್ತಾಂಶ, repeat_ಅಭಿವ್ಯಕ್ತಿ, (ಗಾತ್ರ_t)6U * ಗಾತ್ರ (Eurydice_arr_a3));
    Eurydice_arr_5d
    ಮುಖವಾಡ_ntt =
      core_array__core__clone__Clone_for__T__N___clone((ಗಾತ್ರ_t)5U,
        &ಮುಖವಾಡ,
        Eurydice_arr_a3,
        Eurydice_arr_5d);
    ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)5U; i++)
    {
      ಗಾತ್ರ_t i0 = i;
      libcrux_ml_dsa_ntt_ntt_37(&ಮುಖವಾಡ_ntt.ದತ್ತಾಂಶ[i0]);
    }
    libcrux_ml_dsa_ಮಾತೃಕೆ_compute_ಮಾತೃಕೆ_x_ಮುಖವಾಡ_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_ಒಳ_A,
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_205(&ಮಾತೃಕೆ),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_202(&ಮುಖವಾಡ_ntt),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_205(&a_x_ಮುಖವಾಡ));
    libcrux_ml_dsa_arithmetic_decompose_ಸದಿಶ_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA2,
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_204(&a_x_ಮುಖವಾಡ),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_205(&w0),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_205(&commitment));
    Eurydice_arr_65 commitment_hash_candidate = { .ದತ್ತಾಂಶ = { 0U } };
    Eurydice_arr_d2 commitment_serialized = { .ದತ್ತಾಂಶ = { 0U } };
    libcrux_ml_dsa_encoding_commitment_serialize_ಸದಿಶ_37(LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_COMMITMENT_RING_ELEMENT_ಗಾತ್ರ,
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_204(&commitment),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_27(&commitment_serialized));
    libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
    shake = libcrux_ml_dsa_hash_functions_portable_init_26();
    libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake,
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_17(&ಸಂದೇಶ_representative));
    libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake,
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_27(&commitment_serialized));
    libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake,
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_9f(&commitment_hash_candidate));
    Eurydice_arr_a3 verifier_challenge = libcrux_ml_dsa_polynomial_zero_ff_37();
    libcrux_ml_dsa_sample_sample_challenge_ring_element_2e(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_9f0(&commitment_hash_candidate),
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ONES_ಒಳ_VERIFIER_CHALLENGE,
      &verifier_challenge);
    libcrux_ml_dsa_ntt_ntt_37(&verifier_challenge);
    Eurydice_arr_5d
    challenge_times_s1 =
      core_array__core__clone__Clone_for__T__N___clone((ಗಾತ್ರ_t)5U,
        &s1_as_ntt,
        Eurydice_arr_a3,
        Eurydice_arr_5d);
    Eurydice_arr_dc1
    challenge_times_s2 =
      core_array__core__clone__Clone_for__T__N___clone((ಗಾತ್ರ_t)6U,
        &s2_as_ntt,
        Eurydice_arr_a3,
        Eurydice_arr_dc1);
    libcrux_ml_dsa_ಮಾತೃಕೆ_ಸದಿಶ_times_ring_element_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_204(&challenge_times_s1),
      &verifier_challenge);
    libcrux_ml_dsa_ಮಾತೃಕೆ_ಸದಿಶ_times_ring_element_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_205(&challenge_times_s2),
      &verifier_challenge);
    libcrux_ml_dsa_ಮಾತೃಕೆ_ಕೂಡಿಸು_vectors_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_ಒಳ_A,
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_204(&ಮುಖವಾಡ),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_202(&challenge_times_s1));
    libcrux_ml_dsa_ಮಾತೃಕೆ_ಕಳೆ_vectors_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A,
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_205(&w0),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_204(&challenge_times_s2));
    ಆದರೆ
    (
      !libcrux_ml_dsa_arithmetic_ಸದಿಶ_infinity_norm_exceeds_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_202(&ಮುಖವಾಡ),
        (int32_t)((uint32_t)1 << (uint32_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA1_EXPONENT) -
          LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_BETA)
    )
    {
      ಆದರೆ
      (
        !libcrux_ml_dsa_arithmetic_ಸದಿಶ_infinity_norm_exceeds_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_204(&w0),
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA2 - LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_BETA)
      )
      {
        Eurydice_arr_dc1
        challenge_times_t0 =
          core_array__core__clone__Clone_for__T__N___clone((ಗಾತ್ರ_t)6U,
            &t0_as_ntt,
            Eurydice_arr_a3,
            Eurydice_arr_dc1);
        libcrux_ml_dsa_ಮಾತೃಕೆ_ಸದಿಶ_times_ring_element_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_205(&challenge_times_t0),
          &verifier_challenge);
        ಆದರೆ
        (
          !libcrux_ml_dsa_arithmetic_ಸದಿಶ_infinity_norm_exceeds_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_204(&challenge_times_t0),
            LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA2)
        )
        {
          libcrux_ml_dsa_ಮಾತೃಕೆ_ಕೂಡಿಸು_vectors_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A,
            Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_205(&w0),
            Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_204(&challenge_times_t0));
          Eurydice_arr_5d0
          hint_candidate =
            {
              .ದತ್ತಾಂಶ = {
                { .ದತ್ತಾಂಶ = { 0U } }, { .ದತ್ತಾಂಶ = { 0U } }, { .ದತ್ತಾಂಶ = { 0U } }, { .ದತ್ತಾಂಶ = { 0U } },
                { .ದತ್ತಾಂಶ = { 0U } }, { .ದತ್ತಾಂಶ = { 0U } }
              }
            };
          ಗಾತ್ರ_t
          ones_ಒಳ_hint =
            libcrux_ml_dsa_arithmetic_make_hint_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_204(&w0),
              Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_204(&commitment),
              LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA2,
              Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_860(&hint_candidate));
          ಆದರೆ (!(ones_ಒಳ_hint > LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_MAX_ONES_ಒಳ_HINT))
          {
            attempt = LIBCRUX_ML_DSA_CONSTANTS_REJECTION_SAMPLE_BOUND_SIGN;
            commitment_hash0 =
              (
                KRML_CLITERAL(core_option_Option_81){
                  .ಟ್ಯಾಗ್ = core_option_Some,
                  .f0 = commitment_hash_candidate
                }
              );
            signer_response0 =
              (KRML_CLITERAL(core_option_Option_1e){ .ಟ್ಯಾಗ್ = core_option_Some, .f0 = ಮುಖವಾಡ });
            hint0 =
              (
                KRML_CLITERAL(core_option_Option_05){
                  .ಟ್ಯಾಗ್ = core_option_Some,
                  .f0 = hint_candidate
                }
              );
          }
        }
      }
    }
  }
  core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_53 uu____5;
  ಆದರೆ (commitment_hash0.ಟ್ಯಾಗ್ == core_option_None)
  {
    uu____5 =
      (
        KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_53){
          .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Err,
          .f0 = libcrux_ml_dsa_types_SigningError_RejectionSamplingError
        }
      );
  }
  ಇಲ್ಲದಿದ್ದರೆ
  {
    Eurydice_arr_65 commitment_hash = commitment_hash0.f0;
    Eurydice_arr_65 commitment_hash1 = commitment_hash;
    ಆದರೆ (signer_response0.ಟ್ಯಾಗ್ == core_option_None)
    {
      uu____5 =
        (
          KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_53){
            .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Err,
            .f0 = libcrux_ml_dsa_types_SigningError_RejectionSamplingError
          }
        );
    }
    ಇಲ್ಲದಿದ್ದರೆ
    {
      Eurydice_arr_5d signer_response = signer_response0.f0;
      Eurydice_arr_5d signer_response1 = signer_response;
      ಆದರೆ (!(hint0.ಟ್ಯಾಗ್ == core_option_None))
      {
        Eurydice_arr_5d0 hint = hint0.f0;
        Eurydice_arr_5d0 hint1 = hint;
        libcrux_ml_dsa_encoding_signature_serialize_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_9f0(&commitment_hash1),
          Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_202(&signer_response1),
          Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_860(&hint1),
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COMMITMENT_HASH_ಗಾತ್ರ,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_ಒಳ_A,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA1_EXPONENT,
          LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_GAMMA1_RING_ELEMENT_ಗಾತ್ರ,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_MAX_ONES_ಒಳ_HINT,
          Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_6b(signature));
        ಹಿಂತಿರುಗಿ (KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_53){ .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Ok });
      }
      uu____5 =
        (
          KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_53){
            .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Err,
            .f0 = libcrux_ml_dsa_types_SigningError_RejectionSamplingError
          }
        );
    }
  }
  ಹಿಂತಿರುಗಿ uu____5;
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_65.sign_mut
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_53
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_mut_5a(
  Eurydice_borrow_ತುಂಡು_u8 signing_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 context,
  Eurydice_arr_ec randomness,
  Eurydice_arr_0c *signature
)
{
  core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_a8
  uu____0 =
    libcrux_ml_dsa_pre_hash_new_88(context,
      (KRML_CLITERAL(core_option_Option_57){ .ಟ್ಯಾಗ್ = core_option_None }));
  ಆದರೆ (!(uu____0.ಟ್ಯಾಗ್ == core_ಫಲಿತಾಂಶ_Ok))
  {
    ಹಿಂತಿರುಗಿ
      (
        KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_53){
          .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Err,
          .f0 = libcrux_ml_dsa_types_SigningError_ContextTooLongError
        }
      );
  }
  libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
  libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
  ಹಿಂತಿರುಗಿ
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_ಆಂತರಿಕ_5a(signing_ಕೀಲಿ,
      ಸಂದೇಶ_2,
      (
        KRML_CLITERAL(core_option_Option_84){
          .ಟ್ಯಾಗ್ = core_option_Some,
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
ಸ್ಥಿರ KRML_MUSTINLINE core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_8c
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_5a(
  Eurydice_borrow_ತುಂಡು_u8 signing_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 context,
  Eurydice_arr_ec randomness
)
{
  Eurydice_arr_0c signature = libcrux_ml_dsa_types_zero_c5_5c();
  core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_53
  uu____0 =
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_mut_5a(signing_ಕೀಲಿ,
      ಸಂದೇಶ_2,
      context,
      randomness,
      &signature);
  core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_8c uu____1;
  ಆದರೆ (uu____0.ಟ್ಯಾಗ್ == core_ಫಲಿತಾಂಶ_Ok)
  {
    uu____1 =
      (
        KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_8c){
          .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Ok,
          .val = { .case_Ok = signature }
        }
      );
  }
  ಇಲ್ಲದಿದ್ದರೆ
  {
    libcrux_ml_dsa_types_SigningError e = uu____0.f0;
    uu____1 =
      (KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_8c){ .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Err, .val = { .case_Err = e } });
  }
  ಹಿಂತಿರುಗಿ uu____1;
}

/**
 Sign.
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_8c
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_sign(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_24 *signing_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 context,
  Eurydice_arr_ec randomness
)
{
  ಹಿಂತಿರುಗಿ
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_5a(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_98(signing_ಕೀಲಿ),
      ಸಂದೇಶ_2,
      context,
      randomness);
}

/**
 Sign.
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_53
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_sign_mut(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_24 *signing_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 context,
  Eurydice_arr_ec randomness,
  Eurydice_arr_0c *signature
)
{
  ಹಿಂತಿರುಗಿ
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_mut_5a(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_98(signing_ಕೀಲಿ),
      ಸಂದೇಶ_2,
      context,
      randomness,
      signature);
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_65.sign_pre_hashed_mut
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4, libcrux_ml_dsa_pre_hash_SHAKE128_PH
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_53
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_pre_hashed_mut_3f(
  Eurydice_borrow_ತುಂಡು_u8 signing_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 context,
  Eurydice_mut_borrow_ತುಂಡು_u8 pre_hash_ಬಫರ್,
  Eurydice_arr_ec randomness,
  Eurydice_arr_0c *signature
)
{
  ಆದರೆ (!(context.meta > LIBCRUX_ML_DSA_CONSTANTS_CONTEXT_MAX_LEN))
  {
    libcrux_ml_dsa_pre_hash_hash_30_83(ಸಂದೇಶ_2, pre_hash_ಬಫರ್);
    core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_a8
    uu____0 =
      libcrux_ml_dsa_pre_hash_new_88(context,
        (
          KRML_CLITERAL(core_option_Option_57){
            .ಟ್ಯಾಗ್ = core_option_Some,
            .f0 = libcrux_ml_dsa_pre_hash_oid_30()
          }
        ));
    ಆದರೆ (!(uu____0.ಟ್ಯಾಗ್ == core_ಫಲಿತಾಂಶ_Ok))
    {
      ಹಿಂತಿರುಗಿ
        (
          KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_53){
            .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Err,
            .f0 = libcrux_ml_dsa_types_SigningError_ContextTooLongError
          }
        );
    }
    libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
    libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
    ಹಿಂತಿರುಗಿ
      libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_ಆಂತರಿಕ_5a(signing_ಕೀಲಿ,
        (
          KRML_CLITERAL(Eurydice_borrow_ತುಂಡು_u8){
            .ptr = pre_hash_ಬಫರ್.ptr,
            .meta = pre_hash_ಬಫರ್.meta
          }
        ),
        (
          KRML_CLITERAL(core_option_Option_84){
            .ಟ್ಯಾಗ್ = core_option_Some,
            .f0 = domain_separation_context
          }
        ),
        randomness,
        signature);
  }
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_53){
        .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Err,
        .f0 = libcrux_ml_dsa_types_SigningError_ContextTooLongError
      }
    );
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_65.sign_pre_hashed
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4, libcrux_ml_dsa_pre_hash_SHAKE128_PH
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_8c
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_pre_hashed_3f(
  Eurydice_borrow_ತುಂಡು_u8 signing_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 context,
  Eurydice_mut_borrow_ತುಂಡು_u8 pre_hash_ಬಫರ್,
  Eurydice_arr_ec randomness
)
{
  Eurydice_arr_0c signature = libcrux_ml_dsa_types_zero_c5_5c();
  core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_53
  uu____0 =
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_pre_hashed_mut_3f(signing_ಕೀಲಿ,
      ಸಂದೇಶ_2,
      context,
      pre_hash_ಬಫರ್,
      randomness,
      &signature);
  core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_8c uu____1;
  ಆದರೆ (uu____0.ಟ್ಯಾಗ್ == core_ಫಲಿತಾಂಶ_Ok)
  {
    uu____1 =
      (
        KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_8c){
          .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Ok,
          .val = { .case_Ok = signature }
        }
      );
  }
  ಇಲ್ಲದಿದ್ದರೆ
  {
    libcrux_ml_dsa_types_SigningError e = uu____0.f0;
    uu____1 =
      (KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_8c){ .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Err, .val = { .case_Err = e } });
  }
  ಹಿಂತಿರುಗಿ uu____1;
}

/**
 Sign (pre-hashed).
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_8c
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_sign_pre_hashed_shake128(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_24 *signing_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 context,
  Eurydice_mut_borrow_ತುಂಡು_u8 pre_hash_ಬಫರ್,
  Eurydice_arr_ec randomness
)
{
  ಹಿಂತಿರುಗಿ
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_sign_pre_hashed_3f(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_98(signing_ಕೀಲಿ),
      ಸಂದೇಶ_2,
      context,
      pre_hash_ಬಫರ್,
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
ಸ್ಥಿರ KRML_MUSTINLINE core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_verify_ಆಂತರಿಕ_5a(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_29 *verification_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  core_option_Option_84 domain_separation_context,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_0c *signature_serialized
)
{
  Eurydice_borrow_ತುಂಡು_u8_x2
  uu____0 =
    Eurydice_ತುಂಡು_ವಿಭಜಿಸು_at(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_37(verification_ಕೀಲಿ),
      LIBCRUX_ML_DSA_CONSTANTS_ಬೀಜ_FOR_A_ಗಾತ್ರ,
      uint8_t,
      Eurydice_borrow_ತುಂಡು_u8_x2);
  Eurydice_borrow_ತುಂಡು_u8 ಬೀಜ_for_a = uu____0.fst;
  Eurydice_borrow_ತುಂಡು_u8 t1_serialized = uu____0.snd;
  Eurydice_arr_dc1 t1;
  Eurydice_arr_a3 repeat_expression0[6U];
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)6U; i++)
  {
    repeat_expression0[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  ಸ್ಮರಣೆ_ನಕಲು(t1.ದತ್ತಾಂಶ, repeat_expression0, (ಗಾತ್ರ_t)6U * ಗಾತ್ರ (Eurydice_arr_a3));
  libcrux_ml_dsa_encoding_verification_ಕೀಲಿ_deserialize_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_VERIFICATION_ಕೀಲಿ_ಗಾತ್ರ,
    t1_serialized,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_205(&t1));
  Eurydice_arr_65 deserialized_commitment_hash = { .ದತ್ತಾಂಶ = { 0U } };
  Eurydice_arr_5d deserialized_signer_response;
  Eurydice_arr_a3 repeat_expression1[5U];
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)5U; i++)
  {
    repeat_expression1[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  ಸ್ಮರಣೆ_ನಕಲು(deserialized_signer_response.ದತ್ತಾಂಶ,
    repeat_expression1,
    (ಗಾತ್ರ_t)5U * ಗಾತ್ರ (Eurydice_arr_a3));
  Eurydice_arr_5d0
  deserialized_hint =
    {
      .ದತ್ತಾಂಶ = {
        { .ದತ್ತಾಂಶ = { 0U } }, { .ದತ್ತಾಂಶ = { 0U } }, { .ದತ್ತಾಂಶ = { 0U } }, { .ದತ್ತಾಂಶ = { 0U } },
        { .ದತ್ತಾಂಶ = { 0U } }, { .ದತ್ತಾಂಶ = { 0U } }
      }
    };
  core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41
  uu____1 =
    libcrux_ml_dsa_encoding_signature_deserialize_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_ಒಳ_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COMMITMENT_HASH_ಗಾತ್ರ,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA1_EXPONENT,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_GAMMA1_RING_ELEMENT_ಗಾತ್ರ,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_MAX_ONES_ಒಳ_HINT,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_SIGNATURE_ಗಾತ್ರ,
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_6b(signature_serialized),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_9f(&deserialized_commitment_hash),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_204(&deserialized_signer_response),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_860(&deserialized_hint));
  core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41 uu____2;
  ಆದರೆ (uu____1.ಟ್ಯಾಗ್ == core_ಫಲಿತಾಂಶ_Ok)
  {
    ಆದರೆ
    (
      libcrux_ml_dsa_arithmetic_ಸದಿಶ_infinity_norm_exceeds_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_202(&deserialized_signer_response),
        (int32_t)((uint32_t)1 << (uint32_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA1_EXPONENT) -
          LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_BETA)
    )
    {
      uu____2 =
        (
          KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41){
            .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Err,
            .f0 = libcrux_ml_dsa_types_VerificationError_SignerResponseExceedsBoundError
          }
        );
    }
    ಇಲ್ಲದಿದ್ದರೆ
    {
      Eurydice_arr_5a ಮಾತೃಕೆ;
      Eurydice_arr_a3 repeat_ಅಭಿವ್ಯಕ್ತಿ[30U];
      ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)30U; i++)
      {
        repeat_ಅಭಿವ್ಯಕ್ತಿ[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
      }
      ಸ್ಮರಣೆ_ನಕಲು(ಮಾತೃಕೆ.ದತ್ತಾಂಶ, repeat_ಅಭಿವ್ಯಕ್ತಿ, (ಗಾತ್ರ_t)30U * ಗಾತ್ರ (Eurydice_arr_a3));
      libcrux_ml_dsa_samplex4_portable_ಮಾತೃಕೆ_flat_a8_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_ಒಳ_A,
        ಬೀಜ_for_a,
        Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_203(&ಮಾತೃಕೆ));
      Eurydice_arr_c7 verification_ಕೀಲಿ_hash = { .ದತ್ತಾಂಶ = { 0U } };
      libcrux_ml_dsa_hash_functions_portable_shake256_61_c9(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_37(verification_ಕೀಲಿ),
        &verification_ಕೀಲಿ_hash);
      Eurydice_arr_c7 ಸಂದೇಶ_representative = { .ದತ್ತಾಂಶ = { 0U } };
      libcrux_ml_dsa_ml_dsa_generic_derive_ಸಂದೇಶ_representative_43(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_17(&verification_ಕೀಲಿ_hash),
        &domain_separation_context,
        ಸಂದೇಶ_2,
        &ಸಂದೇಶ_representative);
      Eurydice_arr_a3 verifier_challenge = libcrux_ml_dsa_polynomial_zero_ff_37();
      libcrux_ml_dsa_sample_sample_challenge_ring_element_2e(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_9f0(&deserialized_commitment_hash),
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ONES_ಒಳ_VERIFIER_CHALLENGE,
        &verifier_challenge);
      libcrux_ml_dsa_ntt_ntt_37(&verifier_challenge);
      ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)5U; i++)
      {
        ಗಾತ್ರ_t i0 = i;
        libcrux_ml_dsa_ntt_ntt_37(&deserialized_signer_response.ದತ್ತಾಂಶ[i0]);
      }
      libcrux_ml_dsa_ಮಾತೃಕೆ_compute_w_approx_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A,
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_COLUMNS_ಒಳ_A,
        Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_205(&ಮಾತೃಕೆ),
        Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_202(&deserialized_signer_response),
        &verifier_challenge,
        Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_205(&t1));
      Eurydice_arr_65 recomputed_commitment_hash = { .ದತ್ತಾಂಶ = { 0U } };
      libcrux_ml_dsa_arithmetic_use_hint_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_65_GAMMA2,
        Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_860(&deserialized_hint),
        Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_205(&t1));
      Eurydice_arr_d2 commitment_serialized = { .ದತ್ತಾಂಶ = { 0U } };
      libcrux_ml_dsa_encoding_commitment_serialize_ಸದಿಶ_37(LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_65_COMMITMENT_RING_ELEMENT_ಗಾತ್ರ,
        Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_204(&t1),
        Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_27(&commitment_serialized));
      libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
      shake = libcrux_ml_dsa_hash_functions_portable_init_26();
      libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake,
        Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_17(&ಸಂದೇಶ_representative));
      libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake,
        Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_27(&commitment_serialized));
      libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake,
        Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_9f(&recomputed_commitment_hash));
      ಆದರೆ
      (
        Eurydice_array_eq((ಗಾತ್ರ_t)48U,
          &deserialized_commitment_hash,
          &recomputed_commitment_hash,
          uint8_t)
      )
      {
        uu____2 = (KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41){ .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Ok });
      }
      ಇಲ್ಲದಿದ್ದರೆ
      {
        uu____2 =
          (
            KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41){
              .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Err,
              .f0 = libcrux_ml_dsa_types_Verification_Error_Commitment_Hashes_Dont_ಹೊಂದಿಕೆ_Error
            }
          );
      }
    }
  }
  ಇಲ್ಲದಿದ್ದರೆ
  {
    libcrux_ml_dsa_types_VerificationError e = uu____1.f0;
    uu____2 = (KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41){ .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Err, .f0 = e });
  }
  ಹಿಂತಿರುಗಿ uu____2;
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_65.verify
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_verify_5a(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_29 *verification_ಕೀಲಿ_serialized,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 context,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_0c *signature_serialized
)
{
  core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_a8
  uu____0 =
    libcrux_ml_dsa_pre_hash_new_88(context,
      (KRML_CLITERAL(core_option_Option_57){ .ಟ್ಯಾಗ್ = core_option_None }));
  ಆದರೆ (!(uu____0.ಟ್ಯಾಗ್ == core_ಫಲಿತಾಂಶ_Ok))
  {
    ಹಿಂತಿರುಗಿ
      (
        KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41){
          .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Err,
          .f0 = libcrux_ml_dsa_types_VerificationError_VerificationContextTooLongError
        }
      );
  }
  libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
  libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
  ಹಿಂತಿರುಗಿ
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_verify_ಆಂತರಿಕ_5a(verification_ಕೀಲಿ_serialized,
      ಸಂದೇಶ_2,
      (
        KRML_CLITERAL(core_option_Option_84){
          .ಟ್ಯಾಗ್ = core_option_Some,
          .f0 = domain_separation_context
        }
      ),
      signature_serialized);
}

/**
 Verify.
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_verify(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_29 *verification_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 context,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_0c *signature
)
{
  ಹಿಂತಿರುಗಿ
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_verify_5a(verification_ಕೀಲಿ,
      ಸಂದೇಶ_2,
      context,
      signature);
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_65.verify_pre_hashed
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_pre_hash_SHAKE128_PH
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_verify_pre_hashed_3f(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_29 *verification_ಕೀಲಿ_serialized,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 context,
  Eurydice_mut_borrow_ತುಂಡು_u8 pre_hash_ಬಫರ್,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_0c *signature_serialized
)
{
  libcrux_ml_dsa_pre_hash_hash_30_83(ಸಂದೇಶ_2, pre_hash_ಬಫರ್);
  core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_a8
  uu____0 =
    libcrux_ml_dsa_pre_hash_new_88(context,
      (
        KRML_CLITERAL(core_option_Option_57){
          .ಟ್ಯಾಗ್ = core_option_Some,
          .f0 = libcrux_ml_dsa_pre_hash_oid_30()
        }
      ));
  ಆದರೆ (!(uu____0.ಟ್ಯಾಗ್ == core_ಫಲಿತಾಂಶ_Ok))
  {
    ಹಿಂತಿರುಗಿ
      (
        KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41){
          .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Err,
          .f0 = libcrux_ml_dsa_types_VerificationError_VerificationContextTooLongError
        }
      );
  }
  libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
  libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
  ಹಿಂತಿರುಗಿ
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_verify_ಆಂತರಿಕ_5a(verification_ಕೀಲಿ_serialized,
      (
        KRML_CLITERAL(Eurydice_borrow_ತುಂಡು_u8){
          .ptr = pre_hash_ಬಫರ್.ptr,
          .meta = pre_hash_ಬಫರ್.meta
        }
      ),
      (
        KRML_CLITERAL(core_option_Option_84){
          .ಟ್ಯಾಗ್ = core_option_Some,
          .f0 = domain_separation_context
        }
      ),
      signature_serialized);
}

/**
 Verify (pre-hashed with SHAKE-128).
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_verify_pre_hashed_shake128(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_29 *verification_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 context,
  Eurydice_mut_borrow_ತುಂಡು_u8 pre_hash_ಬಫರ್,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_0c *signature
)
{
  ಹಿಂತಿರುಗಿ
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_verify_pre_hashed_3f(verification_ಕೀಲಿ,
      ಸಂದೇಶ_2,
      context,
      pre_hash_ಬಫರ್,
      signature);
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_87.generate_key_pair
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_generate_ಕೀಲಿ_pair_5a(
  Eurydice_arr_ec randomness,
  Eurydice_mut_borrow_ತುಂಡು_u8 signing_ಕೀಲಿ,
  Eurydice_mut_borrow_ತುಂಡು_u8 verification_ಕೀಲಿ
)
{
  Eurydice_arr_89 ಬೀಜ_expanded0 = { .ದತ್ತಾಂಶ = { 0U } };
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
  shake = libcrux_ml_dsa_hash_functions_portable_init_26();
  libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_01(&randomness));
  /* original Rust expression is not an lvalue in C */
  Eurydice_array_u8x2
  lvalue =
    {
      .ದತ್ತಾಂಶ = {
        (uint8_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A,
        (uint8_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_ಒಳ_A
      }
    };
  libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_82(&lvalue));
  libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_78(&ಬೀಜ_expanded0));
  Eurydice_borrow_ತುಂಡು_u8_x2
  uu____0 =
    Eurydice_ತುಂಡು_ವಿಭಜಿಸು_at(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_78(&ಬೀಜ_expanded0),
      LIBCRUX_ML_DSA_CONSTANTS_ಬೀಜ_FOR_A_ಗಾತ್ರ,
      uint8_t,
      Eurydice_borrow_ತುಂಡು_u8_x2);
  Eurydice_borrow_ತುಂಡು_u8 ಬೀಜ_for_a = uu____0.fst;
  Eurydice_borrow_ತುಂಡು_u8 ಬೀಜ_expanded = uu____0.snd;
  Eurydice_borrow_ತುಂಡು_u8_x2
  uu____1 =
    Eurydice_ತುಂಡು_ವಿಭಜಿಸು_at(ಬೀಜ_expanded,
      LIBCRUX_ML_DSA_CONSTANTS_ಬೀಜ_FOR_ERROR_VECTORS_ಗಾತ್ರ,
      uint8_t,
      Eurydice_borrow_ತುಂಡು_u8_x2);
  Eurydice_borrow_ತುಂಡು_u8 ಬೀಜ_for_error_vectors = uu____1.fst;
  Eurydice_borrow_ತುಂಡು_u8 ಬೀಜ_for_signing = uu____1.snd;
  Eurydice_arr_92 s1_s2;
  Eurydice_arr_a3 repeat_expression0[15U];
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)15U; i++)
  {
    repeat_expression0[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  ಸ್ಮರಣೆ_ನಕಲು(s1_s2.ದತ್ತಾಂಶ, repeat_expression0, (ಗಾತ್ರ_t)15U * ಗಾತ್ರ (Eurydice_arr_a3));
  libcrux_ml_dsa_samplex4_sample_s1_and_s2_29(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ETA,
    ಬೀಜ_for_error_vectors,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_206(&s1_s2));
  Eurydice_arr_8f t0;
  Eurydice_arr_a3 repeat_expression1[8U];
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)8U; i++)
  {
    repeat_expression1[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  ಸ್ಮರಣೆ_ನಕಲು(t0.ದತ್ತಾಂಶ, repeat_expression1, (ಗಾತ್ರ_t)8U * ಗಾತ್ರ (Eurydice_arr_a3));
  Eurydice_arr_0f a_as_ntt;
  Eurydice_arr_a3 repeat_expression2[56U];
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)56U; i++)
  {
    repeat_expression2[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  ಸ್ಮರಣೆ_ನಕಲು(a_as_ntt.ದತ್ತಾಂಶ, repeat_expression2, (ಗಾತ್ರ_t)56U * ಗಾತ್ರ (Eurydice_arr_a3));
  libcrux_ml_dsa_samplex4_portable_ಮಾತೃಕೆ_flat_a8_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_ಒಳ_A,
    ಬೀಜ_for_a,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_207(&a_as_ntt));
  Eurydice_arr_bb s1_ntt;
  Eurydice_arr_a3 repeat_expression3[7U];
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)7U; i++)
  {
    repeat_expression3[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  ಸ್ಮರಣೆ_ನಕಲು(s1_ntt.ದತ್ತಾಂಶ, repeat_expression3, (ಗಾತ್ರ_t)7U * ಗಾತ್ರ (Eurydice_arr_a3));
  Eurydice_ತುಂಡು_copy(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_208(&s1_ntt),
    Eurydice_array_ಗಮ್ಯ_subslice_shared_251(&s1_s2,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .ಆರಂಭ = (ಗಾತ್ರ_t)0U,
          .ಕೊನೆ = LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_ಒಳ_A
        }
      )),
    Eurydice_arr_a3);
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)7U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    libcrux_ml_dsa_ntt_ntt_37(&s1_ntt.ದತ್ತಾಂಶ[i0]);
  }
  libcrux_ml_dsa_ಮಾತೃಕೆ_compute_as1_plus_s2_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A,
    LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_ಒಳ_A,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_207(&a_as_ntt),
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_206(&s1_ntt),
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_207(&s1_s2),
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_20(&t0));
  Eurydice_arr_8f t1;
  Eurydice_arr_a3 repeat_ಅಭಿವ್ಯಕ್ತಿ[8U];
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)8U; i++)
  {
    repeat_ಅಭಿವ್ಯಕ್ತಿ[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  ಸ್ಮರಣೆ_ನಕಲು(t1.ದತ್ತಾಂಶ, repeat_ಅಭಿವ್ಯಕ್ತಿ, (ಗಾತ್ರ_t)8U * ಗಾತ್ರ (Eurydice_arr_a3));
  libcrux_ml_dsa_arithmetic_power2round_ಸದಿಶ_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_20(&t0),
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_20(&t1));
  libcrux_ml_dsa_encoding_verification_ಕೀಲಿ_generate_serialized_37(ಬೀಜ_for_a,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_200(&t1),
    verification_ಕೀಲಿ);
  libcrux_ml_dsa_encoding_signing_ಕೀಲಿ_generate_serialized_2e(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ETA,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_ERROR_RING_ELEMENT_ಗಾತ್ರ,
    ಬೀಜ_for_a,
    ಬೀಜ_for_signing,
    (
      KRML_CLITERAL(Eurydice_borrow_ತುಂಡು_u8){
        .ptr = verification_ಕೀಲಿ.ptr,
        .meta = verification_ಕೀಲಿ.meta
      }
    ),
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_207(&s1_s2),
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_200(&t0),
    signing_ಕೀಲಿ);
}

/**
 Generate key pair.
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_87_generate_ಕೀಲಿ_pair(
  Eurydice_arr_ec randomness,
  Eurydice_arr_e2 *signing_ಕೀಲಿ,
  Eurydice_arr_43 *verification_ಕೀಲಿ
)
{
  libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_generate_ಕೀಲಿ_pair_5a(randomness,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_f7(signing_ಕೀಲಿ),
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_fc(verification_ಕೀಲಿ));
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_87.sign_internal
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_53
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_sign_ಆಂತರಿಕ_5a(
  Eurydice_borrow_ತುಂಡು_u8 signing_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  core_option_Option_84 domain_separation_context,
  Eurydice_arr_ec randomness,
  Eurydice_arr_93 *signature
)
{
  Eurydice_borrow_ತುಂಡು_u8_x2
  uu____0 =
    Eurydice_ತುಂಡು_ವಿಭಜಿಸು_at(signing_ಕೀಲಿ,
      LIBCRUX_ML_DSA_CONSTANTS_ಬೀಜ_FOR_A_ಗಾತ್ರ,
      uint8_t,
      Eurydice_borrow_ತುಂಡು_u8_x2);
  Eurydice_borrow_ತುಂಡು_u8 ಬೀಜ_for_a = uu____0.fst;
  Eurydice_borrow_ತುಂಡು_u8 ಉಳಿದ_serialized0 = uu____0.snd;
  Eurydice_borrow_ತುಂಡು_u8_x2
  uu____1 =
    Eurydice_ತುಂಡು_ವಿಭಜಿಸು_at(ಉಳಿದ_serialized0,
      LIBCRUX_ML_DSA_CONSTANTS_ಬೀಜ_FOR_SIGNING_ಗಾತ್ರ,
      uint8_t,
      Eurydice_borrow_ತುಂಡು_u8_x2);
  Eurydice_borrow_ತುಂಡು_u8 ಬೀಜ_for_signing = uu____1.fst;
  Eurydice_borrow_ತುಂಡು_u8 ಉಳಿದ_serialized1 = uu____1.snd;
  Eurydice_borrow_ತುಂಡು_u8_x2
  uu____2 =
    Eurydice_ತುಂಡು_ವಿಭಜಿಸು_at(ಉಳಿದ_serialized1,
      LIBCRUX_ML_DSA_CONSTANTS_ಬೈಟುಗಳು_FOR_VERIFICATION_ಕೀಲಿ_HASH,
      uint8_t,
      Eurydice_borrow_ತುಂಡು_u8_x2);
  Eurydice_borrow_ತುಂಡು_u8 verification_ಕೀಲಿ_hash = uu____2.fst;
  Eurydice_borrow_ತುಂಡು_u8 ಉಳಿದ_serialized2 = uu____2.snd;
  Eurydice_borrow_ತುಂಡು_u8_x2
  uu____3 =
    Eurydice_ತುಂಡು_ವಿಭಜಿಸು_at(ಉಳಿದ_serialized2,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_ERROR_RING_ELEMENT_ಗಾತ್ರ *
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_ಒಳ_A,
      uint8_t,
      Eurydice_borrow_ತುಂಡು_u8_x2);
  Eurydice_borrow_ತುಂಡು_u8 s1_serialized = uu____3.fst;
  Eurydice_borrow_ತುಂಡು_u8 ಉಳಿದ_serialized = uu____3.snd;
  Eurydice_borrow_ತುಂಡು_u8_x2
  uu____4 =
    Eurydice_ತುಂಡು_ವಿಭಜಿಸು_at(ಉಳಿದ_serialized,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_ERROR_RING_ELEMENT_ಗಾತ್ರ *
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A,
      uint8_t,
      Eurydice_borrow_ತುಂಡು_u8_x2);
  Eurydice_borrow_ತುಂಡು_u8 s2_serialized = uu____4.fst;
  Eurydice_borrow_ತುಂಡು_u8 t0_serialized = uu____4.snd;
  Eurydice_arr_bb s1_as_ntt;
  Eurydice_arr_a3 repeat_expression0[7U];
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)7U; i++)
  {
    repeat_expression0[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  ಸ್ಮರಣೆ_ನಕಲು(s1_as_ntt.ದತ್ತಾಂಶ, repeat_expression0, (ಗಾತ್ರ_t)7U * ಗಾತ್ರ (Eurydice_arr_a3));
  Eurydice_arr_8f s2_as_ntt;
  Eurydice_arr_a3 repeat_expression1[8U];
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)8U; i++)
  {
    repeat_expression1[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  ಸ್ಮರಣೆ_ನಕಲು(s2_as_ntt.ದತ್ತಾಂಶ, repeat_expression1, (ಗಾತ್ರ_t)8U * ಗಾತ್ರ (Eurydice_arr_a3));
  Eurydice_arr_8f t0_as_ntt;
  Eurydice_arr_a3 repeat_expression2[8U];
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)8U; i++)
  {
    repeat_expression2[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  ಸ್ಮರಣೆ_ನಕಲು(t0_as_ntt.ದತ್ತಾಂಶ, repeat_expression2, (ಗಾತ್ರ_t)8U * ಗಾತ್ರ (Eurydice_arr_a3));
  libcrux_ml_dsa_encoding_error_deserialize_ಗಮ್ಯ_ಸದಿಶ_then_ntt_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ETA,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_ERROR_RING_ELEMENT_ಗಾತ್ರ,
    s1_serialized,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_208(&s1_as_ntt));
  libcrux_ml_dsa_encoding_error_deserialize_ಗಮ್ಯ_ಸದಿಶ_then_ntt_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ETA,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_ERROR_RING_ELEMENT_ಗಾತ್ರ,
    s2_serialized,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_20(&s2_as_ntt));
  libcrux_ml_dsa_encoding_t0_deserialize_ಗಮ್ಯ_ಸದಿಶ_then_ntt_37(t0_serialized,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_20(&t0_as_ntt));
  Eurydice_arr_0f ಮಾತೃಕೆ;
  Eurydice_arr_a3 repeat_expression3[56U];
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)56U; i++)
  {
    repeat_expression3[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  ಸ್ಮರಣೆ_ನಕಲು(ಮಾತೃಕೆ.ದತ್ತಾಂಶ, repeat_expression3, (ಗಾತ್ರ_t)56U * ಗಾತ್ರ (Eurydice_arr_a3));
  libcrux_ml_dsa_samplex4_portable_ಮಾತೃಕೆ_flat_a8_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_ಒಳ_A,
    ಬೀಜ_for_a,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_207(&ಮಾತೃಕೆ));
  Eurydice_arr_c7 ಸಂದೇಶ_representative = { .ದತ್ತಾಂಶ = { 0U } };
  libcrux_ml_dsa_ml_dsa_generic_derive_ಸಂದೇಶ_representative_43(verification_ಕೀಲಿ_hash,
    &domain_separation_context,
    ಸಂದೇಶ_2,
    &ಸಂದೇಶ_representative);
  Eurydice_arr_c7 ಮುಖವಾಡ_ಬೀಜ = { .ದತ್ತಾಂಶ = { 0U } };
  libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
  shake0 = libcrux_ml_dsa_hash_functions_portable_init_26();
  libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake0, ಬೀಜ_for_signing);
  libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake0,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_01(&randomness));
  libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake0,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_17(&ಸಂದೇಶ_representative));
  libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake0,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_17(&ಮುಖವಾಡ_ಬೀಜ));
  uint16_t domain_separator_for_ಮುಖವಾಡ = 0U;
  ಗಾತ್ರ_t attempt = (ಗಾತ್ರ_t)0U;
  core_option_Option_b2 commitment_hash0 = { .ಟ್ಯಾಗ್ = core_option_None };
  core_option_Option_2d signer_response0 = { .ಟ್ಯಾಗ್ = core_option_None };
  core_option_Option_45 hint0 = { .ಟ್ಯಾಗ್ = core_option_None };
  ಆಗ (attempt < LIBCRUX_ML_DSA_CONSTANTS_REJECTION_SAMPLE_BOUND_SIGN)
  {
    attempt++;
    Eurydice_arr_bb ಮುಖವಾಡ;
    Eurydice_arr_a3 repeat_expression4[7U];
    ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)7U; i++)
    {
      repeat_expression4[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    ಸ್ಮರಣೆ_ನಕಲು(ಮುಖವಾಡ.ದತ್ತಾಂಶ, repeat_expression4, (ಗಾತ್ರ_t)7U * ಗಾತ್ರ (Eurydice_arr_a3));
    Eurydice_arr_8f w0;
    Eurydice_arr_a3 repeat_expression5[8U];
    ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)8U; i++)
    {
      repeat_expression5[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    ಸ್ಮರಣೆ_ನಕಲು(w0.ದತ್ತಾಂಶ, repeat_expression5, (ಗಾತ್ರ_t)8U * ಗಾತ್ರ (Eurydice_arr_a3));
    Eurydice_arr_8f commitment;
    Eurydice_arr_a3 repeat_expression6[8U];
    ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)8U; i++)
    {
      repeat_expression6[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    ಸ್ಮರಣೆ_ನಕಲು(commitment.ದತ್ತಾಂಶ, repeat_expression6, (ಗಾತ್ರ_t)8U * ಗಾತ್ರ (Eurydice_arr_a3));
    libcrux_ml_dsa_sample_sample_ಮುಖವಾಡ_ಸದಿಶ_67(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_ಒಳ_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_GAMMA1_EXPONENT,
      &ಮುಖವಾಡ_ಬೀಜ,
      &domain_separator_for_ಮುಖವಾಡ,
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_208(&ಮುಖವಾಡ));
    Eurydice_arr_8f a_x_ಮುಖವಾಡ;
    Eurydice_arr_a3 repeat_ಅಭಿವ್ಯಕ್ತಿ[8U];
    ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)8U; i++)
    {
      repeat_ಅಭಿವ್ಯಕ್ತಿ[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
    }
    ಸ್ಮರಣೆ_ನಕಲು(a_x_ಮುಖವಾಡ.ದತ್ತಾಂಶ, repeat_ಅಭಿವ್ಯಕ್ತಿ, (ಗಾತ್ರ_t)8U * ಗಾತ್ರ (Eurydice_arr_a3));
    Eurydice_arr_bb
    ಮುಖವಾಡ_ntt =
      core_array__core__clone__Clone_for__T__N___clone((ಗಾತ್ರ_t)7U,
        &ಮುಖವಾಡ,
        Eurydice_arr_a3,
        Eurydice_arr_bb);
    ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)7U; i++)
    {
      ಗಾತ್ರ_t i0 = i;
      libcrux_ml_dsa_ntt_ntt_37(&ಮುಖವಾಡ_ntt.ದತ್ತಾಂಶ[i0]);
    }
    libcrux_ml_dsa_ಮಾತೃಕೆ_compute_ಮಾತೃಕೆ_x_ಮುಖವಾಡ_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_ಒಳ_A,
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_208(&ಮಾತೃಕೆ),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_206(&ಮುಖವಾಡ_ntt),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_20(&a_x_ಮುಖವಾಡ));
    libcrux_ml_dsa_arithmetic_decompose_ಸದಿಶ_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_GAMMA2,
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_200(&a_x_ಮುಖವಾಡ),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_20(&w0),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_20(&commitment));
    Eurydice_arr_c7 commitment_hash_candidate = { .ದತ್ತಾಂಶ = { 0U } };
    Eurydice_arr_1b commitment_serialized = { .ದತ್ತಾಂಶ = { 0U } };
    libcrux_ml_dsa_encoding_commitment_serialize_ಸದಿಶ_37(LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_COMMITMENT_RING_ELEMENT_ಗಾತ್ರ,
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_200(&commitment),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_68(&commitment_serialized));
    libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
    shake = libcrux_ml_dsa_hash_functions_portable_init_26();
    libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake,
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_17(&ಸಂದೇಶ_representative));
    libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake,
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_68(&commitment_serialized));
    libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake,
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_17(&commitment_hash_candidate));
    Eurydice_arr_a3 verifier_challenge = libcrux_ml_dsa_polynomial_zero_ff_37();
    libcrux_ml_dsa_sample_sample_challenge_ring_element_2e(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_17(&commitment_hash_candidate),
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ONES_ಒಳ_VERIFIER_CHALLENGE,
      &verifier_challenge);
    libcrux_ml_dsa_ntt_ntt_37(&verifier_challenge);
    Eurydice_arr_bb
    challenge_times_s1 =
      core_array__core__clone__Clone_for__T__N___clone((ಗಾತ್ರ_t)7U,
        &s1_as_ntt,
        Eurydice_arr_a3,
        Eurydice_arr_bb);
    Eurydice_arr_8f
    challenge_times_s2 =
      core_array__core__clone__Clone_for__T__N___clone((ಗಾತ್ರ_t)8U,
        &s2_as_ntt,
        Eurydice_arr_a3,
        Eurydice_arr_8f);
    libcrux_ml_dsa_ಮಾತೃಕೆ_ಸದಿಶ_times_ring_element_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_208(&challenge_times_s1),
      &verifier_challenge);
    libcrux_ml_dsa_ಮಾತೃಕೆ_ಸದಿಶ_times_ring_element_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_20(&challenge_times_s2),
      &verifier_challenge);
    libcrux_ml_dsa_ಮಾತೃಕೆ_ಕೂಡಿಸು_vectors_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_ಒಳ_A,
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_208(&ಮುಖವಾಡ),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_206(&challenge_times_s1));
    libcrux_ml_dsa_ಮಾತೃಕೆ_ಕಳೆ_vectors_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A,
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_20(&w0),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_200(&challenge_times_s2));
    ಆದರೆ
    (
      !libcrux_ml_dsa_arithmetic_ಸದಿಶ_infinity_norm_exceeds_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_206(&ಮುಖವಾಡ),
        (int32_t)((uint32_t)1 << (uint32_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_GAMMA1_EXPONENT) -
          LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_BETA)
    )
    {
      ಆದರೆ
      (
        !libcrux_ml_dsa_arithmetic_ಸದಿಶ_infinity_norm_exceeds_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_200(&w0),
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_GAMMA2 - LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_BETA)
      )
      {
        Eurydice_arr_8f
        challenge_times_t0 =
          core_array__core__clone__Clone_for__T__N___clone((ಗಾತ್ರ_t)8U,
            &t0_as_ntt,
            Eurydice_arr_a3,
            Eurydice_arr_8f);
        libcrux_ml_dsa_ಮಾತೃಕೆ_ಸದಿಶ_times_ring_element_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_20(&challenge_times_t0),
          &verifier_challenge);
        ಆದರೆ
        (
          !libcrux_ml_dsa_arithmetic_ಸದಿಶ_infinity_norm_exceeds_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_200(&challenge_times_t0),
            LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_GAMMA2)
        )
        {
          libcrux_ml_dsa_ಮಾತೃಕೆ_ಕೂಡಿಸು_vectors_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A,
            Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_20(&w0),
            Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_200(&challenge_times_t0));
          Eurydice_arr_81
          hint_candidate =
            {
              .ದತ್ತಾಂಶ = {
                { .ದತ್ತಾಂಶ = { 0U } }, { .ದತ್ತಾಂಶ = { 0U } }, { .ದತ್ತಾಂಶ = { 0U } }, { .ದತ್ತಾಂಶ = { 0U } },
                { .ದತ್ತಾಂಶ = { 0U } }, { .ದತ್ತಾಂಶ = { 0U } }, { .ದತ್ತಾಂಶ = { 0U } }, { .ದತ್ತಾಂಶ = { 0U } }
              }
            };
          ಗಾತ್ರ_t
          ones_ಒಳ_hint =
            libcrux_ml_dsa_arithmetic_make_hint_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_200(&w0),
              Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_200(&commitment),
              LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_GAMMA2,
              Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_861(&hint_candidate));
          ಆದರೆ (!(ones_ಒಳ_hint > LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_MAX_ONES_ಒಳ_HINT))
          {
            attempt = LIBCRUX_ML_DSA_CONSTANTS_REJECTION_SAMPLE_BOUND_SIGN;
            commitment_hash0 =
              (
                KRML_CLITERAL(core_option_Option_b2){
                  .ಟ್ಯಾಗ್ = core_option_Some,
                  .f0 = commitment_hash_candidate
                }
              );
            signer_response0 =
              (KRML_CLITERAL(core_option_Option_2d){ .ಟ್ಯಾಗ್ = core_option_Some, .f0 = ಮುಖವಾಡ });
            hint0 =
              (
                KRML_CLITERAL(core_option_Option_45){
                  .ಟ್ಯಾಗ್ = core_option_Some,
                  .f0 = hint_candidate
                }
              );
          }
        }
      }
    }
  }
  core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_53 uu____5;
  ಆದರೆ (commitment_hash0.ಟ್ಯಾಗ್ == core_option_None)
  {
    uu____5 =
      (
        KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_53){
          .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Err,
          .f0 = libcrux_ml_dsa_types_SigningError_RejectionSamplingError
        }
      );
  }
  ಇಲ್ಲದಿದ್ದರೆ
  {
    Eurydice_arr_c7 commitment_hash = commitment_hash0.f0;
    Eurydice_arr_c7 commitment_hash1 = commitment_hash;
    ಆದರೆ (signer_response0.ಟ್ಯಾಗ್ == core_option_None)
    {
      uu____5 =
        (
          KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_53){
            .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Err,
            .f0 = libcrux_ml_dsa_types_SigningError_RejectionSamplingError
          }
        );
    }
    ಇಲ್ಲದಿದ್ದರೆ
    {
      Eurydice_arr_bb signer_response = signer_response0.f0;
      Eurydice_arr_bb signer_response1 = signer_response;
      ಆದರೆ (!(hint0.ಟ್ಯಾಗ್ == core_option_None))
      {
        Eurydice_arr_81 hint = hint0.f0;
        Eurydice_arr_81 hint1 = hint;
        libcrux_ml_dsa_encoding_signature_serialize_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_17(&commitment_hash1),
          Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_206(&signer_response1),
          Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_861(&hint1),
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COMMITMENT_HASH_ಗಾತ್ರ,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_ಒಳ_A,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_GAMMA1_EXPONENT,
          LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_GAMMA1_RING_ELEMENT_ಗಾತ್ರ,
          LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_MAX_ONES_ಒಳ_HINT,
          Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_11(signature));
        ಹಿಂತಿರುಗಿ (KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_53){ .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Ok });
      }
      uu____5 =
        (
          KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_53){
            .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Err,
            .f0 = libcrux_ml_dsa_types_SigningError_RejectionSamplingError
          }
        );
    }
  }
  ಹಿಂತಿರುಗಿ uu____5;
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_87.sign_mut
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_53
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_sign_mut_5a(
  Eurydice_borrow_ತುಂಡು_u8 signing_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 context,
  Eurydice_arr_ec randomness,
  Eurydice_arr_93 *signature
)
{
  core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_a8
  uu____0 =
    libcrux_ml_dsa_pre_hash_new_88(context,
      (KRML_CLITERAL(core_option_Option_57){ .ಟ್ಯಾಗ್ = core_option_None }));
  ಆದರೆ (!(uu____0.ಟ್ಯಾಗ್ == core_ಫಲಿತಾಂಶ_Ok))
  {
    ಹಿಂತಿರುಗಿ
      (
        KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_53){
          .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Err,
          .f0 = libcrux_ml_dsa_types_SigningError_ContextTooLongError
        }
      );
  }
  libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
  libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
  ಹಿಂತಿರುಗಿ
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_sign_ಆಂತರಿಕ_5a(signing_ಕೀಲಿ,
      ಸಂದೇಶ_2,
      (
        KRML_CLITERAL(core_option_Option_84){
          .ಟ್ಯಾಗ್ = core_option_Some,
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
ಸ್ಥಿರ KRML_MUSTINLINE core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_8b
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_sign_5a(
  Eurydice_borrow_ತುಂಡು_u8 signing_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 context,
  Eurydice_arr_ec randomness
)
{
  Eurydice_arr_93 signature = libcrux_ml_dsa_types_zero_c5_f1();
  core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_53
  uu____0 =
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_sign_mut_5a(signing_ಕೀಲಿ,
      ಸಂದೇಶ_2,
      context,
      randomness,
      &signature);
  core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_8b uu____1;
  ಆದರೆ (uu____0.ಟ್ಯಾಗ್ == core_ಫಲಿತಾಂಶ_Ok)
  {
    uu____1 =
      (
        KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_8b){
          .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Ok,
          .val = { .case_Ok = signature }
        }
      );
  }
  ಇಲ್ಲದಿದ್ದರೆ
  {
    libcrux_ml_dsa_types_SigningError e = uu____0.f0;
    uu____1 =
      (KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_8b){ .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Err, .val = { .case_Err = e } });
  }
  ಹಿಂತಿರುಗಿ uu____1;
}

/**
 Sign.
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_8b
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_87_sign(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_e2 *signing_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 context,
  Eurydice_arr_ec randomness
)
{
  ಹಿಂತಿರುಗಿ
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_sign_5a(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_f7(signing_ಕೀಲಿ),
      ಸಂದೇಶ_2,
      context,
      randomness);
}

/**
 Sign.
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_53
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_87_sign_mut(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_e2 *signing_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 context,
  Eurydice_arr_ec randomness,
  Eurydice_arr_93 *signature
)
{
  ಹಿಂತಿರುಗಿ
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_sign_mut_5a(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_f7(signing_ಕೀಲಿ),
      ಸಂದೇಶ_2,
      context,
      randomness,
      signature);
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_87.sign_pre_hashed_mut
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4, libcrux_ml_dsa_pre_hash_SHAKE128_PH
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_53
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_sign_pre_hashed_mut_3f(
  Eurydice_borrow_ತುಂಡು_u8 signing_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 context,
  Eurydice_mut_borrow_ತುಂಡು_u8 pre_hash_ಬಫರ್,
  Eurydice_arr_ec randomness,
  Eurydice_arr_93 *signature
)
{
  ಆದರೆ (!(context.meta > LIBCRUX_ML_DSA_CONSTANTS_CONTEXT_MAX_LEN))
  {
    libcrux_ml_dsa_pre_hash_hash_30_83(ಸಂದೇಶ_2, pre_hash_ಬಫರ್);
    core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_a8
    uu____0 =
      libcrux_ml_dsa_pre_hash_new_88(context,
        (
          KRML_CLITERAL(core_option_Option_57){
            .ಟ್ಯಾಗ್ = core_option_Some,
            .f0 = libcrux_ml_dsa_pre_hash_oid_30()
          }
        ));
    ಆದರೆ (!(uu____0.ಟ್ಯಾಗ್ == core_ಫಲಿತಾಂಶ_Ok))
    {
      ಹಿಂತಿರುಗಿ
        (
          KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_53){
            .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Err,
            .f0 = libcrux_ml_dsa_types_SigningError_ContextTooLongError
          }
        );
    }
    libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
    libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
    ಹಿಂತಿರುಗಿ
      libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_sign_ಆಂತರಿಕ_5a(signing_ಕೀಲಿ,
        (
          KRML_CLITERAL(Eurydice_borrow_ತುಂಡು_u8){
            .ptr = pre_hash_ಬಫರ್.ptr,
            .meta = pre_hash_ಬಫರ್.meta
          }
        ),
        (
          KRML_CLITERAL(core_option_Option_84){
            .ಟ್ಯಾಗ್ = core_option_Some,
            .f0 = domain_separation_context
          }
        ),
        randomness,
        signature);
  }
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_53){
        .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Err,
        .f0 = libcrux_ml_dsa_types_SigningError_ContextTooLongError
      }
    );
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_87.sign_pre_hashed
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_hash_functions_portable_Shake256X4, libcrux_ml_dsa_pre_hash_SHAKE128_PH
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_8b
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_sign_pre_hashed_3f(
  Eurydice_borrow_ತುಂಡು_u8 signing_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 context,
  Eurydice_mut_borrow_ತುಂಡು_u8 pre_hash_ಬಫರ್,
  Eurydice_arr_ec randomness
)
{
  Eurydice_arr_93 signature = libcrux_ml_dsa_types_zero_c5_f1();
  core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_53
  uu____0 =
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_sign_pre_hashed_mut_3f(signing_ಕೀಲಿ,
      ಸಂದೇಶ_2,
      context,
      pre_hash_ಬಫರ್,
      randomness,
      &signature);
  core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_8b uu____1;
  ಆದರೆ (uu____0.ಟ್ಯಾಗ್ == core_ಫಲಿತಾಂಶ_Ok)
  {
    uu____1 =
      (
        KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_8b){
          .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Ok,
          .val = { .case_Ok = signature }
        }
      );
  }
  ಇಲ್ಲದಿದ್ದರೆ
  {
    libcrux_ml_dsa_types_SigningError e = uu____0.f0;
    uu____1 =
      (KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_8b){ .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Err, .val = { .case_Err = e } });
  }
  ಹಿಂತಿರುಗಿ uu____1;
}

/**
 Sign (pre-hashed).
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_8b
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_87_sign_pre_hashed_shake128(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_e2 *signing_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 context,
  Eurydice_mut_borrow_ತುಂಡು_u8 pre_hash_ಬಫರ್,
  Eurydice_arr_ec randomness
)
{
  ಹಿಂತಿರುಗಿ
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_sign_pre_hashed_3f(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_f7(signing_ಕೀಲಿ),
      ಸಂದೇಶ_2,
      context,
      pre_hash_ಬಫರ್,
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
ಸ್ಥಿರ KRML_MUSTINLINE core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_verify_ಆಂತರಿಕ_5a(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_43 *verification_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  core_option_Option_84 domain_separation_context,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_93 *signature_serialized
)
{
  Eurydice_borrow_ತುಂಡು_u8_x2
  uu____0 =
    Eurydice_ತುಂಡು_ವಿಭಜಿಸು_at(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_fc(verification_ಕೀಲಿ),
      LIBCRUX_ML_DSA_CONSTANTS_ಬೀಜ_FOR_A_ಗಾತ್ರ,
      uint8_t,
      Eurydice_borrow_ತುಂಡು_u8_x2);
  Eurydice_borrow_ತುಂಡು_u8 ಬೀಜ_for_a = uu____0.fst;
  Eurydice_borrow_ತುಂಡು_u8 t1_serialized = uu____0.snd;
  Eurydice_arr_8f t1;
  Eurydice_arr_a3 repeat_expression0[8U];
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)8U; i++)
  {
    repeat_expression0[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  ಸ್ಮರಣೆ_ನಕಲು(t1.ದತ್ತಾಂಶ, repeat_expression0, (ಗಾತ್ರ_t)8U * ಗಾತ್ರ (Eurydice_arr_a3));
  libcrux_ml_dsa_encoding_verification_ಕೀಲಿ_deserialize_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A,
    LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_VERIFICATION_ಕೀಲಿ_ಗಾತ್ರ,
    t1_serialized,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_20(&t1));
  Eurydice_arr_c7 deserialized_commitment_hash = { .ದತ್ತಾಂಶ = { 0U } };
  Eurydice_arr_bb deserialized_signer_response;
  Eurydice_arr_a3 repeat_expression1[7U];
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)7U; i++)
  {
    repeat_expression1[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
  }
  ಸ್ಮರಣೆ_ನಕಲು(deserialized_signer_response.ದತ್ತಾಂಶ,
    repeat_expression1,
    (ಗಾತ್ರ_t)7U * ಗಾತ್ರ (Eurydice_arr_a3));
  Eurydice_arr_81
  deserialized_hint =
    {
      .ದತ್ತಾಂಶ = {
        { .ದತ್ತಾಂಶ = { 0U } }, { .ದತ್ತಾಂಶ = { 0U } }, { .ದತ್ತಾಂಶ = { 0U } }, { .ದತ್ತಾಂಶ = { 0U } },
        { .ದತ್ತಾಂಶ = { 0U } }, { .ದತ್ತಾಂಶ = { 0U } }, { .ದತ್ತಾಂಶ = { 0U } }, { .ದತ್ತಾಂಶ = { 0U } }
      }
    };
  core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41
  uu____1 =
    libcrux_ml_dsa_encoding_signature_deserialize_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_ಒಳ_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COMMITMENT_HASH_ಗಾತ್ರ,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_GAMMA1_EXPONENT,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_GAMMA1_RING_ELEMENT_ಗಾತ್ರ,
      LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_MAX_ONES_ಒಳ_HINT,
      LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_SIGNATURE_ಗಾತ್ರ,
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_11(signature_serialized),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_17(&deserialized_commitment_hash),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_208(&deserialized_signer_response),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_861(&deserialized_hint));
  core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41 uu____2;
  ಆದರೆ (uu____1.ಟ್ಯಾಗ್ == core_ಫಲಿತಾಂಶ_Ok)
  {
    ಆದರೆ
    (
      libcrux_ml_dsa_arithmetic_ಸದಿಶ_infinity_norm_exceeds_37(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_206(&deserialized_signer_response),
        (int32_t)((uint32_t)1 << (uint32_t)LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_GAMMA1_EXPONENT) -
          LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_BETA)
    )
    {
      uu____2 =
        (
          KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41){
            .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Err,
            .f0 = libcrux_ml_dsa_types_VerificationError_SignerResponseExceedsBoundError
          }
        );
    }
    ಇಲ್ಲದಿದ್ದರೆ
    {
      Eurydice_arr_0f ಮಾತೃಕೆ;
      Eurydice_arr_a3 repeat_ಅಭಿವ್ಯಕ್ತಿ[56U];
      ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)56U; i++)
      {
        repeat_ಅಭಿವ್ಯಕ್ತಿ[i] = libcrux_ml_dsa_polynomial_zero_ff_37();
      }
      ಸ್ಮರಣೆ_ನಕಲು(ಮಾತೃಕೆ.ದತ್ತಾಂಶ, repeat_ಅಭಿವ್ಯಕ್ತಿ, (ಗಾತ್ರ_t)56U * ಗಾತ್ರ (Eurydice_arr_a3));
      libcrux_ml_dsa_samplex4_portable_ಮಾತೃಕೆ_flat_a8_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_ಒಳ_A,
        ಬೀಜ_for_a,
        Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_207(&ಮಾತೃಕೆ));
      Eurydice_arr_c7 verification_ಕೀಲಿ_hash = { .ದತ್ತಾಂಶ = { 0U } };
      libcrux_ml_dsa_hash_functions_portable_shake256_61_c9(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_fc(verification_ಕೀಲಿ),
        &verification_ಕೀಲಿ_hash);
      Eurydice_arr_c7 ಸಂದೇಶ_representative = { .ದತ್ತಾಂಶ = { 0U } };
      libcrux_ml_dsa_ml_dsa_generic_derive_ಸಂದೇಶ_representative_43(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_17(&verification_ಕೀಲಿ_hash),
        &domain_separation_context,
        ಸಂದೇಶ_2,
        &ಸಂದೇಶ_representative);
      Eurydice_arr_a3 verifier_challenge = libcrux_ml_dsa_polynomial_zero_ff_37();
      libcrux_ml_dsa_sample_sample_challenge_ring_element_2e(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_17(&deserialized_commitment_hash),
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ONES_ಒಳ_VERIFIER_CHALLENGE,
        &verifier_challenge);
      libcrux_ml_dsa_ntt_ntt_37(&verifier_challenge);
      ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)7U; i++)
      {
        ಗಾತ್ರ_t i0 = i;
        libcrux_ml_dsa_ntt_ntt_37(&deserialized_signer_response.ದತ್ತಾಂಶ[i0]);
      }
      libcrux_ml_dsa_ಮಾತೃಕೆ_compute_w_approx_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_ಅಡ್ಡಸಾಲುಗಳು_ಒಳ_A,
        LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_COLUMNS_ಒಳ_A,
        Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_208(&ಮಾತೃಕೆ),
        Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_206(&deserialized_signer_response),
        &verifier_challenge,
        Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_20(&t1));
      Eurydice_arr_c7 recomputed_commitment_hash = { .ದತ್ತಾಂಶ = { 0U } };
      libcrux_ml_dsa_arithmetic_use_hint_37(LIBCRUX_ML_DSA_CONSTANTS_ML_DSA_87_GAMMA2,
        Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_861(&deserialized_hint),
        Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_20(&t1));
      Eurydice_arr_1b commitment_serialized = { .ದತ್ತಾಂಶ = { 0U } };
      libcrux_ml_dsa_encoding_commitment_serialize_ಸದಿಶ_37(LIBCRUX_ML_DSA_ML_DSA_GENERIC_ML_DSA_87_COMMITMENT_RING_ELEMENT_ಗಾತ್ರ,
        Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_200(&t1),
        Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_68(&commitment_serialized));
      libcrux_sha3_generic_keccak_xof_KeccakXofState_8d
      shake = libcrux_ml_dsa_hash_functions_portable_init_26();
      libcrux_ml_dsa_hash_functions_portable_absorb_26(&shake,
        Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_17(&ಸಂದೇಶ_representative));
      libcrux_ml_dsa_hash_functions_portable_absorb_final_26(&shake,
        Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_68(&commitment_serialized));
      libcrux_ml_dsa_hash_functions_portable_squeeze_26(&shake,
        Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_17(&recomputed_commitment_hash));
      ಆದರೆ
      (
        Eurydice_array_eq((ಗಾತ್ರ_t)64U,
          &deserialized_commitment_hash,
          &recomputed_commitment_hash,
          uint8_t)
      )
      {
        uu____2 = (KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41){ .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Ok });
      }
      ಇಲ್ಲದಿದ್ದರೆ
      {
        uu____2 =
          (
            KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41){
              .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Err,
              .f0 = libcrux_ml_dsa_types_Verification_Error_Commitment_Hashes_Dont_ಹೊಂದಿಕೆ_Error
            }
          );
      }
    }
  }
  ಇಲ್ಲದಿದ್ದರೆ
  {
    libcrux_ml_dsa_types_VerificationError e = uu____1.f0;
    uu____2 = (KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41){ .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Err, .f0 = e });
  }
  ಹಿಂತಿರುಗಿ uu____2;
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_87.verify
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_verify_5a(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_43 *verification_ಕೀಲಿ_serialized,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 context,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_93 *signature_serialized
)
{
  core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_a8
  uu____0 =
    libcrux_ml_dsa_pre_hash_new_88(context,
      (KRML_CLITERAL(core_option_Option_57){ .ಟ್ಯಾಗ್ = core_option_None }));
  ಆದರೆ (!(uu____0.ಟ್ಯಾಗ್ == core_ಫಲಿತಾಂಶ_Ok))
  {
    ಹಿಂತಿರುಗಿ
      (
        KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41){
          .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Err,
          .f0 = libcrux_ml_dsa_types_VerificationError_VerificationContextTooLongError
        }
      );
  }
  libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
  libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
  ಹಿಂತಿರುಗಿ
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_verify_ಆಂತರಿಕ_5a(verification_ಕೀಲಿ_serialized,
      ಸಂದೇಶ_2,
      (
        KRML_CLITERAL(core_option_Option_84){
          .ಟ್ಯಾಗ್ = core_option_Some,
          .f0 = domain_separation_context
        }
      ),
      signature_serialized);
}

/**
 Verify.
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_87_verify(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_43 *verification_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 context,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_93 *signature
)
{
  ಹಿಂತಿರುಗಿ
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_verify_5a(verification_ಕೀಲಿ,
      ಸಂದೇಶ_2,
      context,
      signature);
}

/**
A monomorphic instance of libcrux_ml_dsa.ml_dsa_generic.ml_dsa_87.verify_pre_hashed
with types libcrux_ml_dsa_simd_portable_vector_type_Coefficients, libcrux_ml_dsa_samplex4_portable_PortableSampler, libcrux_ml_dsa_hash_functions_portable_Shake128, libcrux_ml_dsa_hash_functions_portable_Shake128X4, libcrux_ml_dsa_hash_functions_portable_Shake256, libcrux_ml_dsa_hash_functions_portable_Shake256Xof, libcrux_ml_dsa_pre_hash_SHAKE128_PH
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41
libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_verify_pre_hashed_3f(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_43 *verification_ಕೀಲಿ_serialized,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 context,
  Eurydice_mut_borrow_ತುಂಡು_u8 pre_hash_ಬಫರ್,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_93 *signature_serialized
)
{
  libcrux_ml_dsa_pre_hash_hash_30_83(ಸಂದೇಶ_2, pre_hash_ಬಫರ್);
  core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_a8
  uu____0 =
    libcrux_ml_dsa_pre_hash_new_88(context,
      (
        KRML_CLITERAL(core_option_Option_57){
          .ಟ್ಯಾಗ್ = core_option_Some,
          .f0 = libcrux_ml_dsa_pre_hash_oid_30()
        }
      ));
  ಆದರೆ (!(uu____0.ಟ್ಯಾಗ್ == core_ಫಲಿತಾಂಶ_Ok))
  {
    ಹಿಂತಿರುಗಿ
      (
        KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41){
          .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Err,
          .f0 = libcrux_ml_dsa_types_VerificationError_VerificationContextTooLongError
        }
      );
  }
  libcrux_ml_dsa_pre_hash_DomainSeparationContext dsc = uu____0.val.case_Ok;
  libcrux_ml_dsa_pre_hash_DomainSeparationContext domain_separation_context = dsc;
  ಹಿಂತಿರುಗಿ
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_verify_ಆಂತರಿಕ_5a(verification_ಕೀಲಿ_serialized,
      (
        KRML_CLITERAL(Eurydice_borrow_ತುಂಡು_u8){
          .ptr = pre_hash_ಬಫರ್.ptr,
          .meta = pre_hash_ಬಫರ್.meta
        }
      ),
      (
        KRML_CLITERAL(core_option_Option_84){
          .ಟ್ಯಾಗ್ = core_option_Some,
          .f0 = domain_separation_context
        }
      ),
      signature_serialized);
}

/**
 Verify (pre-hashed with SHAKE-128).
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41
libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_87_verify_pre_hashed_shake128(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_43 *verification_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 context,
  Eurydice_mut_borrow_ತುಂಡು_u8 pre_hash_ಬಫರ್,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_93 *signature
)
{
  ಹಿಂತಿರುಗಿ
    libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_verify_pre_hashed_3f(verification_ಕೀಲಿ,
      ಸಂದೇಶ_2,
      context,
      pre_hash_ಬಫರ್,
      signature);
}

#ಆದರೆ defined(__cplusplus)
}
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿಸು libcrux_mldsa_portable_H_DEFINED
#ಆದರೆ_ಅಂತ್ಯ /* libcrux_mldsa_portable_H */

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


#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ libcrux_mldsa44_portable_H
#ವ್ಯಾಖ್ಯಾನಿಸು libcrux_mldsa44_portable_H



#ಆದರೆ defined(__cplusplus)
ಬಾಹ್ಯ "C" {
#ಆದರೆ_ಅಂತ್ಯ


/**
 Generate an ML-DSA-44 Key Pair
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_MLDSA44_ಕೀಲಿ_Pair
libcrux_ml_dsa_ml_dsa_44_portable_generate_ಕೀಲಿ_pair(Eurydice_arr_ec randomness)
{
  Eurydice_arr_10 signing_ಕೀಲಿ = { .ದತ್ತಾಂಶ = { 0U } };
  Eurydice_arr_02 verification_ಕೀಲಿ = { .ದತ್ತಾಂಶ = { 0U } };
  libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_44_generate_ಕೀಲಿ_pair(randomness,
    &signing_ಕೀಲಿ,
    &verification_ಕೀಲಿ);
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_MLDSA44_ಕೀಲಿ_Pair){
        .signing_ಕೀಲಿ = libcrux_ml_dsa_types_new_9b_ab(signing_ಕೀಲಿ),
        .verification_ಕೀಲಿ = libcrux_ml_dsa_types_new_7f_7d(verification_ಕೀಲಿ)
      }
    );
}

/**
 Generate an ML-DSA-44 Signature

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_48
libcrux_ml_dsa_ml_dsa_44_portable_sign(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_10 *signing_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 context,
  Eurydice_arr_ec randomness
)
{
  ಹಿಂತಿರುಗಿ
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_44_sign(libcrux_ml_dsa_types_as_ref_9b_ab(signing_ಕೀಲಿ),
      ಸಂದೇಶ_2,
      context,
      randomness);
}

/**
 Generate an ML-DSA-44 Signature

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_53
libcrux_ml_dsa_ml_dsa_44_portable_sign_mut(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_10 *signing_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 context,
  Eurydice_arr_ec randomness,
  Eurydice_arr_85 *signature
)
{
  ಹಿಂತಿರುಗಿ
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_44_sign_mut(libcrux_ml_dsa_types_as_ref_9b_ab(signing_ಕೀಲಿ),
      ಸಂದೇಶ_2,
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_48
libcrux_ml_dsa_ml_dsa_44_portable_sign_pre_hashed_shake128(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_10 *signing_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 context,
  Eurydice_arr_ec randomness
)
{
  Eurydice_arr_ec pre_hash_ಬಫರ್ = { .ದತ್ತಾಂಶ = { 0U } };
  ಸ್ಥಿರಾಂಕ Eurydice_arr_10 *uu____0 = libcrux_ml_dsa_types_as_ref_9b_ab(signing_ಕೀಲಿ);
  ಹಿಂತಿರುಗಿ
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_44_sign_pre_hashed_shake128(uu____0,
      ಸಂದೇಶ_2,
      context,
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_01(&pre_hash_ಬಫರ್),
      randomness);
}

/**
 Verify an ML-DSA-44 Signature

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41
libcrux_ml_dsa_ml_dsa_44_portable_verify(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_02 *verification_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 context,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_85 *signature
)
{
  ಹಿಂತಿರುಗಿ
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_44_verify(libcrux_ml_dsa_types_as_ref_7f_7d(verification_ಕೀಲಿ),
      ಸಂದೇಶ_2,
      context,
      libcrux_ml_dsa_types_as_ref_c5_37(signature));
}

/**
 Verify a HashML-DSA-44 Signature, with a SHAKE128 pre-hashing

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41
libcrux_ml_dsa_ml_dsa_44_portable_verify_pre_hashed_shake128(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_02 *verification_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 context,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_85 *signature
)
{
  Eurydice_arr_ec pre_hash_ಬಫರ್ = { .ದತ್ತಾಂಶ = { 0U } };
  ಸ್ಥಿರಾಂಕ Eurydice_arr_02 *uu____0 = libcrux_ml_dsa_types_as_ref_7f_7d(verification_ಕೀಲಿ);
  Eurydice_borrow_ತುಂಡು_u8 uu____1 = ಸಂದೇಶ_2;
  Eurydice_borrow_ತುಂಡು_u8 uu____2 = context;
  Eurydice_mut_borrow_ತುಂಡು_u8 uu____3 = Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_01(&pre_hash_ಬಫರ್);
  ಹಿಂತಿರುಗಿ
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_44_verify_pre_hashed_shake128(uu____0,
      uu____1,
      uu____2,
      uu____3,
      libcrux_ml_dsa_types_as_ref_c5_37(signature));
}

#ಆದರೆ defined(__cplusplus)
}
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿಸು libcrux_mldsa44_portable_H_DEFINED
#ಆದರೆ_ಅಂತ್ಯ /* libcrux_mldsa44_portable_H */

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


#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ libcrux_mldsa65_portable_H
#ವ್ಯಾಖ್ಯಾನಿಸು libcrux_mldsa65_portable_H



#ಆದರೆ defined(__cplusplus)
ಬಾಹ್ಯ "C" {
#ಆದರೆ_ಅಂತ್ಯ


/**
 Generate an ML-DSA-65 Key Pair
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_MLDSA65_ಕೀಲಿ_Pair
libcrux_ml_dsa_ml_dsa_65_portable_generate_ಕೀಲಿ_pair(Eurydice_arr_ec randomness)
{
  Eurydice_arr_24 signing_ಕೀಲಿ = { .ದತ್ತಾಂಶ = { 0U } };
  Eurydice_arr_29 verification_ಕೀಲಿ = { .ದತ್ತಾಂಶ = { 0U } };
  libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_generate_ಕೀಲಿ_pair(randomness,
    &signing_ಕೀಲಿ,
    &verification_ಕೀಲಿ);
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_MLDSA65_ಕೀಲಿ_Pair){
        .signing_ಕೀಲಿ = libcrux_ml_dsa_types_new_9b_e5(signing_ಕೀಲಿ),
        .verification_ಕೀಲಿ = libcrux_ml_dsa_types_new_7f_a2(verification_ಕೀಲಿ)
      }
    );
}

/**
 Generate an ML-DSA-65 Key Pair
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_ml_dsa_ml_dsa_65_portable_generate_ಕೀಲಿ_pair_mut(
  Eurydice_arr_ec randomness,
  Eurydice_arr_24 *signing_ಕೀಲಿ,
  Eurydice_arr_29 *verification_ಕೀಲಿ
)
{
  libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_generate_ಕೀಲಿ_pair(randomness,
    signing_ಕೀಲಿ,
    verification_ಕೀಲಿ);
}

/**
 Generate an ML-DSA-65 Signature

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_8c
libcrux_ml_dsa_ml_dsa_65_portable_sign(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_24 *signing_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 context,
  Eurydice_arr_ec randomness
)
{
  ಹಿಂತಿರುಗಿ
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_sign(libcrux_ml_dsa_types_as_ref_9b_e5(signing_ಕೀಲಿ),
      ಸಂದೇಶ_2,
      context,
      randomness);
}

/**
 Generate an ML-DSA-65 Signature

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_53
libcrux_ml_dsa_ml_dsa_65_portable_sign_mut(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_24 *signing_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 context,
  Eurydice_arr_ec randomness,
  Eurydice_arr_0c *signature
)
{
  ಹಿಂತಿರುಗಿ
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_sign_mut(signing_ಕೀಲಿ,
      ಸಂದೇಶ_2,
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_8c
libcrux_ml_dsa_ml_dsa_65_portable_sign_pre_hashed_shake128(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_24 *signing_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 context,
  Eurydice_arr_ec randomness
)
{
  Eurydice_arr_ec pre_hash_ಬಫರ್ = { .ದತ್ತಾಂಶ = { 0U } };
  ಸ್ಥಿರಾಂಕ Eurydice_arr_24 *uu____0 = libcrux_ml_dsa_types_as_ref_9b_e5(signing_ಕೀಲಿ);
  ಹಿಂತಿರುಗಿ
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_sign_pre_hashed_shake128(uu____0,
      ಸಂದೇಶ_2,
      context,
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_01(&pre_hash_ಬಫರ್),
      randomness);
}

/**
 Verify an ML-DSA-65 Signature

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41
libcrux_ml_dsa_ml_dsa_65_portable_verify(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_29 *verification_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 context,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_0c *signature
)
{
  ಹಿಂತಿರುಗಿ
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_verify(libcrux_ml_dsa_types_as_ref_7f_a2(verification_ಕೀಲಿ),
      ಸಂದೇಶ_2,
      context,
      libcrux_ml_dsa_types_as_ref_c5_5c(signature));
}

/**
 Verify a HashML-DSA-65 Signature, with a SHAKE128 pre-hashing

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41
libcrux_ml_dsa_ml_dsa_65_portable_verify_pre_hashed_shake128(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_29 *verification_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 context,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_0c *signature
)
{
  Eurydice_arr_ec pre_hash_ಬಫರ್ = { .ದತ್ತಾಂಶ = { 0U } };
  ಸ್ಥಿರಾಂಕ Eurydice_arr_29 *uu____0 = libcrux_ml_dsa_types_as_ref_7f_a2(verification_ಕೀಲಿ);
  Eurydice_borrow_ತುಂಡು_u8 uu____1 = ಸಂದೇಶ_2;
  Eurydice_borrow_ತುಂಡು_u8 uu____2 = context;
  Eurydice_mut_borrow_ತುಂಡು_u8 uu____3 = Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_01(&pre_hash_ಬಫರ್);
  ಹಿಂತಿರುಗಿ
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_65_verify_pre_hashed_shake128(uu____0,
      uu____1,
      uu____2,
      uu____3,
      libcrux_ml_dsa_types_as_ref_c5_5c(signature));
}

#ಆದರೆ defined(__cplusplus)
}
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿಸು libcrux_mldsa65_portable_H_DEFINED
#ಆದರೆ_ಅಂತ್ಯ /* libcrux_mldsa65_portable_H */

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


#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ libcrux_mldsa87_portable_H
#ವ್ಯಾಖ್ಯಾನಿಸು libcrux_mldsa87_portable_H



#ಆದರೆ defined(__cplusplus)
ಬಾಹ್ಯ "C" {
#ಆದರೆ_ಅಂತ್ಯ


/**
 Generate an ML-DSA-87 Key Pair
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_MLDSA87_ಕೀಲಿ_Pair
libcrux_ml_dsa_ml_dsa_87_portable_generate_ಕೀಲಿ_pair(Eurydice_arr_ec randomness)
{
  Eurydice_arr_e2 signing_ಕೀಲಿ = { .ದತ್ತಾಂಶ = { 0U } };
  Eurydice_arr_43 verification_ಕೀಲಿ = { .ದತ್ತಾಂಶ = { 0U } };
  libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_87_generate_ಕೀಲಿ_pair(randomness,
    &signing_ಕೀಲಿ,
    &verification_ಕೀಲಿ);
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_MLDSA87_ಕೀಲಿ_Pair){
        .signing_ಕೀಲಿ = libcrux_ml_dsa_types_new_9b_72(signing_ಕೀಲಿ),
        .verification_ಕೀಲಿ = libcrux_ml_dsa_types_new_7f_c6(verification_ಕೀಲಿ)
      }
    );
}

/**
 Generate an ML-DSA-87 Signature

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_8b
libcrux_ml_dsa_ml_dsa_87_portable_sign(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_e2 *signing_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 context,
  Eurydice_arr_ec randomness
)
{
  ಹಿಂತಿರುಗಿ
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_87_sign(libcrux_ml_dsa_types_as_ref_9b_72(signing_ಕೀಲಿ),
      ಸಂದೇಶ_2,
      context,
      randomness);
}

/**
 Generate an ML-DSA-87 Signature

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_53
libcrux_ml_dsa_ml_dsa_87_portable_sign_mut(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_e2 *signing_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 context,
  Eurydice_arr_ec randomness,
  Eurydice_arr_93 *signature
)
{
  ಹಿಂತಿರುಗಿ
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_87_sign_mut(libcrux_ml_dsa_types_as_ref_9b_72(signing_ಕೀಲಿ),
      ಸಂದೇಶ_2,
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_8b
libcrux_ml_dsa_ml_dsa_87_portable_sign_pre_hashed_shake128(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_e2 *signing_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 context,
  Eurydice_arr_ec randomness
)
{
  Eurydice_arr_ec pre_hash_ಬಫರ್ = { .ದತ್ತಾಂಶ = { 0U } };
  ಸ್ಥಿರಾಂಕ Eurydice_arr_e2 *uu____0 = libcrux_ml_dsa_types_as_ref_9b_72(signing_ಕೀಲಿ);
  ಹಿಂತಿರುಗಿ
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_87_sign_pre_hashed_shake128(uu____0,
      ಸಂದೇಶ_2,
      context,
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_01(&pre_hash_ಬಫರ್),
      randomness);
}

/**
 Verify an ML-DSA-87 Signature

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41
libcrux_ml_dsa_ml_dsa_87_portable_verify(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_43 *verification_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 context,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_93 *signature
)
{
  ಹಿಂತಿರುಗಿ
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_87_verify(libcrux_ml_dsa_types_as_ref_7f_c6(verification_ಕೀಲಿ),
      ಸಂದೇಶ_2,
      context,
      libcrux_ml_dsa_types_as_ref_c5_f1(signature));
}

/**
 Verify a HashML-DSA-87 Signature, with a SHAKE128 pre-hashing

 The parameter `context` is used for domain separation
 and is a byte string of length at most 255 bytes. It
 may also be empty.
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41
libcrux_ml_dsa_ml_dsa_87_portable_verify_pre_hashed_shake128(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_43 *verification_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 context,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_93 *signature
)
{
  Eurydice_arr_ec pre_hash_ಬಫರ್ = { .ದತ್ತಾಂಶ = { 0U } };
  ಸ್ಥಿರಾಂಕ Eurydice_arr_43 *uu____0 = libcrux_ml_dsa_types_as_ref_7f_c6(verification_ಕೀಲಿ);
  Eurydice_borrow_ತುಂಡು_u8 uu____1 = ಸಂದೇಶ_2;
  Eurydice_borrow_ತುಂಡು_u8 uu____2 = context;
  Eurydice_mut_borrow_ತುಂಡು_u8 uu____3 = Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_01(&pre_hash_ಬಫರ್);
  ಹಿಂತಿರುಗಿ
    libcrux_ml_dsa_ml_dsa_generic_instantiations_portable_ml_dsa_87_verify_pre_hashed_shake128(uu____0,
      uu____1,
      uu____2,
      uu____3,
      libcrux_ml_dsa_types_as_ref_c5_f1(signature));
}

#ಆದರೆ defined(__cplusplus)
}
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿಸು libcrux_mldsa87_portable_H_DEFINED
#ಆದರೆ_ಅಂತ್ಯ /* libcrux_mldsa87_portable_H */

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


#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ libcrux_mlkem768_portable_H
#ವ್ಯಾಖ್ಯಾನಿಸು libcrux_mlkem768_portable_H



#ಆದರೆ defined(__cplusplus)
ಬಾಹ್ಯ "C" {
#ಆದರೆ_ಅಂತ್ಯ


ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_c7
libcrux_ml_kem_hash_functions_portable_G(Eurydice_borrow_ತುಂಡು_u8 ಒಳಹರಿವು)
{
  Eurydice_arr_c7 digest = { .ದತ್ತಾಂಶ = { 0U } };
  libcrux_sha3_portable_sha512(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_17(&digest), ಒಳಹರಿವು);
  ಹಿಂತಿರುಗಿ digest;
}

ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_ec
libcrux_ml_kem_hash_functions_portable_H(Eurydice_borrow_ತುಂಡು_u8 ಒಳಹರಿವು)
{
  Eurydice_arr_ec digest = { .ದತ್ತಾಂಶ = { 0U } };
  libcrux_sha3_portable_sha256(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_01(&digest), ಒಳಹರಿವು);
  ಹಿಂತಿರುಗಿ digest;
}

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_KEM_POLYNOMIAL_ZETAS_TIMES_MONTGOMERY_R ((KRML_CLITERAL(Eurydice_arr_34){ .ದತ್ತಾಂಶ = { -1044, -758, -359, -1517, 1493, 1422, 287, 202, -171, 622, 1577, 182, 962, -1202, -1474, 1468, 573, -1325, 264, 383, -829, 1458, -1602, -130, -681, 1017, 732, 608, -1542, 411, -205, -1571, 1223, 652, -552, 1015, -1293, 1491, -282, -1544, 516, -8, -320, -666, -1618, -1162, 126, 1469, -853, -90, -271, 830, 107, -1421, -247, -951, -398, 961, -1508, -725, 448, -1065, 677, -1275, -1103, 430, 555, 843, -1251, 871, 1550, 105, 422, 587, 177, -235, -291, -460, 1574, 1653, -246, 778, 1159, -147, -777, 1483, -602, 1119, -1590, 644, -872, 349, 418, 329, -156, -75, 817, 1097, 603, 610, 1322, -1285, -1465, 384, -1215, -136, 1218, -1335, -874, 220, -1187, -1659, -1185, -1530, -1278, 794, -1510, -854, -870, 478, -108, -308, 996, 991, 958, -1460, 1522, 1628 } }))

ಸ್ಥಿರ KRML_MUSTINLINE int16_t libcrux_ml_kem_polynomial_zeta(ಗಾತ್ರ_t i)
{
  ಹಿಂತಿರುಗಿ LIBCRUX_ML_KEM_POLYNOMIAL_ZETAS_TIMES_MONTGOMERY_R.ದತ್ತಾಂಶ[i];
}

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_ಒಳ_RING_ELEMENT ((ಗಾತ್ರ_t)16U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_KEM_ಸದಿಶ_TRAITS_ಕ್ಷೇತ್ರ_ELEMENTS_ಒಳ_ಸದಿಶ ((ಗಾತ್ರ_t)16U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_KEM_ಸದಿಶ_TRAITS_MONTGOMERY_R_SQUARED_MOD_ಕ್ಷೇತ್ರ_MODULUS (1353)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_KEM_ಸದಿಶ_TRAITS_ಕ್ಷೇತ್ರ_MODULUS (3329)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_KEM_ಸದಿಶ_TRAITS_INVERSE_ದ_MODULUS_MOD_MONTGOMERY_R (62209U)

ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_ಸದಿಶ_type_from_i16_array(Eurydice_borrow_ತುಂಡು_i16 array)
{
  Eurydice_arr_d6 arr;
  ಸ್ಮರಣೆ_ನಕಲು(arr.ದತ್ತಾಂಶ,
    Eurydice_ತುಂಡು_subslice_shared_a6(array,
      (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = (ಗಾತ್ರ_t)0U, .ಕೊನೆ = (ಗಾತ್ರ_t)16U })).ptr,
    (ಗಾತ್ರ_t)16U * ಗಾತ್ರ (int16_t));
  ಹಿಂತಿರುಗಿ
    core_ಫಲಿತಾಂಶ_unwrap_26_d3((
        KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_ec){ .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Ok, .val = { .case_Ok = arr } }
      ));
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_from_i16_array_b8(Eurydice_borrow_ತುಂಡು_i16 array)
{
  ಹಿಂತಿರುಗಿ
    libcrux_ml_kem_ಸದಿಶ_portable_ಸದಿಶ_type_from_i16_array(libcrux_secrets_int_classify_ಬಹಿರಂಗ_classify_ref_6d_39(array));
}

ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_d6 libcrux_ml_kem_ಸದಿಶ_portable_ಸದಿಶ_type_zero(ಶೂನ್ಯ)
{
  ಹಿಂತಿರುಗಿ
    libcrux_secrets_int_ಬಹಿರಂಗ_integers_classify_27_4b((
        KRML_CLITERAL(Eurydice_arr_d6){ .ದತ್ತಾಂಶ = { 0U } }
      ));
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_d6 libcrux_ml_kem_ಸದಿಶ_portable_ZERO_b8(ಶೂನ್ಯ)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ಸದಿಶ_portable_ಸದಿಶ_type_zero();
}

ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_arithmetic_ಕೂಡಿಸು(Eurydice_arr_d6 lhs, ಸ್ಥಿರಾಂಕ Eurydice_arr_d6 *rhs)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < LIBCRUX_ML_KEM_ಸದಿಶ_TRAITS_ಕ್ಷೇತ್ರ_ELEMENTS_ಒಳ_ಸದಿಶ; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    ಗಾತ್ರ_t uu____0 = i0;
    lhs.ದತ್ತಾಂಶ[uu____0] += rhs->ದತ್ತಾಂಶ[i0];
  }
  ಹಿಂತಿರುಗಿ lhs;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_ಕೂಡಿಸು_b8(Eurydice_arr_d6 lhs, ಸ್ಥಿರಾಂಕ Eurydice_arr_d6 *rhs)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ಸದಿಶ_portable_arithmetic_ಕೂಡಿಸು(lhs, rhs);
}

ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_arithmetic_sub(Eurydice_arr_d6 lhs, ಸ್ಥಿರಾಂಕ Eurydice_arr_d6 *rhs)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < LIBCRUX_ML_KEM_ಸದಿಶ_TRAITS_ಕ್ಷೇತ್ರ_ELEMENTS_ಒಳ_ಸದಿಶ; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    ಗಾತ್ರ_t uu____0 = i0;
    lhs.ದತ್ತಾಂಶ[uu____0] -= rhs->ದತ್ತಾಂಶ[i0];
  }
  ಹಿಂತಿರುಗಿ lhs;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_sub_b8(Eurydice_arr_d6 lhs, ಸ್ಥಿರಾಂಕ Eurydice_arr_d6 *rhs)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ಸದಿಶ_portable_arithmetic_sub(lhs, rhs);
}

ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_arithmetic_multiply_by_constant(Eurydice_arr_d6 vec, int16_t c)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < LIBCRUX_ML_KEM_ಸದಿಶ_TRAITS_ಕ್ಷೇತ್ರ_ELEMENTS_ಒಳ_ಸದಿಶ; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    ಗಾತ್ರ_t uu____0 = i0;
    vec.ದತ್ತಾಂಶ[uu____0] *= c;
  }
  ಹಿಂತಿರುಗಿ vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_multiply_by_constant_b8(Eurydice_arr_d6 vec, int16_t c)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ಸದಿಶ_portable_arithmetic_multiply_by_constant(vec, c);
}

/**
 Note: This function is not secret independent
 Only use with public values.
*/
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_arithmetic_cond_ಕಳೆ_3329(Eurydice_arr_d6 vec)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < LIBCRUX_ML_KEM_ಸದಿಶ_TRAITS_ಕ್ಷೇತ್ರ_ELEMENTS_ಒಳ_ಸದಿಶ; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    ಆದರೆ (libcrux_secrets_int_ಬಹಿರಂಗ_integers_declassify_d8_39(vec.ದತ್ತಾಂಶ[i0]) >= 3329)
    {
      ಗಾತ್ರ_t uu____0 = i0;
      vec.ದತ್ತಾಂಶ[uu____0] -= 3329;
    }
  }
  ಹಿಂತಿರುಗಿ vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_cond_ಕಳೆ_3329_b8(Eurydice_arr_d6 v)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ಸದಿಶ_portable_arithmetic_cond_ಕಳೆ_3329(v);
}

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_KEM_ಸದಿಶ_PORTABLE_ARITHMETIC_BARRETT_MULTIPLIER (20159)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_KEM_ಸದಿಶ_TRAITS_BARRETT_ಸರಿಸು (26)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_KEM_ಸದಿಶ_TRAITS_BARRETT_R ((int32_t)((uint32_t)1 << (uint32_t)LIBCRUX_ML_KEM_ಸದಿಶ_TRAITS_BARRETT_ಸರಿಸು))

/**
 Signed Barrett Reduction

 Given an input `value`, `barrett_reduce` outputs a representative `result`
 such that:

 - result ≡ value (mod FIELD_MODULUS)
 - the absolute value of `result` is bound as follows:

 `|result| ≤ FIELD_MODULUS / 2 · (|value|/BARRETT_R + 1)

 Note: The input bound is 28296 to prevent overflow in the multiplication of quotient by FIELD_MODULUS

*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ int16_t
libcrux_ml_kem_ಸದಿಶ_portable_arithmetic_barrett_reduce_element(int16_t ಮೌಲ್ಯ)
{
  int32_t
  t =
    libcrux_secrets_int_as_i32_f5(ಮೌಲ್ಯ) *
      LIBCRUX_ML_KEM_ಸದಿಶ_PORTABLE_ARITHMETIC_BARRETT_MULTIPLIER
    + (LIBCRUX_ML_KEM_ಸದಿಶ_TRAITS_BARRETT_R >> 1U);
  int16_t
  quotient =
    libcrux_secrets_int_as_i16_36(t >> (uint32_t)LIBCRUX_ML_KEM_ಸದಿಶ_TRAITS_BARRETT_ಸರಿಸು);
  ಹಿಂತಿರುಗಿ ಮೌಲ್ಯ - quotient * LIBCRUX_ML_KEM_ಸದಿಶ_TRAITS_ಕ್ಷೇತ್ರ_MODULUS;
}

ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_arithmetic_barrett_reduce(Eurydice_arr_d6 vec)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < LIBCRUX_ML_KEM_ಸದಿಶ_TRAITS_ಕ್ಷೇತ್ರ_ELEMENTS_ಒಳ_ಸದಿಶ; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    int16_t vi = libcrux_ml_kem_ಸದಿಶ_portable_arithmetic_barrett_reduce_element(vec.ದತ್ತಾಂಶ[i0]);
    vec.ದತ್ತಾಂಶ[i0] = vi;
  }
  ಹಿಂತಿರುಗಿ vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_barrett_reduce_b8(Eurydice_arr_d6 ಸದಿಶ)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ಸದಿಶ_portable_arithmetic_barrett_reduce(ಸದಿಶ);
}

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_KEM_ಸದಿಶ_PORTABLE_ARITHMETIC_MONTGOMERY_ಸರಿಸು (16U)

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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ int16_t
libcrux_ml_kem_ಸದಿಶ_portable_arithmetic_montgomery_reduce_element(int32_t ಮೌಲ್ಯ)
{
  int32_t
  k =
    libcrux_secrets_int_as_i32_f5(libcrux_secrets_int_as_i16_36(ಮೌಲ್ಯ)) *
      libcrux_secrets_int_as_i32_b8(libcrux_secrets_int_ಬಹಿರಂಗ_integers_classify_27_df(LIBCRUX_ML_KEM_ಸದಿಶ_TRAITS_INVERSE_ದ_MODULUS_MOD_MONTGOMERY_R));
  int32_t
  k_times_modulus =
    libcrux_secrets_int_as_i32_f5(libcrux_secrets_int_as_i16_36(k)) *
      libcrux_secrets_int_as_i32_f5(libcrux_secrets_int_ಬಹಿರಂಗ_integers_classify_27_39(LIBCRUX_ML_KEM_ಸದಿಶ_TRAITS_ಕ್ಷೇತ್ರ_MODULUS));
  int16_t
  c =
    libcrux_secrets_int_as_i16_36(k_times_modulus >>
        (uint32_t)LIBCRUX_ML_KEM_ಸದಿಶ_PORTABLE_ARITHMETIC_MONTGOMERY_ಸರಿಸು);
  int16_t
  ಮೌಲ್ಯ_ಮೇಲಿನ =
    libcrux_secrets_int_as_i16_36(ಮೌಲ್ಯ >>
        (uint32_t)LIBCRUX_ML_KEM_ಸದಿಶ_PORTABLE_ARITHMETIC_MONTGOMERY_ಸರಿಸು);
  ಹಿಂತಿರುಗಿ ಮೌಲ್ಯ_ಮೇಲಿನ - c;
}

/**
 If `fe` is some field element 'x' of the Kyber field and `fer` is congruent to
 `y · MONTGOMERY_R`, this procedure outputs a value that is congruent to
 `x · y`, as follows:

    `fe · fer ≡ x · y · MONTGOMERY_R (mod FIELD_MODULUS)`

 `montgomery_reduce` takes the value `x · y · MONTGOMERY_R` and outputs a representative
 `x · y · MONTGOMERY_R * MONTGOMERY_R^{-1} ≡ x · y (mod FIELD_MODULUS)`.
*/
ಸ್ಥಿರ KRML_MUSTINLINE int16_t
libcrux_ml_kem_ಸದಿಶ_portable_arithmetic_montgomery_multiply_fe_by_fer(
  int16_t fe,
  int16_t fer
)
{
  int32_t ಗುಣಲಬ್ಧ = libcrux_secrets_int_as_i32_f5(fe) * libcrux_secrets_int_as_i32_f5(fer);
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ಸದಿಶ_portable_arithmetic_montgomery_reduce_element(ಗುಣಲಬ್ಧ);
}

ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_arithmetic_montgomery_multiply_by_constant(
  Eurydice_arr_d6 vec,
  int16_t c
)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < LIBCRUX_ML_KEM_ಸದಿಶ_TRAITS_ಕ್ಷೇತ್ರ_ELEMENTS_ಒಳ_ಸದಿಶ; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    vec.ದತ್ತಾಂಶ[i0] =
      libcrux_ml_kem_ಸದಿಶ_portable_arithmetic_montgomery_multiply_fe_by_fer(vec.ದತ್ತಾಂಶ[i0],
        c);
  }
  ಹಿಂತಿರುಗಿ vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_montgomery_multiply_by_constant_b8(
  Eurydice_arr_d6 ಸದಿಶ,
  int16_t constant
)
{
  ಹಿಂತಿರುಗಿ
    libcrux_ml_kem_ಸದಿಶ_portable_arithmetic_montgomery_multiply_by_constant(ಸದಿಶ,
      libcrux_secrets_int_ಬಹಿರಂಗ_integers_classify_27_39(constant));
}

ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_arithmetic_bitwise_and_with_constant(
  Eurydice_arr_d6 vec,
  int16_t c
)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < LIBCRUX_ML_KEM_ಸದಿಶ_TRAITS_ಕ್ಷೇತ್ರ_ELEMENTS_ಒಳ_ಸದಿಶ; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    ಗಾತ್ರ_t uu____0 = i0;
    vec.ದತ್ತಾಂಶ[uu____0] &= c;
  }
  ಹಿಂತಿರುಗಿ vec;
}

/**
A monomorphic instance of libcrux_ml_kem.vector.portable.arithmetic.shift_right
with const generics
- SHIFT_BY= 15
*/
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_arithmetic_ಸರಿಸು_ಬಲ_ef(Eurydice_arr_d6 vec)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < LIBCRUX_ML_KEM_ಸದಿಶ_TRAITS_ಕ್ಷೇತ್ರ_ELEMENTS_ಒಳ_ಸದಿಶ; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    vec.ದತ್ತಾಂಶ[i0] >>= (uint32_t)15;
  }
  ಹಿಂತಿರುಗಿ vec;
}

ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_arithmetic_ಗಮ್ಯ_unsigned_representative(Eurydice_arr_d6 a)
{
  Eurydice_arr_d6 t = libcrux_ml_kem_ಸದಿಶ_portable_arithmetic_ಸರಿಸು_ಬಲ_ef(a);
  Eurydice_arr_d6
  fm =
    libcrux_ml_kem_ಸದಿಶ_portable_arithmetic_bitwise_and_with_constant(t,
      LIBCRUX_ML_KEM_ಸದಿಶ_TRAITS_ಕ್ಷೇತ್ರ_MODULUS);
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ಸದಿಶ_portable_arithmetic_ಕೂಡಿಸು(a, &fm);
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_ಗಮ್ಯ_unsigned_representative_b8(Eurydice_arr_d6 a)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ಸದಿಶ_portable_arithmetic_ಗಮ್ಯ_unsigned_representative(a);
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ uint8_t
libcrux_ml_kem_ಸದಿಶ_portable_compress_compress_ಸಂದೇಶ_coefficient(uint16_t fe)
{
  int16_t
  shifted =
    libcrux_secrets_int_ಬಹಿರಂಗ_integers_classify_27_39(1664) - libcrux_secrets_int_as_i16_ca(fe);
  int16_t ಮುಖವಾಡ = shifted >> 15U;
  int16_t shifted_ಗಮ್ಯ_ಧನಾತ್ಮಕ = ಮುಖವಾಡ ^ shifted;
  int16_t shifted_ಧನಾತ್ಮಕ_ಒಳ_range = shifted_ಗಮ್ಯ_ಧನಾತ್ಮಕ - 832;
  int16_t r0 = shifted_ಧನಾತ್ಮಕ_ಒಳ_range >> 15U;
  int16_t r1 = r0 & 1;
  ಹಿಂತಿರುಗಿ libcrux_secrets_int_as_u8_f5(r1);
}

ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_compress_compress_1(Eurydice_arr_d6 a)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < LIBCRUX_ML_KEM_ಸದಿಶ_TRAITS_ಕ್ಷೇತ್ರ_ELEMENTS_ಒಳ_ಸದಿಶ; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    a.ದತ್ತಾಂಶ[i0] =
      libcrux_secrets_int_as_i16_59(libcrux_ml_kem_ಸದಿಶ_portable_compress_compress_ಸಂದೇಶ_coefficient(libcrux_secrets_int_as_u16_f5(a.ದತ್ತಾಂಶ[i0])));
  }
  ಹಿಂತಿರುಗಿ a;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_d6 libcrux_ml_kem_ಸದಿಶ_portable_compress_1_b8(Eurydice_arr_d6 a)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ಸದಿಶ_portable_compress_compress_1(a);
}

ಸ್ಥಿರ KRML_MUSTINLINE uint32_t
libcrux_ml_kem_ಸದಿಶ_portable_arithmetic_get_n_ಕನಿಷ್ಠ_significant_ಬಿಟ್ಟುಗಳು(
  uint8_t n,
  uint32_t ಮೌಲ್ಯ
)
{
  ಹಿಂತಿರುಗಿ ಮೌಲ್ಯ & ((1U << (uint32_t)n) - 1U);
}

ಸ್ಥಿರ ಸಾಲೊಳಗೆ int16_t
libcrux_ml_kem_ಸದಿಶ_portable_compress_compress_ciphertext_coefficient(
  uint8_t coefficient_ಬಿಟ್ಟುಗಳು,
  uint16_t fe
)
{
  uint64_t compressed = libcrux_secrets_int_as_u64_ca(fe) << (uint32_t)coefficient_ಬಿಟ್ಟುಗಳು;
  compressed += 1664ULL;
  compressed *= 10321340ULL;
  compressed >>= 35U;
  ಹಿಂತಿರುಗಿ
    libcrux_secrets_int_as_i16_b8(libcrux_ml_kem_ಸದಿಶ_portable_arithmetic_get_n_ಕನಿಷ್ಠ_significant_ಬಿಟ್ಟುಗಳು(coefficient_ಬಿಟ್ಟುಗಳು,
        libcrux_secrets_int_as_u32_a3(compressed)));
}

ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_compress_decompress_1(Eurydice_arr_d6 a)
{
  Eurydice_arr_d6 z = libcrux_ml_kem_ಸದಿಶ_portable_ಸದಿಶ_type_zero();
  Eurydice_arr_d6 s = libcrux_ml_kem_ಸದಿಶ_portable_arithmetic_sub(z, &a);
  Eurydice_arr_d6
  res = libcrux_ml_kem_ಸದಿಶ_portable_arithmetic_bitwise_and_with_constant(s, 1665);
  ಹಿಂತಿರುಗಿ res;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_d6 libcrux_ml_kem_ಸದಿಶ_portable_decompress_1_b8(Eurydice_arr_d6 a)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ಸದಿಶ_portable_compress_decompress_1(a);
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_kem_ಸದಿಶ_portable_ntt_ntt_ಹೆಜ್ಜೆ(
  Eurydice_arr_d6 *vec,
  int16_t zeta,
  ಗಾತ್ರ_t i,
  ಗಾತ್ರ_t j
)
{
  int16_t
  t =
    libcrux_ml_kem_ಸದಿಶ_portable_arithmetic_montgomery_multiply_fe_by_fer(vec->ದತ್ತಾಂಶ[j],
      libcrux_secrets_int_ಬಹಿರಂಗ_integers_classify_27_39(zeta));
  int16_t a_minus_t = vec->ದತ್ತಾಂಶ[i] - t;
  int16_t a_plus_t = vec->ದತ್ತಾಂಶ[i] + t;
  vec->ದತ್ತಾಂಶ[j] = a_minus_t;
  vec->ದತ್ತಾಂಶ[i] = a_plus_t;
}

ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_ntt_ntt_layer_1_ಹೆಜ್ಜೆ(
  Eurydice_arr_d6 vec,
  int16_t zeta0,
  int16_t zeta1,
  int16_t zeta2,
  int16_t zeta3
)
{
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_ntt_ಹೆಜ್ಜೆ(&vec, zeta0, (ಗಾತ್ರ_t)0U, (ಗಾತ್ರ_t)2U);
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_ntt_ಹೆಜ್ಜೆ(&vec, zeta0, (ಗಾತ್ರ_t)1U, (ಗಾತ್ರ_t)3U);
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_ntt_ಹೆಜ್ಜೆ(&vec, zeta1, (ಗಾತ್ರ_t)4U, (ಗಾತ್ರ_t)6U);
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_ntt_ಹೆಜ್ಜೆ(&vec, zeta1, (ಗಾತ್ರ_t)5U, (ಗಾತ್ರ_t)7U);
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_ntt_ಹೆಜ್ಜೆ(&vec, zeta2, (ಗಾತ್ರ_t)8U, (ಗಾತ್ರ_t)10U);
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_ntt_ಹೆಜ್ಜೆ(&vec, zeta2, (ಗಾತ್ರ_t)9U, (ಗಾತ್ರ_t)11U);
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_ntt_ಹೆಜ್ಜೆ(&vec, zeta3, (ಗಾತ್ರ_t)12U, (ಗಾತ್ರ_t)14U);
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_ntt_ಹೆಜ್ಜೆ(&vec, zeta3, (ಗಾತ್ರ_t)13U, (ಗಾತ್ರ_t)15U);
  ಹಿಂತಿರುಗಿ vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_ntt_layer_1_ಹೆಜ್ಜೆ_b8(
  Eurydice_arr_d6 a,
  int16_t zeta0,
  int16_t zeta1,
  int16_t zeta2,
  int16_t zeta3
)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ಸದಿಶ_portable_ntt_ntt_layer_1_ಹೆಜ್ಜೆ(a, zeta0, zeta1, zeta2, zeta3);
}

ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_ntt_ntt_layer_2_ಹೆಜ್ಜೆ(
  Eurydice_arr_d6 vec,
  int16_t zeta0,
  int16_t zeta1
)
{
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_ntt_ಹೆಜ್ಜೆ(&vec, zeta0, (ಗಾತ್ರ_t)0U, (ಗಾತ್ರ_t)4U);
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_ntt_ಹೆಜ್ಜೆ(&vec, zeta0, (ಗಾತ್ರ_t)1U, (ಗಾತ್ರ_t)5U);
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_ntt_ಹೆಜ್ಜೆ(&vec, zeta0, (ಗಾತ್ರ_t)2U, (ಗಾತ್ರ_t)6U);
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_ntt_ಹೆಜ್ಜೆ(&vec, zeta0, (ಗಾತ್ರ_t)3U, (ಗಾತ್ರ_t)7U);
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_ntt_ಹೆಜ್ಜೆ(&vec, zeta1, (ಗಾತ್ರ_t)8U, (ಗಾತ್ರ_t)12U);
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_ntt_ಹೆಜ್ಜೆ(&vec, zeta1, (ಗಾತ್ರ_t)9U, (ಗಾತ್ರ_t)13U);
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_ntt_ಹೆಜ್ಜೆ(&vec, zeta1, (ಗಾತ್ರ_t)10U, (ಗಾತ್ರ_t)14U);
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_ntt_ಹೆಜ್ಜೆ(&vec, zeta1, (ಗಾತ್ರ_t)11U, (ಗಾತ್ರ_t)15U);
  ಹಿಂತಿರುಗಿ vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_ntt_layer_2_ಹೆಜ್ಜೆ_b8(
  Eurydice_arr_d6 a,
  int16_t zeta0,
  int16_t zeta1
)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ಸದಿಶ_portable_ntt_ntt_layer_2_ಹೆಜ್ಜೆ(a, zeta0, zeta1);
}

ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_ntt_ntt_layer_3_ಹೆಜ್ಜೆ(Eurydice_arr_d6 vec, int16_t zeta)
{
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_ntt_ಹೆಜ್ಜೆ(&vec, zeta, (ಗಾತ್ರ_t)0U, (ಗಾತ್ರ_t)8U);
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_ntt_ಹೆಜ್ಜೆ(&vec, zeta, (ಗಾತ್ರ_t)1U, (ಗಾತ್ರ_t)9U);
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_ntt_ಹೆಜ್ಜೆ(&vec, zeta, (ಗಾತ್ರ_t)2U, (ಗಾತ್ರ_t)10U);
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_ntt_ಹೆಜ್ಜೆ(&vec, zeta, (ಗಾತ್ರ_t)3U, (ಗಾತ್ರ_t)11U);
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_ntt_ಹೆಜ್ಜೆ(&vec, zeta, (ಗಾತ್ರ_t)4U, (ಗಾತ್ರ_t)12U);
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_ntt_ಹೆಜ್ಜೆ(&vec, zeta, (ಗಾತ್ರ_t)5U, (ಗಾತ್ರ_t)13U);
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_ntt_ಹೆಜ್ಜೆ(&vec, zeta, (ಗಾತ್ರ_t)6U, (ಗಾತ್ರ_t)14U);
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_ntt_ಹೆಜ್ಜೆ(&vec, zeta, (ಗಾತ್ರ_t)7U, (ಗಾತ್ರ_t)15U);
  ಹಿಂತಿರುಗಿ vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_ntt_layer_3_ಹೆಜ್ಜೆ_b8(Eurydice_arr_d6 a, int16_t zeta)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ಸದಿಶ_portable_ntt_ntt_layer_3_ಹೆಜ್ಜೆ(a, zeta);
}

ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_kem_ಸದಿಶ_portable_ntt_inv_ntt_ಹೆಜ್ಜೆ(
  Eurydice_arr_d6 *vec,
  int16_t zeta,
  ಗಾತ್ರ_t i,
  ಗಾತ್ರ_t j
)
{
  int16_t a_minus_b = vec->ದತ್ತಾಂಶ[j] - vec->ದತ್ತಾಂಶ[i];
  int16_t a_plus_b = vec->ದತ್ತಾಂಶ[j] + vec->ದತ್ತಾಂಶ[i];
  int16_t o0 = libcrux_ml_kem_ಸದಿಶ_portable_arithmetic_barrett_reduce_element(a_plus_b);
  int16_t
  o1 =
    libcrux_ml_kem_ಸದಿಶ_portable_arithmetic_montgomery_multiply_fe_by_fer(a_minus_b,
      libcrux_secrets_int_ಬಹಿರಂಗ_integers_classify_27_39(zeta));
  vec->ದತ್ತಾಂಶ[i] = o0;
  vec->ದತ್ತಾಂಶ[j] = o1;
}

ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_ntt_inv_ntt_layer_1_ಹೆಜ್ಜೆ(
  Eurydice_arr_d6 vec,
  int16_t zeta0,
  int16_t zeta1,
  int16_t zeta2,
  int16_t zeta3
)
{
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_inv_ntt_ಹೆಜ್ಜೆ(&vec, zeta0, (ಗಾತ್ರ_t)0U, (ಗಾತ್ರ_t)2U);
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_inv_ntt_ಹೆಜ್ಜೆ(&vec, zeta0, (ಗಾತ್ರ_t)1U, (ಗಾತ್ರ_t)3U);
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_inv_ntt_ಹೆಜ್ಜೆ(&vec, zeta1, (ಗಾತ್ರ_t)4U, (ಗಾತ್ರ_t)6U);
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_inv_ntt_ಹೆಜ್ಜೆ(&vec, zeta1, (ಗಾತ್ರ_t)5U, (ಗಾತ್ರ_t)7U);
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_inv_ntt_ಹೆಜ್ಜೆ(&vec, zeta2, (ಗಾತ್ರ_t)8U, (ಗಾತ್ರ_t)10U);
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_inv_ntt_ಹೆಜ್ಜೆ(&vec, zeta2, (ಗಾತ್ರ_t)9U, (ಗಾತ್ರ_t)11U);
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_inv_ntt_ಹೆಜ್ಜೆ(&vec, zeta3, (ಗಾತ್ರ_t)12U, (ಗಾತ್ರ_t)14U);
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_inv_ntt_ಹೆಜ್ಜೆ(&vec, zeta3, (ಗಾತ್ರ_t)13U, (ಗಾತ್ರ_t)15U);
  ಹಿಂತಿರುಗಿ vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_inv_ntt_layer_1_ಹೆಜ್ಜೆ_b8(
  Eurydice_arr_d6 a,
  int16_t zeta0,
  int16_t zeta1,
  int16_t zeta2,
  int16_t zeta3
)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ಸದಿಶ_portable_ntt_inv_ntt_layer_1_ಹೆಜ್ಜೆ(a, zeta0, zeta1, zeta2, zeta3);
}

ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_ntt_inv_ntt_layer_2_ಹೆಜ್ಜೆ(
  Eurydice_arr_d6 vec,
  int16_t zeta0,
  int16_t zeta1
)
{
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_inv_ntt_ಹೆಜ್ಜೆ(&vec, zeta0, (ಗಾತ್ರ_t)0U, (ಗಾತ್ರ_t)4U);
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_inv_ntt_ಹೆಜ್ಜೆ(&vec, zeta0, (ಗಾತ್ರ_t)1U, (ಗಾತ್ರ_t)5U);
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_inv_ntt_ಹೆಜ್ಜೆ(&vec, zeta0, (ಗಾತ್ರ_t)2U, (ಗಾತ್ರ_t)6U);
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_inv_ntt_ಹೆಜ್ಜೆ(&vec, zeta0, (ಗಾತ್ರ_t)3U, (ಗಾತ್ರ_t)7U);
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_inv_ntt_ಹೆಜ್ಜೆ(&vec, zeta1, (ಗಾತ್ರ_t)8U, (ಗಾತ್ರ_t)12U);
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_inv_ntt_ಹೆಜ್ಜೆ(&vec, zeta1, (ಗಾತ್ರ_t)9U, (ಗಾತ್ರ_t)13U);
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_inv_ntt_ಹೆಜ್ಜೆ(&vec, zeta1, (ಗಾತ್ರ_t)10U, (ಗಾತ್ರ_t)14U);
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_inv_ntt_ಹೆಜ್ಜೆ(&vec, zeta1, (ಗಾತ್ರ_t)11U, (ಗಾತ್ರ_t)15U);
  ಹಿಂತಿರುಗಿ vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_inv_ntt_layer_2_ಹೆಜ್ಜೆ_b8(
  Eurydice_arr_d6 a,
  int16_t zeta0,
  int16_t zeta1
)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ಸದಿಶ_portable_ntt_inv_ntt_layer_2_ಹೆಜ್ಜೆ(a, zeta0, zeta1);
}

ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_ntt_inv_ntt_layer_3_ಹೆಜ್ಜೆ(Eurydice_arr_d6 vec, int16_t zeta)
{
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_inv_ntt_ಹೆಜ್ಜೆ(&vec, zeta, (ಗಾತ್ರ_t)0U, (ಗಾತ್ರ_t)8U);
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_inv_ntt_ಹೆಜ್ಜೆ(&vec, zeta, (ಗಾತ್ರ_t)1U, (ಗಾತ್ರ_t)9U);
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_inv_ntt_ಹೆಜ್ಜೆ(&vec, zeta, (ಗಾತ್ರ_t)2U, (ಗಾತ್ರ_t)10U);
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_inv_ntt_ಹೆಜ್ಜೆ(&vec, zeta, (ಗಾತ್ರ_t)3U, (ಗಾತ್ರ_t)11U);
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_inv_ntt_ಹೆಜ್ಜೆ(&vec, zeta, (ಗಾತ್ರ_t)4U, (ಗಾತ್ರ_t)12U);
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_inv_ntt_ಹೆಜ್ಜೆ(&vec, zeta, (ಗಾತ್ರ_t)5U, (ಗಾತ್ರ_t)13U);
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_inv_ntt_ಹೆಜ್ಜೆ(&vec, zeta, (ಗಾತ್ರ_t)6U, (ಗಾತ್ರ_t)14U);
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_inv_ntt_ಹೆಜ್ಜೆ(&vec, zeta, (ಗಾತ್ರ_t)7U, (ಗಾತ್ರ_t)15U);
  ಹಿಂತಿರುಗಿ vec;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_inv_ntt_layer_3_ಹೆಜ್ಜೆ_b8(Eurydice_arr_d6 a, int16_t zeta)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ಸದಿಶ_portable_ntt_inv_ntt_layer_3_ಹೆಜ್ಜೆ(a, zeta);
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_kem_ಸದಿಶ_portable_ntt_ntt_multiply_binomials(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_d6 *a,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_d6 *b,
  int16_t zeta,
  ಗಾತ್ರ_t i,
  Eurydice_arr_d6 *ಹೊರಹೋಗು
)
{
  int16_t ai = a->ದತ್ತಾಂಶ[(ಗಾತ್ರ_t)2U * i];
  int16_t bi = b->ದತ್ತಾಂಶ[(ಗಾತ್ರ_t)2U * i];
  int16_t aj = a->ದತ್ತಾಂಶ[(ಗಾತ್ರ_t)2U * i + (ಗಾತ್ರ_t)1U];
  int16_t bj = b->ದತ್ತಾಂಶ[(ಗಾತ್ರ_t)2U * i + (ಗಾತ್ರ_t)1U];
  int32_t ai_bi = libcrux_secrets_int_as_i32_f5(ai) * libcrux_secrets_int_as_i32_f5(bi);
  int32_t aj_bj_ = libcrux_secrets_int_as_i32_f5(aj) * libcrux_secrets_int_as_i32_f5(bj);
  int16_t aj_bj = libcrux_ml_kem_ಸದಿಶ_portable_arithmetic_montgomery_reduce_element(aj_bj_);
  int32_t
  aj_bj_zeta = libcrux_secrets_int_as_i32_f5(aj_bj) * libcrux_secrets_int_as_i32_f5(zeta);
  int32_t ai_bi_aj_bj = ai_bi + aj_bj_zeta;
  int16_t o0 = libcrux_ml_kem_ಸದಿಶ_portable_arithmetic_montgomery_reduce_element(ai_bi_aj_bj);
  int32_t ai_bj = libcrux_secrets_int_as_i32_f5(ai) * libcrux_secrets_int_as_i32_f5(bj);
  int32_t aj_bi = libcrux_secrets_int_as_i32_f5(aj) * libcrux_secrets_int_as_i32_f5(bi);
  int32_t ai_bj_aj_bi = ai_bj + aj_bi;
  int16_t o1 = libcrux_ml_kem_ಸದಿಶ_portable_arithmetic_montgomery_reduce_element(ai_bj_aj_bi);
  ಹೊರಹೋಗು->ದತ್ತಾಂಶ[(ಗಾತ್ರ_t)2U * i] = o0;
  ಹೊರಹೋಗು->ದತ್ತಾಂಶ[(ಗಾತ್ರ_t)2U * i + (ಗಾತ್ರ_t)1U] = o1;
}

ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_ntt_ntt_multiply(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_d6 *lhs,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_d6 *rhs,
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
  Eurydice_arr_d6 ಹೊರಹೋಗು = libcrux_ml_kem_ಸದಿಶ_portable_ಸದಿಶ_type_zero();
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_ntt_multiply_binomials(lhs,
    rhs,
    libcrux_secrets_int_ಬಹಿರಂಗ_integers_classify_27_39(zeta0),
    (ಗಾತ್ರ_t)0U,
    &ಹೊರಹೋಗು);
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_ntt_multiply_binomials(lhs,
    rhs,
    libcrux_secrets_int_ಬಹಿರಂಗ_integers_classify_27_39(nzeta0),
    (ಗಾತ್ರ_t)1U,
    &ಹೊರಹೋಗು);
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_ntt_multiply_binomials(lhs,
    rhs,
    libcrux_secrets_int_ಬಹಿರಂಗ_integers_classify_27_39(zeta1),
    (ಗಾತ್ರ_t)2U,
    &ಹೊರಹೋಗು);
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_ntt_multiply_binomials(lhs,
    rhs,
    libcrux_secrets_int_ಬಹಿರಂಗ_integers_classify_27_39(nzeta1),
    (ಗಾತ್ರ_t)3U,
    &ಹೊರಹೋಗು);
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_ntt_multiply_binomials(lhs,
    rhs,
    libcrux_secrets_int_ಬಹಿರಂಗ_integers_classify_27_39(zeta2),
    (ಗಾತ್ರ_t)4U,
    &ಹೊರಹೋಗು);
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_ntt_multiply_binomials(lhs,
    rhs,
    libcrux_secrets_int_ಬಹಿರಂಗ_integers_classify_27_39(nzeta2),
    (ಗಾತ್ರ_t)5U,
    &ಹೊರಹೋಗು);
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_ntt_multiply_binomials(lhs,
    rhs,
    libcrux_secrets_int_ಬಹಿರಂಗ_integers_classify_27_39(zeta3),
    (ಗಾತ್ರ_t)6U,
    &ಹೊರಹೋಗು);
  libcrux_ml_kem_ಸದಿಶ_portable_ntt_ntt_multiply_binomials(lhs,
    rhs,
    libcrux_secrets_int_ಬಹಿರಂಗ_integers_classify_27_39(nzeta3),
    (ಗಾತ್ರ_t)7U,
    &ಹೊರಹೋಗು);
  ಹಿಂತಿರುಗಿ ಹೊರಹೋಗು;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_ntt_multiply_b8(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_d6 *lhs,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_d6 *rhs,
  int16_t zeta0,
  int16_t zeta1,
  int16_t zeta2,
  int16_t zeta3
)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ಸದಿಶ_portable_ntt_ntt_multiply(lhs, rhs, zeta0, zeta1, zeta2, zeta3);
}

ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_array_u8x2
libcrux_ml_kem_ಸದಿಶ_portable_serialize_serialize_1(Eurydice_arr_d6 v)
{
  uint8_t
  result0 =
    (((((((uint32_t)libcrux_secrets_int_as_u8_f5(v.ದತ್ತಾಂಶ[0U]) |
      (uint32_t)libcrux_secrets_int_as_u8_f5(v.ದತ್ತಾಂಶ[1U]) << 1U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.ದತ್ತಾಂಶ[2U]) << 2U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.ದತ್ತಾಂಶ[3U]) << 3U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.ದತ್ತಾಂಶ[4U]) << 4U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.ದತ್ತಾಂಶ[5U]) << 5U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.ದತ್ತಾಂಶ[6U]) << 6U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.ದತ್ತಾಂಶ[7U]) << 7U;
  uint8_t
  result1 =
    (((((((uint32_t)libcrux_secrets_int_as_u8_f5(v.ದತ್ತಾಂಶ[8U]) |
      (uint32_t)libcrux_secrets_int_as_u8_f5(v.ದತ್ತಾಂಶ[9U]) << 1U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.ದತ್ತಾಂಶ[10U]) << 2U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.ದತ್ತಾಂಶ[11U]) << 3U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.ದತ್ತಾಂಶ[12U]) << 4U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.ದತ್ತಾಂಶ[13U]) << 5U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.ದತ್ತಾಂಶ[14U]) << 6U)
    | (uint32_t)libcrux_secrets_int_as_u8_f5(v.ದತ್ತಾಂಶ[15U]) << 7U;
  ಹಿಂತಿರುಗಿ (KRML_CLITERAL(Eurydice_array_u8x2){ .ದತ್ತಾಂಶ = { result0, result1 } });
}

ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_array_u8x2 libcrux_ml_kem_ಸದಿಶ_portable_serialize_1(Eurydice_arr_d6 a)
{
  ಹಿಂತಿರುಗಿ
    libcrux_secrets_int_ಬಹಿರಂಗ_integers_declassify_d8_75(libcrux_ml_kem_ಸದಿಶ_portable_serialize_serialize_1(a));
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_array_u8x2
libcrux_ml_kem_ಸದಿಶ_portable_serialize_1_b8(Eurydice_arr_d6 a)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ಸದಿಶ_portable_serialize_1(a);
}

ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_serialize_deserialize_1(Eurydice_borrow_ತುಂಡು_u8 v)
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
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(Eurydice_arr_d6){
        .ದತ್ತಾಂಶ = {
          result0, result1, result2, result3, result4, result5, result6, result7, result8, result9,
          result10, result11, result12, result13, result14, result15
        }
      }
    );
}

ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_deserialize_1(Eurydice_borrow_ತುಂಡು_u8 a)
{
  ಹಿಂತಿರುಗಿ
    libcrux_ml_kem_ಸದಿಶ_portable_serialize_deserialize_1(libcrux_secrets_int_classify_ಬಹಿರಂಗ_classify_ref_6d_90(a));
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_deserialize_1_b8(Eurydice_borrow_ತುಂಡು_u8 a)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ಸದಿಶ_portable_deserialize_1(a);
}

ಸ್ಥಿರ KRML_MUSTINLINE uint8_t_x4
libcrux_ml_kem_ಸದಿಶ_portable_serialize_serialize_4_int(Eurydice_borrow_ತುಂಡು_i16 v)
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
  ಹಿಂತಿರುಗಿ
    (KRML_CLITERAL(uint8_t_x4){ .fst = result0, .snd = result1, .thd = result2, .f3 = result3 });
}

ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_array_u8x8
libcrux_ml_kem_ಸದಿಶ_portable_serialize_serialize_4(Eurydice_arr_d6 v)
{
  uint8_t_x4
  result0_3 =
    libcrux_ml_kem_ಸದಿಶ_portable_serialize_serialize_4_int(Eurydice_array_ಗಮ್ಯ_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = (ಗಾತ್ರ_t)0U, .ಕೊನೆ = (ಗಾತ್ರ_t)8U })));
  uint8_t_x4
  result4_7 =
    libcrux_ml_kem_ಸದಿಶ_portable_serialize_serialize_4_int(Eurydice_array_ಗಮ್ಯ_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = (ಗಾತ್ರ_t)8U, .ಕೊನೆ = (ಗಾತ್ರ_t)16U })));
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(Eurydice_array_u8x8){
        .ದತ್ತಾಂಶ = {
          result0_3.fst, result0_3.snd, result0_3.thd, result0_3.f3, result4_7.fst, result4_7.snd,
          result4_7.thd, result4_7.f3
        }
      }
    );
}

ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_array_u8x8 libcrux_ml_kem_ಸದಿಶ_portable_serialize_4(Eurydice_arr_d6 a)
{
  ಹಿಂತಿರುಗಿ
    libcrux_secrets_int_ಬಹಿರಂಗ_integers_declassify_d8_52(libcrux_ml_kem_ಸದಿಶ_portable_serialize_serialize_4(a));
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_array_u8x8
libcrux_ml_kem_ಸದಿಶ_portable_serialize_4_b8(Eurydice_arr_d6 a)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ಸದಿಶ_portable_serialize_4(a);
}

ಸ್ಥಿರ KRML_MUSTINLINE int16_t_x8
libcrux_ml_kem_ಸದಿಶ_portable_serialize_deserialize_4_int(Eurydice_borrow_ತುಂಡು_u8 ಬೈಟುಗಳು)
{
  int16_t v0 = libcrux_secrets_int_as_i16_59((uint32_t)ಬೈಟುಗಳು.ptr[0U] & 15U);
  int16_t v1 = libcrux_secrets_int_as_i16_59((uint32_t)ಬೈಟುಗಳು.ptr[0U] >> 4U & 15U);
  int16_t v2 = libcrux_secrets_int_as_i16_59((uint32_t)ಬೈಟುಗಳು.ptr[1U] & 15U);
  int16_t v3 = libcrux_secrets_int_as_i16_59((uint32_t)ಬೈಟುಗಳು.ptr[1U] >> 4U & 15U);
  int16_t v4 = libcrux_secrets_int_as_i16_59((uint32_t)ಬೈಟುಗಳು.ptr[2U] & 15U);
  int16_t v5 = libcrux_secrets_int_as_i16_59((uint32_t)ಬೈಟುಗಳು.ptr[2U] >> 4U & 15U);
  int16_t v6 = libcrux_secrets_int_as_i16_59((uint32_t)ಬೈಟುಗಳು.ptr[3U] & 15U);
  int16_t v7 = libcrux_secrets_int_as_i16_59((uint32_t)ಬೈಟುಗಳು.ptr[3U] >> 4U & 15U);
  ಹಿಂತಿರುಗಿ
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

ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_serialize_deserialize_4(Eurydice_borrow_ತುಂಡು_u8 ಬೈಟುಗಳು)
{
  int16_t_x8
  v0_7 =
    libcrux_ml_kem_ಸದಿಶ_portable_serialize_deserialize_4_int(Eurydice_ತುಂಡು_subslice_shared_c8(ಬೈಟುಗಳು,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = (ಗಾತ್ರ_t)0U, .ಕೊನೆ = (ಗಾತ್ರ_t)4U })));
  int16_t_x8
  v8_15 =
    libcrux_ml_kem_ಸದಿಶ_portable_serialize_deserialize_4_int(Eurydice_ತುಂಡು_subslice_shared_c8(ಬೈಟುಗಳು,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = (ಗಾತ್ರ_t)4U, .ಕೊನೆ = (ಗಾತ್ರ_t)8U })));
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(Eurydice_arr_d6){
        .ದತ್ತಾಂಶ = {
          v0_7.fst, v0_7.snd, v0_7.thd, v0_7.f3, v0_7.f4, v0_7.f5, v0_7.f6, v0_7.f7, v8_15.fst,
          v8_15.snd, v8_15.thd, v8_15.f3, v8_15.f4, v8_15.f5, v8_15.f6, v8_15.f7
        }
      }
    );
}

ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_deserialize_4(Eurydice_borrow_ತುಂಡು_u8 a)
{
  ಹಿಂತಿರುಗಿ
    libcrux_ml_kem_ಸದಿಶ_portable_serialize_deserialize_4(libcrux_secrets_int_classify_ಬಹಿರಂಗ_classify_ref_6d_90(a));
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_deserialize_4_b8(Eurydice_borrow_ತುಂಡು_u8 a)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ಸದಿಶ_portable_deserialize_4(a);
}

ಸ್ಥಿರ KRML_MUSTINLINE uint8_t_x5
libcrux_ml_kem_ಸದಿಶ_portable_serialize_serialize_10_int(Eurydice_borrow_ತುಂಡು_i16 v)
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
  ಹಿಂತಿರುಗಿ (KRML_CLITERAL(uint8_t_x5){ .fst = r0, .snd = r1, .thd = r2, .f3 = r3, .f4 = r4 });
}

ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_fc
libcrux_ml_kem_ಸದಿಶ_portable_serialize_serialize_10(Eurydice_arr_d6 v)
{
  uint8_t_x5
  r0_4 =
    libcrux_ml_kem_ಸದಿಶ_portable_serialize_serialize_10_int(Eurydice_array_ಗಮ್ಯ_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = (ಗಾತ್ರ_t)0U, .ಕೊನೆ = (ಗಾತ್ರ_t)4U })));
  uint8_t_x5
  r5_9 =
    libcrux_ml_kem_ಸದಿಶ_portable_serialize_serialize_10_int(Eurydice_array_ಗಮ್ಯ_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = (ಗಾತ್ರ_t)4U, .ಕೊನೆ = (ಗಾತ್ರ_t)8U })));
  uint8_t_x5
  r10_14 =
    libcrux_ml_kem_ಸದಿಶ_portable_serialize_serialize_10_int(Eurydice_array_ಗಮ್ಯ_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = (ಗಾತ್ರ_t)8U, .ಕೊನೆ = (ಗಾತ್ರ_t)12U })));
  uint8_t_x5
  r15_19 =
    libcrux_ml_kem_ಸದಿಶ_portable_serialize_serialize_10_int(Eurydice_array_ಗಮ್ಯ_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = (ಗಾತ್ರ_t)12U, .ಕೊನೆ = (ಗಾತ್ರ_t)16U })));
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(Eurydice_arr_fc){
        .ದತ್ತಾಂಶ = {
          r0_4.fst, r0_4.snd, r0_4.thd, r0_4.f3, r0_4.f4, r5_9.fst, r5_9.snd, r5_9.thd, r5_9.f3,
          r5_9.f4, r10_14.fst, r10_14.snd, r10_14.thd, r10_14.f3, r10_14.f4, r15_19.fst, r15_19.snd,
          r15_19.thd, r15_19.f3, r15_19.f4
        }
      }
    );
}

ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_fc libcrux_ml_kem_ಸದಿಶ_portable_serialize_10(Eurydice_arr_d6 a)
{
  ಹಿಂತಿರುಗಿ
    libcrux_secrets_int_ಬಹಿರಂಗ_integers_declassify_d8_2b(libcrux_ml_kem_ಸದಿಶ_portable_serialize_serialize_10(a));
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_fc libcrux_ml_kem_ಸದಿಶ_portable_serialize_10_b8(Eurydice_arr_d6 a)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ಸದಿಶ_portable_serialize_10(a);
}

ಸ್ಥಿರ KRML_MUSTINLINE int16_t_x8
libcrux_ml_kem_ಸದಿಶ_portable_serialize_deserialize_10_int(Eurydice_borrow_ತುಂಡು_u8 ಬೈಟುಗಳು)
{
  int16_t
  r0 =
    libcrux_secrets_int_as_i16_f5((int16_t)((uint32_t)(libcrux_secrets_int_as_i16_59(ಬೈಟುಗಳು.ptr[1U])
      & 3)
      << 8U)
      | (libcrux_secrets_int_as_i16_59(ಬೈಟುಗಳು.ptr[0U]) & 255));
  int16_t
  r1 =
    libcrux_secrets_int_as_i16_f5((int16_t)((uint32_t)(libcrux_secrets_int_as_i16_59(ಬೈಟುಗಳು.ptr[2U])
      & 15)
      << 6U)
      | libcrux_secrets_int_as_i16_59(ಬೈಟುಗಳು.ptr[1U]) >> 2U);
  int16_t
  r2 =
    libcrux_secrets_int_as_i16_f5((int16_t)((uint32_t)(libcrux_secrets_int_as_i16_59(ಬೈಟುಗಳು.ptr[3U])
      & 63)
      << 4U)
      | libcrux_secrets_int_as_i16_59(ಬೈಟುಗಳು.ptr[2U]) >> 4U);
  int16_t
  r3 =
    libcrux_secrets_int_as_i16_f5((int16_t)((uint32_t)libcrux_secrets_int_as_i16_59(ಬೈಟುಗಳು.ptr[4U])
      << 2U)
      | libcrux_secrets_int_as_i16_59(ಬೈಟುಗಳು.ptr[3U]) >> 6U);
  int16_t
  r4 =
    libcrux_secrets_int_as_i16_f5((int16_t)((uint32_t)(libcrux_secrets_int_as_i16_59(ಬೈಟುಗಳು.ptr[6U])
      & 3)
      << 8U)
      | (libcrux_secrets_int_as_i16_59(ಬೈಟುಗಳು.ptr[5U]) & 255));
  int16_t
  r5 =
    libcrux_secrets_int_as_i16_f5((int16_t)((uint32_t)(libcrux_secrets_int_as_i16_59(ಬೈಟುಗಳು.ptr[7U])
      & 15)
      << 6U)
      | libcrux_secrets_int_as_i16_59(ಬೈಟುಗಳು.ptr[6U]) >> 2U);
  int16_t
  r6 =
    libcrux_secrets_int_as_i16_f5((int16_t)((uint32_t)(libcrux_secrets_int_as_i16_59(ಬೈಟುಗಳು.ptr[8U])
      & 63)
      << 4U)
      | libcrux_secrets_int_as_i16_59(ಬೈಟುಗಳು.ptr[7U]) >> 4U);
  int16_t
  r7 =
    libcrux_secrets_int_as_i16_f5((int16_t)((uint32_t)libcrux_secrets_int_as_i16_59(ಬೈಟುಗಳು.ptr[9U])
      << 2U)
      | libcrux_secrets_int_as_i16_59(ಬೈಟುಗಳು.ptr[8U]) >> 6U);
  ಹಿಂತಿರುಗಿ
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

ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_serialize_deserialize_10(Eurydice_borrow_ತುಂಡು_u8 ಬೈಟುಗಳು)
{
  int16_t_x8
  v0_7 =
    libcrux_ml_kem_ಸದಿಶ_portable_serialize_deserialize_10_int(Eurydice_ತುಂಡು_subslice_shared_c8(ಬೈಟುಗಳು,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = (ಗಾತ್ರ_t)0U, .ಕೊನೆ = (ಗಾತ್ರ_t)10U })));
  int16_t_x8
  v8_15 =
    libcrux_ml_kem_ಸದಿಶ_portable_serialize_deserialize_10_int(Eurydice_ತುಂಡು_subslice_shared_c8(ಬೈಟುಗಳು,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = (ಗಾತ್ರ_t)10U, .ಕೊನೆ = (ಗಾತ್ರ_t)20U })));
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(Eurydice_arr_d6){
        .ದತ್ತಾಂಶ = {
          v0_7.fst, v0_7.snd, v0_7.thd, v0_7.f3, v0_7.f4, v0_7.f5, v0_7.f6, v0_7.f7, v8_15.fst,
          v8_15.snd, v8_15.thd, v8_15.f3, v8_15.f4, v8_15.f5, v8_15.f6, v8_15.f7
        }
      }
    );
}

ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_deserialize_10(Eurydice_borrow_ತುಂಡು_u8 a)
{
  ಹಿಂತಿರುಗಿ
    libcrux_ml_kem_ಸದಿಶ_portable_serialize_deserialize_10(libcrux_secrets_int_classify_ಬಹಿರಂಗ_classify_ref_6d_90(a));
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_deserialize_10_b8(Eurydice_borrow_ತುಂಡು_u8 a)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ಸದಿಶ_portable_deserialize_10(a);
}

ಸ್ಥಿರ KRML_MUSTINLINE uint8_t_x3
libcrux_ml_kem_ಸದಿಶ_portable_serialize_serialize_12_int(Eurydice_borrow_ತುಂಡು_i16 v)
{
  uint8_t r0 = libcrux_secrets_int_as_u8_f5(v.ptr[0U] & 255);
  uint8_t
  r1 =
    libcrux_secrets_int_as_u8_f5(v.ptr[0U] >> 8U | (int16_t)((uint32_t)(v.ptr[1U] & 15) << 4U));
  uint8_t r2 = libcrux_secrets_int_as_u8_f5(v.ptr[1U] >> 4U & 255);
  ಹಿಂತಿರುಗಿ (KRML_CLITERAL(uint8_t_x3){ .fst = r0, .snd = r1, .thd = r2 });
}

ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_94
libcrux_ml_kem_ಸದಿಶ_portable_serialize_serialize_12(Eurydice_arr_d6 v)
{
  uint8_t_x3
  r0_2 =
    libcrux_ml_kem_ಸದಿಶ_portable_serialize_serialize_12_int(Eurydice_array_ಗಮ್ಯ_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = (ಗಾತ್ರ_t)0U, .ಕೊನೆ = (ಗಾತ್ರ_t)2U })));
  uint8_t_x3
  r3_5 =
    libcrux_ml_kem_ಸದಿಶ_portable_serialize_serialize_12_int(Eurydice_array_ಗಮ್ಯ_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = (ಗಾತ್ರ_t)2U, .ಕೊನೆ = (ಗಾತ್ರ_t)4U })));
  uint8_t_x3
  r6_8 =
    libcrux_ml_kem_ಸದಿಶ_portable_serialize_serialize_12_int(Eurydice_array_ಗಮ್ಯ_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = (ಗಾತ್ರ_t)4U, .ಕೊನೆ = (ಗಾತ್ರ_t)6U })));
  uint8_t_x3
  r9_11 =
    libcrux_ml_kem_ಸದಿಶ_portable_serialize_serialize_12_int(Eurydice_array_ಗಮ್ಯ_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = (ಗಾತ್ರ_t)6U, .ಕೊನೆ = (ಗಾತ್ರ_t)8U })));
  uint8_t_x3
  r12_14 =
    libcrux_ml_kem_ಸದಿಶ_portable_serialize_serialize_12_int(Eurydice_array_ಗಮ್ಯ_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = (ಗಾತ್ರ_t)8U, .ಕೊನೆ = (ಗಾತ್ರ_t)10U })));
  uint8_t_x3
  r15_17 =
    libcrux_ml_kem_ಸದಿಶ_portable_serialize_serialize_12_int(Eurydice_array_ಗಮ್ಯ_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = (ಗಾತ್ರ_t)10U, .ಕೊನೆ = (ಗಾತ್ರ_t)12U })));
  uint8_t_x3
  r18_20 =
    libcrux_ml_kem_ಸದಿಶ_portable_serialize_serialize_12_int(Eurydice_array_ಗಮ್ಯ_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = (ಗಾತ್ರ_t)12U, .ಕೊನೆ = (ಗಾತ್ರ_t)14U })));
  uint8_t_x3
  r21_23 =
    libcrux_ml_kem_ಸದಿಶ_portable_serialize_serialize_12_int(Eurydice_array_ಗಮ್ಯ_subslice_shared_e7(&v,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = (ಗಾತ್ರ_t)14U, .ಕೊನೆ = (ಗಾತ್ರ_t)16U })));
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(Eurydice_arr_94){
        .ದತ್ತಾಂಶ = {
          r0_2.fst, r0_2.snd, r0_2.thd, r3_5.fst, r3_5.snd, r3_5.thd, r6_8.fst, r6_8.snd, r6_8.thd,
          r9_11.fst, r9_11.snd, r9_11.thd, r12_14.fst, r12_14.snd, r12_14.thd, r15_17.fst,
          r15_17.snd, r15_17.thd, r18_20.fst, r18_20.snd, r18_20.thd, r21_23.fst, r21_23.snd,
          r21_23.thd
        }
      }
    );
}

ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_94 libcrux_ml_kem_ಸದಿಶ_portable_serialize_12(Eurydice_arr_d6 a)
{
  ಹಿಂತಿರುಗಿ
    libcrux_secrets_int_ಬಹಿರಂಗ_integers_declassify_d8_40(libcrux_ml_kem_ಸದಿಶ_portable_serialize_serialize_12(a));
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_94 libcrux_ml_kem_ಸದಿಶ_portable_serialize_12_b8(Eurydice_arr_d6 a)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ಸದಿಶ_portable_serialize_12(a);
}

ಸ್ಥಿರ KRML_MUSTINLINE int16_t_x2
libcrux_ml_kem_ಸದಿಶ_portable_serialize_deserialize_12_int(Eurydice_borrow_ತುಂಡು_u8 ಬೈಟುಗಳು)
{
  int16_t byte0 = libcrux_secrets_int_as_i16_59(ಬೈಟುಗಳು.ptr[0U]);
  int16_t byte1 = libcrux_secrets_int_as_i16_59(ಬೈಟುಗಳು.ptr[1U]);
  int16_t byte2 = libcrux_secrets_int_as_i16_59(ಬೈಟುಗಳು.ptr[2U]);
  int16_t r0 = (int16_t)((uint32_t)(byte1 & 15) << 8U) | (byte0 & 255);
  int16_t r1 = (int16_t)((uint32_t)byte2 << 4U) | (byte1 >> 4U & 15);
  ಹಿಂತಿರುಗಿ (KRML_CLITERAL(int16_t_x2){ .fst = r0, .snd = r1 });
}

ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_serialize_deserialize_12(Eurydice_borrow_ತುಂಡು_u8 ಬೈಟುಗಳು)
{
  int16_t_x2
  v0_1 =
    libcrux_ml_kem_ಸದಿಶ_portable_serialize_deserialize_12_int(Eurydice_ತುಂಡು_subslice_shared_c8(ಬೈಟುಗಳು,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = (ಗಾತ್ರ_t)0U, .ಕೊನೆ = (ಗಾತ್ರ_t)3U })));
  int16_t_x2
  v2_3 =
    libcrux_ml_kem_ಸದಿಶ_portable_serialize_deserialize_12_int(Eurydice_ತುಂಡು_subslice_shared_c8(ಬೈಟುಗಳು,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = (ಗಾತ್ರ_t)3U, .ಕೊನೆ = (ಗಾತ್ರ_t)6U })));
  int16_t_x2
  v4_5 =
    libcrux_ml_kem_ಸದಿಶ_portable_serialize_deserialize_12_int(Eurydice_ತುಂಡು_subslice_shared_c8(ಬೈಟುಗಳು,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = (ಗಾತ್ರ_t)6U, .ಕೊನೆ = (ಗಾತ್ರ_t)9U })));
  int16_t_x2
  v6_7 =
    libcrux_ml_kem_ಸದಿಶ_portable_serialize_deserialize_12_int(Eurydice_ತುಂಡು_subslice_shared_c8(ಬೈಟುಗಳು,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = (ಗಾತ್ರ_t)9U, .ಕೊನೆ = (ಗಾತ್ರ_t)12U })));
  int16_t_x2
  v8_9 =
    libcrux_ml_kem_ಸದಿಶ_portable_serialize_deserialize_12_int(Eurydice_ತುಂಡು_subslice_shared_c8(ಬೈಟುಗಳು,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = (ಗಾತ್ರ_t)12U, .ಕೊನೆ = (ಗಾತ್ರ_t)15U })));
  int16_t_x2
  v10_11 =
    libcrux_ml_kem_ಸದಿಶ_portable_serialize_deserialize_12_int(Eurydice_ತುಂಡು_subslice_shared_c8(ಬೈಟುಗಳು,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = (ಗಾತ್ರ_t)15U, .ಕೊನೆ = (ಗಾತ್ರ_t)18U })));
  int16_t_x2
  v12_13 =
    libcrux_ml_kem_ಸದಿಶ_portable_serialize_deserialize_12_int(Eurydice_ತುಂಡು_subslice_shared_c8(ಬೈಟುಗಳು,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = (ಗಾತ್ರ_t)18U, .ಕೊನೆ = (ಗಾತ್ರ_t)21U })));
  int16_t_x2
  v14_15 =
    libcrux_ml_kem_ಸದಿಶ_portable_serialize_deserialize_12_int(Eurydice_ತುಂಡು_subslice_shared_c8(ಬೈಟುಗಳು,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = (ಗಾತ್ರ_t)21U, .ಕೊನೆ = (ಗಾತ್ರ_t)24U })));
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(Eurydice_arr_d6){
        .ದತ್ತಾಂಶ = {
          v0_1.fst, v0_1.snd, v2_3.fst, v2_3.snd, v4_5.fst, v4_5.snd, v6_7.fst, v6_7.snd, v8_9.fst,
          v8_9.snd, v10_11.fst, v10_11.snd, v12_13.fst, v12_13.snd, v14_15.fst, v14_15.snd
        }
      }
    );
}

ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_deserialize_12(Eurydice_borrow_ತುಂಡು_u8 a)
{
  ಹಿಂತಿರುಗಿ
    libcrux_ml_kem_ಸದಿಶ_portable_serialize_deserialize_12(libcrux_secrets_int_classify_ಬಹಿರಂಗ_classify_ref_6d_90(a));
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_deserialize_12_b8(Eurydice_borrow_ತುಂಡು_u8 a)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ಸದಿಶ_portable_deserialize_12(a);
}

ಸ್ಥಿರ KRML_MUSTINLINE ಗಾತ್ರ_t
libcrux_ml_kem_ಸದಿಶ_portable_sampling_rej_sample(
  Eurydice_borrow_ತುಂಡು_u8 a,
  Eurydice_mut_borrow_ತುಂಡು_i16 ಫಲಿತಾಂಶ
)
{
  ಗಾತ್ರ_t sampled = (ಗಾತ್ರ_t)0U;
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < a.meta / (ಗಾತ್ರ_t)3U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    int16_t b1 = (int16_t)(uint32_t)a.ptr[i0 * (ಗಾತ್ರ_t)3U + (ಗಾತ್ರ_t)0U];
    int16_t b2 = (int16_t)(uint32_t)a.ptr[i0 * (ಗಾತ್ರ_t)3U + (ಗಾತ್ರ_t)1U];
    int16_t b3 = (int16_t)(uint32_t)a.ptr[i0 * (ಗಾತ್ರ_t)3U + (ಗಾತ್ರ_t)2U];
    int16_t d1 = (int16_t)((uint32_t)(b2 & 15) << 8U) | b1;
    int16_t d2 = (int16_t)((uint32_t)b3 << 4U) | b2 >> 4U;
    ಆದರೆ (d1 < LIBCRUX_ML_KEM_ಸದಿಶ_TRAITS_ಕ್ಷೇತ್ರ_MODULUS)
    {
      ಆದರೆ (sampled < (ಗಾತ್ರ_t)16U)
      {
        ಫಲಿತಾಂಶ.ptr[sampled] = d1;
        sampled++;
      }
    }
    ಆದರೆ (d2 < LIBCRUX_ML_KEM_ಸದಿಶ_TRAITS_ಕ್ಷೇತ್ರ_MODULUS)
    {
      ಆದರೆ (sampled < (ಗಾತ್ರ_t)16U)
      {
        ಫಲಿತಾಂಶ.ptr[sampled] = d2;
        sampled++;
      }
    }
  }
  ಹಿಂತಿರುಗಿ sampled;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಗಾತ್ರ_t
libcrux_ml_kem_ಸದಿಶ_portable_rej_sample_b8(
  Eurydice_borrow_ತುಂಡು_u8 a,
  Eurydice_mut_borrow_ತುಂಡು_i16 ಹೊರಹೋಗು
)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ಸದಿಶ_portable_sampling_rej_sample(a, ಹೊರಹೋಗು);
}

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_KEM_MLKEM768_ಸದಿಶ_U_COMPRESSION_ಗುಣಕ ((ಗಾತ್ರ_t)10U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_KEM_MLKEM768_C1_ಖಂಡ_ಗಾತ್ರ (LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_ಒಳ_RING_ELEMENT * LIBCRUX_ML_KEM_MLKEM768_ಸದಿಶ_U_COMPRESSION_ಗುಣಕ / (ಗಾತ್ರ_t)8U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_KEM_MLKEM768_RANK ((ಗಾತ್ರ_t)3U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_KEM_MLKEM768_C1_ಗಾತ್ರ (LIBCRUX_ML_KEM_MLKEM768_C1_ಖಂಡ_ಗಾತ್ರ * LIBCRUX_ML_KEM_MLKEM768_RANK)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_KEM_MLKEM768_ಸದಿಶ_V_COMPRESSION_ಗುಣಕ ((ಗಾತ್ರ_t)4U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_KEM_MLKEM768_C2_ಗಾತ್ರ (LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_ಒಳ_RING_ELEMENT * LIBCRUX_ML_KEM_MLKEM768_ಸದಿಶ_V_COMPRESSION_ಗುಣಕ / (ಗಾತ್ರ_t)8U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_KEM_MLKEM768_CPA_PKE_CIPHERTEXT_ಗಾತ್ರ (LIBCRUX_ML_KEM_MLKEM768_C1_ಗಾತ್ರ + LIBCRUX_ML_KEM_MLKEM768_C2_ಗಾತ್ರ)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_KEM_MLKEM768_T_AS_NTT_ENCODED_ಗಾತ್ರ (LIBCRUX_ML_KEM_MLKEM768_RANK * LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_ಒಳ_RING_ELEMENT * LIBCRUX_ML_KEM_CONSTANTS_ಬಿಟ್ಟುಗಳು_ಪ್ರತಿ_COEFFICIENT / (ಗಾತ್ರ_t)8U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_KEM_MLKEM768_CPA_PKE_ಬಹಿರಂಗ_ಕೀಲಿ_ಗಾತ್ರ (LIBCRUX_ML_KEM_MLKEM768_T_AS_NTT_ENCODED_ಗಾತ್ರ + (ಗಾತ್ರ_t)32U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_KEM_MLKEM768_CPA_PKE_SECRET_ಕೀಲಿ_ಗಾತ್ರ (LIBCRUX_ML_KEM_MLKEM768_RANK * LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_ಒಳ_RING_ELEMENT * LIBCRUX_ML_KEM_CONSTANTS_ಬಿಟ್ಟುಗಳು_ಪ್ರತಿ_COEFFICIENT / (ಗಾತ್ರ_t)8U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_KEM_MLKEM768_ETA1 ((ಗಾತ್ರ_t)2U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_KEM_MLKEM768_ETA1_RANDOMNESS_ಗಾತ್ರ (LIBCRUX_ML_KEM_MLKEM768_ETA1 * (ಗಾತ್ರ_t)64U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_KEM_MLKEM768_ETA2 ((ಗಾತ್ರ_t)2U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_KEM_MLKEM768_ETA2_RANDOMNESS_ಗಾತ್ರ (LIBCRUX_ML_KEM_MLKEM768_ETA2 * (ಗಾತ್ರ_t)64U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_KEM_MLKEM768_IMPLICIT_REJECTION_HASH_ಒಳಹರಿವು_ಗಾತ್ರ (LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_ಗಾತ್ರ + LIBCRUX_ML_KEM_MLKEM768_CPA_PKE_CIPHERTEXT_ಗಾತ್ರ)

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ Eurydice_arr_7d libcrux_ml_kem_mlkem768_Ml_Kem768_ಖಾಸಗಿ_ಕೀಲಿ;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ Eurydice_arr_5f libcrux_ml_kem_mlkem768_Ml_Kem768_ಬಹಿರಂಗ_ಕೀಲಿ;

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_KEM_MLKEM768_RANKED_ಬೈಟುಗಳು_ಪ್ರತಿ_RING_ELEMENT (LIBCRUX_ML_KEM_MLKEM768_RANK * LIBCRUX_ML_KEM_CONSTANTS_ಬಿಟ್ಟುಗಳು_ಪ್ರತಿ_RING_ELEMENT / (ಗಾತ್ರ_t)8U)

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ML_KEM_MLKEM768_SECRET_ಕೀಲಿ_ಗಾತ್ರ (LIBCRUX_ML_KEM_MLKEM768_CPA_PKE_SECRET_ಕೀಲಿ_ಗಾತ್ರ + LIBCRUX_ML_KEM_MLKEM768_CPA_PKE_ಬಹಿರಂಗ_ಕೀಲಿ_ಗಾತ್ರ + LIBCRUX_ML_KEM_CONSTANTS_H_DIGEST_ಗಾತ್ರ + LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_ಗಾತ್ರ)

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- $16size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_9e_s { Eurydice_arr_d6 ದತ್ತಾಂಶ[16U]; } Eurydice_arr_9e;

/**
A monomorphic instance of Eurydice.arr
with types libcrux_ml_kem_polynomial_PolynomialRingElement_1d
with const generics
- $3size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_bb0_s { Eurydice_arr_9e ದತ್ತಾಂಶ[3U]; } Eurydice_arr_bb0;

/**
This function found in impl {libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.polynomial.ZERO_d6
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_9e libcrux_ml_kem_polynomial_ZERO_d6_ea(ಶೂನ್ಯ)
{
  Eurydice_arr_9e lit;
  Eurydice_arr_d6 repeat_ಅಭಿವ್ಯಕ್ತಿ[16U];
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)16U; i++)
  {
    repeat_ಅಭಿವ್ಯಕ್ತಿ[i] = libcrux_ml_kem_ಸದಿಶ_portable_ZERO_b8();
  }
  ಸ್ಮರಣೆ_ನಕಲು(lit.ದತ್ತಾಂಶ, repeat_ಅಭಿವ್ಯಕ್ತಿ, (ಗಾತ್ರ_t)16U * ಗಾತ್ರ (Eurydice_arr_d6));
  ಹಿಂತಿರುಗಿ lit;
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_9e
libcrux_ml_kem_ind_cpa_decrypt_call_mut_0b_01(ಶೂನ್ಯ **_, ಗಾತ್ರ_t tupled_ವಾದಗಳು)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_polynomial_ZERO_d6_ea();
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.deserialize_to_uncompressed_ring_element
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_serialize_deserialize_ಗಮ್ಯ_uncompressed_ring_element_ea(
  Eurydice_borrow_ತುಂಡು_u8 serialized
)
{
  Eurydice_arr_9e re = libcrux_ml_kem_polynomial_ZERO_d6_ea();
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < serialized.meta / (ಗಾತ್ರ_t)24U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    Eurydice_borrow_ತುಂಡು_u8
    ಬೈಟುಗಳು =
      Eurydice_ತುಂಡು_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ಆರಂಭ = i0 * (ಗಾತ್ರ_t)24U,
            .ಕೊನೆ = i0 * (ಗಾತ್ರ_t)24U + (ಗಾತ್ರ_t)24U
          }
        ));
    Eurydice_arr_d6 uu____0 = libcrux_ml_kem_ಸದಿಶ_portable_deserialize_12_b8(ಬೈಟುಗಳು);
    re.ದತ್ತಾಂಶ[i0] = uu____0;
  }
  ಹಿಂತಿರುಗಿ re;
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_kem_ind_cpa_deserialize_ಸದಿಶ_68(
  Eurydice_borrow_ತುಂಡು_u8 secret_ಕೀಲಿ,
  Eurydice_arr_bb0 *secret_as_ntt
)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)3U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    Eurydice_arr_9e
    uu____0 =
      libcrux_ml_kem_serialize_deserialize_ಗಮ್ಯ_uncompressed_ring_element_ea(Eurydice_ತುಂಡು_subslice_shared_c8(secret_ಕೀಲಿ,
          (
            KRML_CLITERAL(core_ops_range_Range_87){
              .ಆರಂಭ = i0 * LIBCRUX_ML_KEM_CONSTANTS_ಬೈಟುಗಳು_ಪ್ರತಿ_RING_ELEMENT,
              .ಕೊನೆ = (i0 + (ಗಾತ್ರ_t)1U) * LIBCRUX_ML_KEM_CONSTANTS_ಬೈಟುಗಳು_ಪ್ರತಿ_RING_ELEMENT
            }
          )));
    secret_as_ntt->ದತ್ತಾಂಶ[i0] = uu____0;
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_9e
libcrux_ml_kem_ind_cpa_deserialize_then_decompress_u_call_mut_35_30(
  ಶೂನ್ಯ **_,
  ಗಾತ್ರ_t tupled_ವಾದಗಳು
)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_polynomial_ZERO_d6_ea();
}

/**
A monomorphic instance of libcrux_ml_kem.vector.portable.compress.decompress_ciphertext_coefficient
with const generics
- COEFFICIENT_BITS= 10
*/
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_compress_decompress_ciphertext_coefficient_ef(Eurydice_arr_d6 a)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < LIBCRUX_ML_KEM_ಸದಿಶ_TRAITS_ಕ್ಷೇತ್ರ_ELEMENTS_ಒಳ_ಸದಿಶ; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    int32_t
    decompressed =
      libcrux_secrets_int_as_i32_f5(a.ದತ್ತಾಂಶ[i0]) *
        libcrux_secrets_int_as_i32_f5(libcrux_secrets_int_ಬಹಿರಂಗ_integers_classify_27_39(LIBCRUX_ML_KEM_ಸದಿಶ_TRAITS_ಕ್ಷೇತ್ರ_MODULUS));
    decompressed = (int32_t)((uint32_t)decompressed << 1U) + (int32_t)((uint32_t)1 << (uint32_t)10);
    decompressed >>= (uint32_t)(10 + 1);
    a.ದತ್ತಾಂಶ[i0] = libcrux_secrets_int_as_i16_36(decompressed);
  }
  ಹಿಂತಿರುಗಿ a;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
/**
A monomorphic instance of libcrux_ml_kem.vector.portable.decompress_ciphertext_coefficient_b8
with const generics
- COEFFICIENT_BITS= 10
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_decompress_ciphertext_coefficient_b8_ef(Eurydice_arr_d6 a)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ಸದಿಶ_portable_compress_decompress_ciphertext_coefficient_ef(a);
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.deserialize_then_decompress_10
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_serialize_deserialize_then_decompress_10_ea(Eurydice_borrow_ತುಂಡು_u8 serialized)
{
  Eurydice_arr_9e re = libcrux_ml_kem_polynomial_ZERO_d6_ea();
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < serialized.meta / (ಗಾತ್ರ_t)20U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    Eurydice_borrow_ತುಂಡು_u8
    ಬೈಟುಗಳು =
      Eurydice_ತುಂಡು_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ಆರಂಭ = i0 * (ಗಾತ್ರ_t)20U,
            .ಕೊನೆ = i0 * (ಗಾತ್ರ_t)20U + (ಗಾತ್ರ_t)20U
          }
        ));
    Eurydice_arr_d6 coefficient = libcrux_ml_kem_ಸದಿಶ_portable_deserialize_10_b8(ಬೈಟುಗಳು);
    Eurydice_arr_d6
    uu____0 = libcrux_ml_kem_ಸದಿಶ_portable_decompress_ciphertext_coefficient_b8_ef(coefficient);
    re.ದತ್ತಾಂಶ[i0] = uu____0;
  }
  ಹಿಂತಿರುಗಿ re;
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.deserialize_then_decompress_ring_element_u
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- COMPRESSION_FACTOR= 10
*/
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_serialize_deserialize_then_decompress_ring_element_u_f7(
  Eurydice_borrow_ತುಂಡು_u8 serialized
)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_serialize_deserialize_then_decompress_10_ea(serialized);
}

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ libcrux_ml_kem_ಸದಿಶ_portable_ಸದಿಶ_type_Portable_ಸದಿಶ_x2_s
{
  Eurydice_arr_d6 fst;
  Eurydice_arr_d6 snd;
}
libcrux_ml_kem_ಸದಿಶ_portable_ಸದಿಶ_type_Portable_ಸದಿಶ_x2;

/**
A monomorphic instance of libcrux_ml_kem.ntt.ntt_layer_int_vec_step
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE libcrux_ml_kem_ಸದಿಶ_portable_ಸದಿಶ_type_Portable_ಸದಿಶ_x2
libcrux_ml_kem_ntt_ntt_layer_int_vec_ಹೆಜ್ಜೆ_ea(
  Eurydice_arr_d6 a,
  Eurydice_arr_d6 b,
  int16_t zeta_r
)
{
  Eurydice_arr_d6
  t = libcrux_ml_kem_ಸದಿಶ_portable_montgomery_multiply_by_constant_b8(b, zeta_r);
  b = libcrux_ml_kem_ಸದಿಶ_portable_sub_b8(a, &t);
  a = libcrux_ml_kem_ಸದಿಶ_portable_ಕೂಡಿಸು_b8(a, &t);
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(libcrux_ml_kem_ಸದಿಶ_portable_ಸದಿಶ_type_Portable_ಸದಿಶ_x2){
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_kem_ntt_ntt_at_layer_4_plus_ea(
  ಗಾತ್ರ_t *zeta_i,
  Eurydice_arr_9e *re,
  ಗಾತ್ರ_t layer,
  ಗಾತ್ರ_t _initial_coefficient_bound
)
{
  ಗಾತ್ರ_t ಹೆಜ್ಜೆ = (ಗಾತ್ರ_t)1U << (uint32_t)layer;
  ಗಾಗಿ (ಗಾತ್ರ_t i0 = (ಗಾತ್ರ_t)0U; i0 < (ಗಾತ್ರ_t)128U >> (uint32_t)layer; i0++)
  {
    ಗಾತ್ರ_t ಸುತ್ತು = i0;
    zeta_i[0U]++;
    ಗಾತ್ರ_t ಸ್ಥಾನಾಂತರ = ಸುತ್ತು * ಹೆಜ್ಜೆ * (ಗಾತ್ರ_t)2U;
    ಗಾತ್ರ_t ಸ್ಥಾನಾಂತರ_vec = ಸ್ಥಾನಾಂತರ / (ಗಾತ್ರ_t)16U;
    ಗಾತ್ರ_t ಹೆಜ್ಜೆ_vec = ಹೆಜ್ಜೆ / (ಗಾತ್ರ_t)16U;
    ಗಾಗಿ (ಗಾತ್ರ_t i = ಸ್ಥಾನಾಂತರ_vec; i < ಸ್ಥಾನಾಂತರ_vec + ಹೆಜ್ಜೆ_vec; i++)
    {
      ಗಾತ್ರ_t j = i;
      libcrux_ml_kem_ಸದಿಶ_portable_ಸದಿಶ_type_Portable_ಸದಿಶ_x2
      uu____0 =
        libcrux_ml_kem_ntt_ntt_layer_int_vec_ಹೆಜ್ಜೆ_ea(re->ದತ್ತಾಂಶ[j],
          re->ದತ್ತಾಂಶ[j + ಹೆಜ್ಜೆ_vec],
          libcrux_ml_kem_polynomial_zeta(zeta_i[0U]));
      Eurydice_arr_d6 x = uu____0.fst;
      Eurydice_arr_d6 y = uu____0.snd;
      re->ದತ್ತಾಂಶ[j] = x;
      re->ದತ್ತಾಂಶ[j + ಹೆಜ್ಜೆ_vec] = y;
    }
  }
}

/**
A monomorphic instance of libcrux_ml_kem.ntt.ntt_at_layer_3
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_kem_ntt_ntt_at_layer_3_ea(
  ಗಾತ್ರ_t *zeta_i,
  Eurydice_arr_9e *re,
  ಗಾತ್ರ_t _initial_coefficient_bound
)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)16U; i++)
  {
    ಗಾತ್ರ_t ಸುತ್ತು = i;
    zeta_i[0U]++;
    Eurydice_arr_d6
    uu____0 =
      libcrux_ml_kem_ಸದಿಶ_portable_ntt_layer_3_ಹೆಜ್ಜೆ_b8(re->ದತ್ತಾಂಶ[ಸುತ್ತು],
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U]));
    re->ದತ್ತಾಂಶ[ಸುತ್ತು] = uu____0;
  }
}

/**
A monomorphic instance of libcrux_ml_kem.ntt.ntt_at_layer_2
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_kem_ntt_ntt_at_layer_2_ea(
  ಗಾತ್ರ_t *zeta_i,
  Eurydice_arr_9e *re,
  ಗಾತ್ರ_t _initial_coefficient_bound
)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)16U; i++)
  {
    ಗಾತ್ರ_t ಸುತ್ತು = i;
    zeta_i[0U]++;
    re->ದತ್ತಾಂಶ[ಸುತ್ತು] =
      libcrux_ml_kem_ಸದಿಶ_portable_ntt_layer_2_ಹೆಜ್ಜೆ_b8(re->ದತ್ತಾಂಶ[ಸುತ್ತು],
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U]),
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U] + (ಗಾತ್ರ_t)1U));
    zeta_i[0U]++;
  }
}

/**
A monomorphic instance of libcrux_ml_kem.ntt.ntt_at_layer_1
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_kem_ntt_ntt_at_layer_1_ea(
  ಗಾತ್ರ_t *zeta_i,
  Eurydice_arr_9e *re,
  ಗಾತ್ರ_t _initial_coefficient_bound
)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)16U; i++)
  {
    ಗಾತ್ರ_t ಸುತ್ತು = i;
    zeta_i[0U]++;
    re->ದತ್ತಾಂಶ[ಸುತ್ತು] =
      libcrux_ml_kem_ಸದಿಶ_portable_ntt_layer_1_ಹೆಜ್ಜೆ_b8(re->ದತ್ತಾಂಶ[ಸುತ್ತು],
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U]),
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U] + (ಗಾತ್ರ_t)1U),
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U] + (ಗಾತ್ರ_t)2U),
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U] + (ಗಾತ್ರ_t)3U));
    zeta_i[0U] += (ಗಾತ್ರ_t)3U;
  }
}

/**
A monomorphic instance of libcrux_ml_kem.polynomial.poly_barrett_reduce
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_kem_polynomial_poly_barrett_reduce_ea(Eurydice_arr_9e *myself)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_ಒಳ_RING_ELEMENT; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    Eurydice_arr_d6 uu____0 = libcrux_ml_kem_ಸದಿಶ_portable_barrett_reduce_b8(myself->ದತ್ತಾಂಶ[i0]);
    myself->ದತ್ತಾಂಶ[i0] = uu____0;
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ libcrux_ml_kem_ntt_ntt_ಸದಿಶ_u_f7(Eurydice_arr_9e *re)
{
  ಗಾತ್ರ_t zeta_i = (ಗಾತ್ರ_t)0U;
  libcrux_ml_kem_ntt_ntt_at_layer_4_plus_ea(&zeta_i, re, (ಗಾತ್ರ_t)7U, (ಗಾತ್ರ_t)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_4_plus_ea(&zeta_i, re, (ಗಾತ್ರ_t)6U, (ಗಾತ್ರ_t)2U * (ಗಾತ್ರ_t)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_4_plus_ea(&zeta_i, re, (ಗಾತ್ರ_t)5U, (ಗಾತ್ರ_t)3U * (ಗಾತ್ರ_t)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_4_plus_ea(&zeta_i, re, (ಗಾತ್ರ_t)4U, (ಗಾತ್ರ_t)4U * (ಗಾತ್ರ_t)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_3_ea(&zeta_i, re, (ಗಾತ್ರ_t)5U * (ಗಾತ್ರ_t)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_2_ea(&zeta_i, re, (ಗಾತ್ರ_t)6U * (ಗಾತ್ರ_t)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_1_ea(&zeta_i, re, (ಗಾತ್ರ_t)7U * (ಗಾತ್ರ_t)3328U);
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
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_bb0
libcrux_ml_kem_ind_cpa_deserialize_then_decompress_u_30(ಸ್ಥಿರಾಂಕ Eurydice_arr_2b *ciphertext)
{
  Eurydice_arr_bb0 arr_struct;
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    ಶೂನ್ಯ *lvalue = (ಶೂನ್ಯ *)0U;
    arr_struct.ದತ್ತಾಂಶ[i] =
      libcrux_ml_kem_ind_cpa_deserialize_then_decompress_u_call_mut_35_30(&lvalue,
        i);
  }
  Eurydice_arr_bb0 u_as_ntt = arr_struct;
  ಗಾಗಿ
  (ಗಾತ್ರ_t
    i = (ಗಾತ್ರ_t)0U;
    i <
      (ಗಾತ್ರ_t)1088U /
        (LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_ಒಳ_RING_ELEMENT * (ಗಾತ್ರ_t)10U / (ಗಾತ್ರ_t)8U);
    i++)
  {
    ಗಾತ್ರ_t i0 = i;
    Eurydice_borrow_ತುಂಡು_u8
    u_ಬೈಟುಗಳು =
      Eurydice_array_ಗಮ್ಯ_subslice_shared_d44(ciphertext,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ಆರಂಭ = i0 *
              (LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_ಒಳ_RING_ELEMENT * (ಗಾತ್ರ_t)10U / (ಗಾತ್ರ_t)8U),
            .ಕೊನೆ = i0 *
              (LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_ಒಳ_RING_ELEMENT * (ಗಾತ್ರ_t)10U / (ಗಾತ್ರ_t)8U)
            + LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_ಒಳ_RING_ELEMENT * (ಗಾತ್ರ_t)10U / (ಗಾತ್ರ_t)8U
          }
        ));
    u_as_ntt.ದತ್ತಾಂಶ[i0] =
      libcrux_ml_kem_serialize_deserialize_then_decompress_ring_element_u_f7(u_ಬೈಟುಗಳು);
    libcrux_ml_kem_ntt_ntt_ಸದಿಶ_u_f7(&u_as_ntt.ದತ್ತಾಂಶ[i0]);
  }
  ಹಿಂತಿರುಗಿ u_as_ntt;
}

/**
A monomorphic instance of libcrux_ml_kem.vector.portable.compress.decompress_ciphertext_coefficient
with const generics
- COEFFICIENT_BITS= 4
*/
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_compress_decompress_ciphertext_coefficient_d1(Eurydice_arr_d6 a)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < LIBCRUX_ML_KEM_ಸದಿಶ_TRAITS_ಕ್ಷೇತ್ರ_ELEMENTS_ಒಳ_ಸದಿಶ; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    int32_t
    decompressed =
      libcrux_secrets_int_as_i32_f5(a.ದತ್ತಾಂಶ[i0]) *
        libcrux_secrets_int_as_i32_f5(libcrux_secrets_int_ಬಹಿರಂಗ_integers_classify_27_39(LIBCRUX_ML_KEM_ಸದಿಶ_TRAITS_ಕ್ಷೇತ್ರ_MODULUS));
    decompressed = (int32_t)((uint32_t)decompressed << 1U) + (int32_t)((uint32_t)1 << (uint32_t)4);
    decompressed >>= (uint32_t)(4 + 1);
    a.ದತ್ತಾಂಶ[i0] = libcrux_secrets_int_as_i16_36(decompressed);
  }
  ಹಿಂತಿರುಗಿ a;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
/**
A monomorphic instance of libcrux_ml_kem.vector.portable.decompress_ciphertext_coefficient_b8
with const generics
- COEFFICIENT_BITS= 4
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_decompress_ciphertext_coefficient_b8_d1(Eurydice_arr_d6 a)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ಸದಿಶ_portable_compress_decompress_ciphertext_coefficient_d1(a);
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.deserialize_then_decompress_4
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_serialize_deserialize_then_decompress_4_ea(Eurydice_borrow_ತುಂಡು_u8 serialized)
{
  Eurydice_arr_9e re = libcrux_ml_kem_polynomial_ZERO_d6_ea();
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < serialized.meta / (ಗಾತ್ರ_t)8U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    Eurydice_borrow_ತುಂಡು_u8
    ಬೈಟುಗಳು =
      Eurydice_ತುಂಡು_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ಆರಂಭ = i0 * (ಗಾತ್ರ_t)8U,
            .ಕೊನೆ = i0 * (ಗಾತ್ರ_t)8U + (ಗಾತ್ರ_t)8U
          }
        ));
    Eurydice_arr_d6 coefficient = libcrux_ml_kem_ಸದಿಶ_portable_deserialize_4_b8(ಬೈಟುಗಳು);
    Eurydice_arr_d6
    uu____0 = libcrux_ml_kem_ಸದಿಶ_portable_decompress_ciphertext_coefficient_b8_d1(coefficient);
    re.ದತ್ತಾಂಶ[i0] = uu____0;
  }
  ಹಿಂತಿರುಗಿ re;
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.deserialize_then_decompress_ring_element_v
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- COMPRESSION_FACTOR= 4
*/
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_serialize_deserialize_then_decompress_ring_element_v_b6(
  Eurydice_borrow_ತುಂಡು_u8 serialized
)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_serialize_deserialize_then_decompress_4_ea(serialized);
}

/**
A monomorphic instance of libcrux_ml_kem.polynomial.ZERO
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_9e libcrux_ml_kem_polynomial_ZERO_ea(ಶೂನ್ಯ)
{
  Eurydice_arr_9e lit;
  Eurydice_arr_d6 repeat_ಅಭಿವ್ಯಕ್ತಿ[16U];
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)16U; i++)
  {
    repeat_ಅಭಿವ್ಯಕ್ತಿ[i] = libcrux_ml_kem_ಸದಿಶ_portable_ZERO_b8();
  }
  ಸ್ಮರಣೆ_ನಕಲು(lit.ದತ್ತಾಂಶ, repeat_ಅಭಿವ್ಯಕ್ತಿ, (ಗಾತ್ರ_t)16U * ಗಾತ್ರ (Eurydice_arr_d6));
  ಹಿಂತಿರುಗಿ lit;
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
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_polynomial_ntt_multiply_ea(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_9e *myself,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_9e *rhs
)
{
  Eurydice_arr_9e ಹೊರಹೋಗು = libcrux_ml_kem_polynomial_ZERO_ea();
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_ಒಳ_RING_ELEMENT; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    Eurydice_arr_d6
    uu____0 =
      libcrux_ml_kem_ಸದಿಶ_portable_ntt_multiply_b8(&myself->ದತ್ತಾಂಶ[i0],
        &rhs->ದತ್ತಾಂಶ[i0],
        libcrux_ml_kem_polynomial_zeta((ಗಾತ್ರ_t)64U + (ಗಾತ್ರ_t)4U * i0),
        libcrux_ml_kem_polynomial_zeta((ಗಾತ್ರ_t)64U + (ಗಾತ್ರ_t)4U * i0 + (ಗಾತ್ರ_t)1U),
        libcrux_ml_kem_polynomial_zeta((ಗಾತ್ರ_t)64U + (ಗಾತ್ರ_t)4U * i0 + (ಗಾತ್ರ_t)2U),
        libcrux_ml_kem_polynomial_zeta((ಗಾತ್ರ_t)64U + (ಗಾತ್ರ_t)4U * i0 + (ಗಾತ್ರ_t)3U));
    ಹೊರಹೋಗು.ದತ್ತಾಂಶ[i0] = uu____0;
  }
  ಹಿಂತಿರುಗಿ ಹೊರಹೋಗು;
}

/**
This function found in impl {libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.polynomial.ntt_multiply_d6
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_polynomial_ntt_multiply_d6_ea(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_9e *self,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_9e *rhs
)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_polynomial_ntt_multiply_ea(self, rhs);
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_kem_polynomial_ಕೂಡಿಸು_ಗಮ್ಯ_ring_element_68(
  Eurydice_arr_9e *myself,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_9e *rhs
)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)16U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    Eurydice_arr_d6
    uu____0 = libcrux_ml_kem_ಸದಿಶ_portable_ಕೂಡಿಸು_b8(myself->ದತ್ತಾಂಶ[i0], &rhs->ದತ್ತಾಂಶ[i0]);
    myself->ದತ್ತಾಂಶ[i0] = uu____0;
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_kem_polynomial_ಕೂಡಿಸು_ಗಮ್ಯ_ring_element_d6_68(
  Eurydice_arr_9e *self,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_9e *rhs
)
{
  libcrux_ml_kem_polynomial_ಕೂಡಿಸು_ಗಮ್ಯ_ring_element_68(self, rhs);
}

/**
A monomorphic instance of libcrux_ml_kem.invert_ntt.invert_ntt_at_layer_1
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_1_ea(ಗಾತ್ರ_t *zeta_i, Eurydice_arr_9e *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)16U; i++)
  {
    ಗಾತ್ರ_t ಸುತ್ತು = i;
    zeta_i[0U]--;
    re->ದತ್ತಾಂಶ[ಸುತ್ತು] =
      libcrux_ml_kem_ಸದಿಶ_portable_inv_ntt_layer_1_ಹೆಜ್ಜೆ_b8(re->ದತ್ತಾಂಶ[ಸುತ್ತು],
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U]),
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U] - (ಗಾತ್ರ_t)1U),
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U] - (ಗಾತ್ರ_t)2U),
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U] - (ಗಾತ್ರ_t)3U));
    zeta_i[0U] -= (ಗಾತ್ರ_t)3U;
  }
}

/**
A monomorphic instance of libcrux_ml_kem.invert_ntt.invert_ntt_at_layer_2
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_2_ea(ಗಾತ್ರ_t *zeta_i, Eurydice_arr_9e *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)16U; i++)
  {
    ಗಾತ್ರ_t ಸುತ್ತು = i;
    zeta_i[0U]--;
    re->ದತ್ತಾಂಶ[ಸುತ್ತು] =
      libcrux_ml_kem_ಸದಿಶ_portable_inv_ntt_layer_2_ಹೆಜ್ಜೆ_b8(re->ದತ್ತಾಂಶ[ಸುತ್ತು],
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U]),
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U] - (ಗಾತ್ರ_t)1U));
    zeta_i[0U]--;
  }
}

/**
A monomorphic instance of libcrux_ml_kem.invert_ntt.invert_ntt_at_layer_3
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_3_ea(ಗಾತ್ರ_t *zeta_i, Eurydice_arr_9e *re)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)16U; i++)
  {
    ಗಾತ್ರ_t ಸುತ್ತು = i;
    zeta_i[0U]--;
    Eurydice_arr_d6
    uu____0 =
      libcrux_ml_kem_ಸದಿಶ_portable_inv_ntt_layer_3_ಹೆಜ್ಜೆ_b8(re->ದತ್ತಾಂಶ[ಸುತ್ತು],
        libcrux_ml_kem_polynomial_zeta(zeta_i[0U]));
    re->ದತ್ತಾಂಶ[ಸುತ್ತು] = uu____0;
  }
}

/**
A monomorphic instance of libcrux_ml_kem.invert_ntt.inv_ntt_layer_int_vec_step_reduce
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE libcrux_ml_kem_ಸದಿಶ_portable_ಸದಿಶ_type_Portable_ಸದಿಶ_x2
libcrux_ml_kem_invert_ntt_inv_ntt_layer_int_vec_ಹೆಜ್ಜೆ_reduce_ea(
  Eurydice_arr_d6 a,
  Eurydice_arr_d6 b,
  int16_t zeta_r
)
{
  Eurydice_arr_d6 a_minus_b = libcrux_ml_kem_ಸದಿಶ_portable_sub_b8(b, &a);
  a =
    libcrux_ml_kem_ಸದಿಶ_portable_barrett_reduce_b8(libcrux_ml_kem_ಸದಿಶ_portable_ಕೂಡಿಸು_b8(a, &b));
  b = libcrux_ml_kem_ಸದಿಶ_portable_montgomery_multiply_by_constant_b8(a_minus_b, zeta_r);
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(libcrux_ml_kem_ಸದಿಶ_portable_ಸದಿಶ_type_Portable_ಸದಿಶ_x2){
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_4_plus_ea(
  ಗಾತ್ರ_t *zeta_i,
  Eurydice_arr_9e *re,
  ಗಾತ್ರ_t layer
)
{
  ಗಾತ್ರ_t ಹೆಜ್ಜೆ = (ಗಾತ್ರ_t)1U << (uint32_t)layer;
  ಗಾಗಿ (ಗಾತ್ರ_t i0 = (ಗಾತ್ರ_t)0U; i0 < (ಗಾತ್ರ_t)128U >> (uint32_t)layer; i0++)
  {
    ಗಾತ್ರ_t ಸುತ್ತು = i0;
    zeta_i[0U]--;
    ಗಾತ್ರ_t ಸ್ಥಾನಾಂತರ = ಸುತ್ತು * ಹೆಜ್ಜೆ * (ಗಾತ್ರ_t)2U;
    ಗಾತ್ರ_t ಸ್ಥಾನಾಂತರ_vec = ಸ್ಥಾನಾಂತರ / LIBCRUX_ML_KEM_ಸದಿಶ_TRAITS_ಕ್ಷೇತ್ರ_ELEMENTS_ಒಳ_ಸದಿಶ;
    ಗಾತ್ರ_t ಹೆಜ್ಜೆ_vec = ಹೆಜ್ಜೆ / LIBCRUX_ML_KEM_ಸದಿಶ_TRAITS_ಕ್ಷೇತ್ರ_ELEMENTS_ಒಳ_ಸದಿಶ;
    ಗಾಗಿ (ಗಾತ್ರ_t i = ಸ್ಥಾನಾಂತರ_vec; i < ಸ್ಥಾನಾಂತರ_vec + ಹೆಜ್ಜೆ_vec; i++)
    {
      ಗಾತ್ರ_t j = i;
      libcrux_ml_kem_ಸದಿಶ_portable_ಸದಿಶ_type_Portable_ಸದಿಶ_x2
      uu____0 =
        libcrux_ml_kem_invert_ntt_inv_ntt_layer_int_vec_ಹೆಜ್ಜೆ_reduce_ea(re->ದತ್ತಾಂಶ[j],
          re->ದತ್ತಾಂಶ[j + ಹೆಜ್ಜೆ_vec],
          libcrux_ml_kem_polynomial_zeta(zeta_i[0U]));
      Eurydice_arr_d6 x = uu____0.fst;
      Eurydice_arr_d6 y = uu____0.snd;
      re->ದತ್ತಾಂಶ[j] = x;
      re->ದತ್ತಾಂಶ[j + ಹೆಜ್ಜೆ_vec] = y;
    }
  }
}

/**
A monomorphic instance of libcrux_ml_kem.invert_ntt.invert_ntt_montgomery
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_kem_invert_ntt_invert_ntt_montgomery_68(Eurydice_arr_9e *re)
{
  ಗಾತ್ರ_t zeta_i = LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_ಒಳ_RING_ELEMENT / (ಗಾತ್ರ_t)2U;
  libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_1_ea(&zeta_i, re);
  libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_2_ea(&zeta_i, re);
  libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_3_ea(&zeta_i, re);
  libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_4_plus_ea(&zeta_i, re, (ಗಾತ್ರ_t)4U);
  libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_4_plus_ea(&zeta_i, re, (ಗಾತ್ರ_t)5U);
  libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_4_plus_ea(&zeta_i, re, (ಗಾತ್ರ_t)6U);
  libcrux_ml_kem_invert_ntt_invert_ntt_at_layer_4_plus_ea(&zeta_i, re, (ಗಾತ್ರ_t)7U);
  libcrux_ml_kem_polynomial_poly_barrett_reduce_d6_ea(re);
}

/**
A monomorphic instance of libcrux_ml_kem.polynomial.subtract_reduce
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_polynomial_ಕಳೆ_reduce_ea(ಸ್ಥಿರಾಂಕ Eurydice_arr_9e *myself, Eurydice_arr_9e b)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_ಒಳ_RING_ELEMENT; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    Eurydice_arr_d6
    coefficient_ಸಾಮಾನ್ಯ_form =
      libcrux_ml_kem_ಸದಿಶ_portable_montgomery_multiply_by_constant_b8(b.ದತ್ತಾಂಶ[i0],
        1441);
    Eurydice_arr_d6
    diff = libcrux_ml_kem_ಸದಿಶ_portable_sub_b8(myself->ದತ್ತಾಂಶ[i0], &coefficient_ಸಾಮಾನ್ಯ_form);
    Eurydice_arr_d6 red = libcrux_ml_kem_ಸದಿಶ_portable_barrett_reduce_b8(diff);
    b.ದತ್ತಾಂಶ[i0] = red;
  }
  ಹಿಂತಿರುಗಿ b;
}

/**
This function found in impl {libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.polynomial.subtract_reduce_d6
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_polynomial_ಕಳೆ_reduce_d6_ea(ಸ್ಥಿರಾಂಕ Eurydice_arr_9e *self, Eurydice_arr_9e b)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_polynomial_ಕಳೆ_reduce_ea(self, b);
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
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_ಮಾತೃಕೆ_compute_ಸಂದೇಶ_68(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_9e *v,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_bb0 *secret_as_ntt,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_bb0 *u_as_ntt
)
{
  Eurydice_arr_9e ಫಲಿತಾಂಶ = libcrux_ml_kem_polynomial_ZERO_d6_ea();
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)3U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    Eurydice_arr_9e
    ಗುಣಲಬ್ಧ =
      libcrux_ml_kem_polynomial_ntt_multiply_d6_ea(&secret_as_ntt->ದತ್ತಾಂಶ[i0],
        &u_as_ntt->ದತ್ತಾಂಶ[i0]);
    libcrux_ml_kem_polynomial_ಕೂಡಿಸು_ಗಮ್ಯ_ring_element_d6_68(&ಫಲಿತಾಂಶ, &ಗುಣಲಬ್ಧ);
  }
  libcrux_ml_kem_invert_ntt_invert_ntt_montgomery_68(&ಫಲಿತಾಂಶ);
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_polynomial_ಕಳೆ_reduce_d6_ea(v, ಫಲಿತಾಂಶ);
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.to_unsigned_field_modulus
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_serialize_ಗಮ್ಯ_unsigned_ಕ್ಷೇತ್ರ_modulus_ea(Eurydice_arr_d6 a)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ಸದಿಶ_portable_ಗಮ್ಯ_unsigned_representative_b8(a);
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.compress_then_serialize_message
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_ec
libcrux_ml_kem_serialize_compress_then_serialize_ಸಂದೇಶ_ea(Eurydice_arr_9e re)
{
  Eurydice_arr_ec serialized = { .ದತ್ತಾಂಶ = { 0U } };
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)16U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    Eurydice_arr_d6
    coefficient = libcrux_ml_kem_serialize_ಗಮ್ಯ_unsigned_ಕ್ಷೇತ್ರ_modulus_ea(re.ದತ್ತಾಂಶ[i0]);
    Eurydice_arr_d6
    coefficient_compressed = libcrux_ml_kem_ಸದಿಶ_portable_compress_1_b8(coefficient);
    Eurydice_array_u8x2
    ಬೈಟುಗಳು = libcrux_ml_kem_ಸದಿಶ_portable_serialize_1_b8(coefficient_compressed);
    Eurydice_ತುಂಡು_copy(Eurydice_array_ಗಮ್ಯ_subslice_mut_d46(&serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ಆರಂಭ = (ಗಾತ್ರ_t)2U * i0,
            .ಕೊನೆ = (ಗಾತ್ರ_t)2U * i0 + (ಗಾತ್ರ_t)2U
          }
        )),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_82(&ಬೈಟುಗಳು),
      uint8_t);
  }
  ಹಿಂತಿರುಗಿ serialized;
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
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_ec
libcrux_ml_kem_ind_cpa_decrypt_unpacked_01(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_bb0 *secret_ಕೀಲಿ,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_2b *ciphertext
)
{
  Eurydice_arr_bb0
  u_as_ntt = libcrux_ml_kem_ind_cpa_deserialize_then_decompress_u_30(ciphertext);
  Eurydice_arr_9e
  v =
    libcrux_ml_kem_serialize_deserialize_then_decompress_ring_element_v_b6(Eurydice_array_ಗಮ್ಯ_subslice_from_shared_5f0(ciphertext,
        (ಗಾತ್ರ_t)960U));
  Eurydice_arr_9e ಸಂದೇಶ_2 = libcrux_ml_kem_ಮಾತೃಕೆ_compute_ಸಂದೇಶ_68(&v, secret_ಕೀಲಿ, &u_as_ntt);
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_serialize_compress_then_serialize_ಸಂದೇಶ_ea(ಸಂದೇಶ_2);
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
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_ec
libcrux_ml_kem_ind_cpa_decrypt_01(
  Eurydice_borrow_ತುಂಡು_u8 secret_ಕೀಲಿ,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_2b *ciphertext
)
{
  Eurydice_arr_bb0 arr_struct;
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    ಶೂನ್ಯ *lvalue = (ಶೂನ್ಯ *)0U;
    arr_struct.ದತ್ತಾಂಶ[i] = libcrux_ml_kem_ind_cpa_decrypt_call_mut_0b_01(&lvalue, i);
  }
  Eurydice_arr_bb0 secret_ಕೀಲಿ_unpacked = arr_struct;
  libcrux_ml_kem_ind_cpa_deserialize_ಸದಿಶ_68(secret_ಕೀಲಿ, &secret_ಕೀಲಿ_unpacked);
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ind_cpa_decrypt_unpacked_01(&secret_ಕೀಲಿ_unpacked, ciphertext);
}

/**
This function found in impl {libcrux_ml_kem::hash_functions::Hash<K> for libcrux_ml_kem::hash_functions::portable::PortableHash<K>}
*/
/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.G_4a
with const generics
- K= 3
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_c7
libcrux_ml_kem_hash_functions_portable_G_4a_78(Eurydice_borrow_ತುಂಡು_u8 ಒಳಹರಿವು)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_hash_functions_portable_G(ಒಳಹರಿವು);
}

/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.PRF
with const generics
- LEN= 32
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_ec
libcrux_ml_kem_hash_functions_portable_PRF_ce(Eurydice_borrow_ತುಂಡು_u8 ಒಳಹರಿವು)
{
  Eurydice_arr_ec digest = { .ದತ್ತಾಂಶ = { 0U } };
  libcrux_sha3_portable_shake256(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_01(&digest), ಒಳಹರಿವು);
  ಹಿಂತಿರುಗಿ digest;
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_ec
libcrux_ml_kem_hash_functions_portable_PRF_4a_3b(Eurydice_borrow_ತುಂಡು_u8 ಒಳಹರಿವು)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_hash_functions_portable_PRF_ce(ಒಳಹರಿವು);
}

/**
A monomorphic instance of Eurydice.arr
with types Eurydice_arr_bb0
with const generics
- $3size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ Eurydice_arr_c10_s { Eurydice_arr_bb0 ದತ್ತಾಂಶ[3U]; } Eurydice_arr_c10;

/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.unpacked.IndCpaPublicKeyUnpacked
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- $3size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_ಬಹಿರಂಗ_ಕೀಲಿ_Unpacked_51_s
{
  Eurydice_arr_bb0 t_as_ntt;
  Eurydice_arr_ec ಬೀಜ_for_A;
  Eurydice_arr_c10 A;
}
libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_ಬಹಿರಂಗ_ಕೀಲಿ_Unpacked_51;

/**
This function found in impl {core::default::Default for libcrux_ml_kem::ind_cpa::unpacked::IndCpaPublicKeyUnpacked<Vector, K>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.unpacked.default_8b
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_ಬಹಿರಂಗ_ಕೀಲಿ_Unpacked_51
libcrux_ml_kem_ind_cpa_unpacked_default_8b_68(ಶೂನ್ಯ)
{
  Eurydice_arr_bb0 uu____0;
  Eurydice_arr_9e repeat_expression0[3U];
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)3U; i++)
  {
    repeat_expression0[i] = libcrux_ml_kem_polynomial_ZERO_d6_ea();
  }
  ಸ್ಮರಣೆ_ನಕಲು(uu____0.ದತ್ತಾಂಶ, repeat_expression0, (ಗಾತ್ರ_t)3U * ಗಾತ್ರ (Eurydice_arr_9e));
  Eurydice_arr_ec uu____1 = { .ದತ್ತಾಂಶ = { 0U } };
  libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_ಬಹಿರಂಗ_ಕೀಲಿ_Unpacked_51 lit0;
  lit0.t_as_ntt = uu____0;
  lit0.ಬೀಜ_for_A = uu____1;
  Eurydice_arr_bb0 repeat_expression1[3U];
  ಗಾಗಿ (ಗಾತ್ರ_t i0 = (ಗಾತ್ರ_t)0U; i0 < (ಗಾತ್ರ_t)3U; i0++)
  {
    Eurydice_arr_bb0 lit;
    Eurydice_arr_9e repeat_ಅಭಿವ್ಯಕ್ತಿ[3U];
    ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)3U; i++)
    {
      repeat_ಅಭಿವ್ಯಕ್ತಿ[i] = libcrux_ml_kem_polynomial_ZERO_d6_ea();
    }
    ಸ್ಮರಣೆ_ನಕಲು(lit.ದತ್ತಾಂಶ, repeat_ಅಭಿವ್ಯಕ್ತಿ, (ಗಾತ್ರ_t)3U * ಗಾತ್ರ (Eurydice_arr_9e));
    repeat_expression1[i0] = lit;
  }
  ಸ್ಮರಣೆ_ನಕಲು(lit0.A.ದತ್ತಾಂಶ, repeat_expression1, (ಗಾತ್ರ_t)3U * ಗಾತ್ರ (Eurydice_arr_bb0));
  ಹಿಂತಿರುಗಿ lit0;
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
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_serialize_deserialize_ಗಮ್ಯ_reduced_ring_element_ea(
  Eurydice_borrow_ತುಂಡು_u8 serialized
)
{
  Eurydice_arr_9e re = libcrux_ml_kem_polynomial_ZERO_d6_ea();
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < serialized.meta / (ಗಾತ್ರ_t)24U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    Eurydice_borrow_ತುಂಡು_u8
    ಬೈಟುಗಳು =
      Eurydice_ತುಂಡು_subslice_shared_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ಆರಂಭ = i0 * (ಗಾತ್ರ_t)24U,
            .ಕೊನೆ = i0 * (ಗಾತ್ರ_t)24U + (ಗಾತ್ರ_t)24U
          }
        ));
    Eurydice_arr_d6 coefficient = libcrux_ml_kem_ಸದಿಶ_portable_deserialize_12_b8(ಬೈಟುಗಳು);
    Eurydice_arr_d6 uu____0 = libcrux_ml_kem_ಸದಿಶ_portable_cond_ಕಳೆ_3329_b8(coefficient);
    re.ದತ್ತಾಂಶ[i0] = uu____0;
  }
  ಹಿಂತಿರುಗಿ re;
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_kem_serialize_deserialize_ring_elements_reduced_68(
  Eurydice_borrow_ತುಂಡು_u8 ಬಹಿರಂಗ_ಕೀಲಿ,
  Eurydice_arr_bb0 *deserialized_pk
)
{
  ಗಾಗಿ
  (ಗಾತ್ರ_t
    i = (ಗಾತ್ರ_t)0U;
    i < ಬಹಿರಂಗ_ಕೀಲಿ.meta / LIBCRUX_ML_KEM_CONSTANTS_ಬೈಟುಗಳು_ಪ್ರತಿ_RING_ELEMENT;
    i++)
  {
    ಗಾತ್ರ_t i0 = i;
    Eurydice_borrow_ತುಂಡು_u8
    ring_element =
      Eurydice_ತುಂಡು_subslice_shared_c8(ಬಹಿರಂಗ_ಕೀಲಿ,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ಆರಂಭ = i0 * LIBCRUX_ML_KEM_CONSTANTS_ಬೈಟುಗಳು_ಪ್ರತಿ_RING_ELEMENT,
            .ಕೊನೆ = i0 * LIBCRUX_ML_KEM_CONSTANTS_ಬೈಟುಗಳು_ಪ್ರತಿ_RING_ELEMENT +
              LIBCRUX_ML_KEM_CONSTANTS_ಬೈಟುಗಳು_ಪ್ರತಿ_RING_ELEMENT
          }
        ));
    Eurydice_arr_9e
    uu____0 = libcrux_ml_kem_serialize_deserialize_ಗಮ್ಯ_reduced_ring_element_ea(ring_element);
    deserialized_pk->ದತ್ತಾಂಶ[i0] = uu____0;
  }
}

/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.shake128_init_absorb_final
with const generics
- K= 3
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_1b0
libcrux_ml_kem_hash_functions_portable_shake128_init_absorb_final_78(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_810 *ಒಳಹರಿವು
)
{
  Eurydice_arr_1b0 shake128_state;
  Eurydice_arr_7c repeat_ಅಭಿವ್ಯಕ್ತಿ[3U];
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)3U; i++)
  {
    repeat_ಅಭಿವ್ಯಕ್ತಿ[i] = libcrux_sha3_portable_incremental_shake128_init();
  }
  ಸ್ಮರಣೆ_ನಕಲು(shake128_state.ದತ್ತಾಂಶ, repeat_ಅಭಿವ್ಯಕ್ತಿ, (ಗಾತ್ರ_t)3U * ಗಾತ್ರ (Eurydice_arr_7c));
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)3U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    libcrux_sha3_portable_incremental_shake128_absorb_final(&shake128_state.ದತ್ತಾಂಶ[i0],
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_e9(&ಒಳಹರಿವು->ದತ್ತಾಂಶ[i0]));
  }
  ಹಿಂತಿರುಗಿ shake128_state;
}

/**
This function found in impl {libcrux_ml_kem::hash_functions::Hash<K> for libcrux_ml_kem::hash_functions::portable::PortableHash<K>}
*/
/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.shake128_init_absorb_final_4a
with const generics
- K= 3
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_1b0
libcrux_ml_kem_hash_functions_portable_shake128_init_absorb_final_4a_78(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_810 *ಒಳಹರಿವು
)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_hash_functions_portable_shake128_init_absorb_final_78(ಒಳಹರಿವು);
}

/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.shake128_squeeze_first_three_blocks
with const generics
- K= 3
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_7e
libcrux_ml_kem_hash_functions_portable_shake128_squeeze_ಮೊದಲ_three_ಖಂಡಗಳು_78(
  Eurydice_arr_1b0 *st
)
{
  Eurydice_arr_7e
  ಹೊರಹೋಗು = { .ದತ್ತಾಂಶ = { { .ದತ್ತಾಂಶ = { 0U } }, { .ದತ್ತಾಂಶ = { 0U } }, { .ದತ್ತಾಂಶ = { 0U } } } };
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)3U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    libcrux_sha3_portable_incremental_shake128_squeeze_ಮೊದಲ_three_ಖಂಡಗಳು(&st->ದತ್ತಾಂಶ[i0],
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_48(&ಹೊರಹೋಗು.ದತ್ತಾಂಶ[i0]));
  }
  ಹಿಂತಿರುಗಿ ಹೊರಹೋಗು;
}

/**
This function found in impl {libcrux_ml_kem::hash_functions::Hash<K> for libcrux_ml_kem::hash_functions::portable::PortableHash<K>}
*/
/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.shake128_squeeze_first_three_blocks_4a
with const generics
- K= 3
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_7e
libcrux_ml_kem_hash_functions_portable_shake128_squeeze_ಮೊದಲ_three_ಖಂಡಗಳು_4a_78(
  Eurydice_arr_1b0 *self
)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_hash_functions_portable_shake128_squeeze_ಮೊದಲ_three_ಖಂಡಗಳು_78(self);
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
ಸ್ಥಿರ KRML_MUSTINLINE bool
libcrux_ml_kem_sampling_sample_from_ಏಕರೂಪ_distribution_ಮುಂದಿನ_b6(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_7e *randomness,
  Eurydice_arr_eb *sampled_coefficients,
  Eurydice_arr_b1 *ಹೊರಹೋಗು
)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i0 = (ಗಾತ್ರ_t)0U; i0 < (ಗಾತ್ರ_t)3U; i0++)
  {
    ಗಾತ್ರ_t i1 = i0;
    ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)504U / (ಗಾತ್ರ_t)24U; i++)
    {
      ಗಾತ್ರ_t r = i;
      ಆದರೆ (sampled_coefficients->ದತ್ತಾಂಶ[i1] < LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_ಒಳ_RING_ELEMENT)
      {
        ಗಾತ್ರ_t
        sampled =
          libcrux_ml_kem_ಸದಿಶ_portable_rej_sample_b8(Eurydice_array_ಗಮ್ಯ_subslice_shared_d45(&randomness->ದತ್ತಾಂಶ[i1],
              (
                KRML_CLITERAL(core_ops_range_Range_87){
                  .ಆರಂಭ = r * (ಗಾತ್ರ_t)24U,
                  .ಕೊನೆ = r * (ಗಾತ್ರ_t)24U + (ಗಾತ್ರ_t)24U
                }
              )),
            Eurydice_array_ಗಮ್ಯ_subslice_mut_e7(&ಹೊರಹೋಗು->ದತ್ತಾಂಶ[i1],
              (
                KRML_CLITERAL(core_ops_range_Range_87){
                  .ಆರಂಭ = sampled_coefficients->ದತ್ತಾಂಶ[i1],
                  .ಕೊನೆ = sampled_coefficients->ದತ್ತಾಂಶ[i1] + (ಗಾತ್ರ_t)16U
                }
              )));
        ಗಾತ್ರ_t uu____0 = i1;
        sampled_coefficients->ದತ್ತಾಂಶ[uu____0] += sampled;
      }
    }
  }
  bool ಮುಗಿದ = true;
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)3U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    ಆದರೆ (sampled_coefficients->ದತ್ತಾಂಶ[i0] >= LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_ಒಳ_RING_ELEMENT)
    {
      sampled_coefficients->ದತ್ತಾಂಶ[i0] = LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_ಒಳ_RING_ELEMENT;
    }
    ಇಲ್ಲದಿದ್ದರೆ
    {
      ಮುಗಿದ = false;
    }
  }
  ಹಿಂತಿರುಗಿ ಮುಗಿದ;
}

/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.shake128_squeeze_next_block
with const generics
- K= 3
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_2c
libcrux_ml_kem_hash_functions_portable_shake128_squeeze_ಮುಂದಿನ_ಖಂಡ_78(Eurydice_arr_1b0 *st)
{
  Eurydice_arr_2c
  ಹೊರಹೋಗು = { .ದತ್ತಾಂಶ = { { .ದತ್ತಾಂಶ = { 0U } }, { .ದತ್ತಾಂಶ = { 0U } }, { .ದತ್ತಾಂಶ = { 0U } } } };
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)3U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    libcrux_sha3_portable_incremental_shake128_squeeze_ಮುಂದಿನ_ಖಂಡ(&st->ದತ್ತಾಂಶ[i0],
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_2c(&ಹೊರಹೋಗು.ದತ್ತಾಂಶ[i0]));
  }
  ಹಿಂತಿರುಗಿ ಹೊರಹೋಗು;
}

/**
This function found in impl {libcrux_ml_kem::hash_functions::Hash<K> for libcrux_ml_kem::hash_functions::portable::PortableHash<K>}
*/
/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.shake128_squeeze_next_block_4a
with const generics
- K= 3
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_2c
libcrux_ml_kem_hash_functions_portable_shake128_squeeze_ಮುಂದಿನ_ಖಂಡ_4a_78(
  Eurydice_arr_1b0 *self
)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_hash_functions_portable_shake128_squeeze_ಮುಂದಿನ_ಖಂಡ_78(self);
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
ಸ್ಥಿರ KRML_MUSTINLINE bool
libcrux_ml_kem_sampling_sample_from_ಏಕರೂಪ_distribution_ಮುಂದಿನ_b60(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_2c *randomness,
  Eurydice_arr_eb *sampled_coefficients,
  Eurydice_arr_b1 *ಹೊರಹೋಗು
)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i0 = (ಗಾತ್ರ_t)0U; i0 < (ಗಾತ್ರ_t)3U; i0++)
  {
    ಗಾತ್ರ_t i1 = i0;
    ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)168U / (ಗಾತ್ರ_t)24U; i++)
    {
      ಗಾತ್ರ_t r = i;
      ಆದರೆ (sampled_coefficients->ದತ್ತಾಂಶ[i1] < LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_ಒಳ_RING_ELEMENT)
      {
        ಗಾತ್ರ_t
        sampled =
          libcrux_ml_kem_ಸದಿಶ_portable_rej_sample_b8(Eurydice_array_ಗಮ್ಯ_subslice_shared_d46(&randomness->ದತ್ತಾಂಶ[i1],
              (
                KRML_CLITERAL(core_ops_range_Range_87){
                  .ಆರಂಭ = r * (ಗಾತ್ರ_t)24U,
                  .ಕೊನೆ = r * (ಗಾತ್ರ_t)24U + (ಗಾತ್ರ_t)24U
                }
              )),
            Eurydice_array_ಗಮ್ಯ_subslice_mut_e7(&ಹೊರಹೋಗು->ದತ್ತಾಂಶ[i1],
              (
                KRML_CLITERAL(core_ops_range_Range_87){
                  .ಆರಂಭ = sampled_coefficients->ದತ್ತಾಂಶ[i1],
                  .ಕೊನೆ = sampled_coefficients->ದತ್ತಾಂಶ[i1] + (ಗಾತ್ರ_t)16U
                }
              )));
        ಗಾತ್ರ_t uu____0 = i1;
        sampled_coefficients->ದತ್ತಾಂಶ[uu____0] += sampled;
      }
    }
  }
  bool ಮುಗಿದ = true;
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)3U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    ಆದರೆ (sampled_coefficients->ದತ್ತಾಂಶ[i0] >= LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_ಒಳ_RING_ELEMENT)
    {
      sampled_coefficients->ದತ್ತಾಂಶ[i0] = LIBCRUX_ML_KEM_CONSTANTS_COEFFICIENTS_ಒಳ_RING_ELEMENT;
    }
    ಇಲ್ಲದಿದ್ದರೆ
    {
      ಮುಗಿದ = false;
    }
  }
  ಹಿಂತಿರುಗಿ ಮುಗಿದ;
}

/**
A monomorphic instance of libcrux_ml_kem.polynomial.from_i16_array
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_polynomial_from_i16_array_ea(Eurydice_borrow_ತುಂಡು_i16 a)
{
  Eurydice_arr_9e ಫಲಿತಾಂಶ = libcrux_ml_kem_polynomial_ZERO_ea();
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_ಒಳ_RING_ELEMENT; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    Eurydice_arr_d6
    uu____0 =
      libcrux_ml_kem_ಸದಿಶ_portable_from_i16_array_b8(Eurydice_ತುಂಡು_subslice_shared_a6(a,
          (
            KRML_CLITERAL(core_ops_range_Range_87){
              .ಆರಂಭ = i0 * (ಗಾತ್ರ_t)16U,
              .ಕೊನೆ = (i0 + (ಗಾತ್ರ_t)1U) * (ಗಾತ್ರ_t)16U
            }
          )));
    ಫಲಿತಾಂಶ.ದತ್ತಾಂಶ[i0] = uu____0;
  }
  ಹಿಂತಿರುಗಿ ಫಲಿತಾಂಶ;
}

/**
This function found in impl {libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.polynomial.from_i16_array_d6
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_polynomial_from_i16_array_d6_ea(Eurydice_borrow_ತುಂಡು_i16 a)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_polynomial_from_i16_array_ea(a);
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_9e
libcrux_ml_kem_sampling_sample_from_xof_call_mut_0a_91(ಶೂನ್ಯ **_, Eurydice_arr_5b tupled_ವಾದಗಳು)
{
  Eurydice_arr_5b s = tupled_ವಾದಗಳು;
  ಹಿಂತಿರುಗಿ
    libcrux_ml_kem_polynomial_from_i16_array_d6_ea(Eurydice_array_ಗಮ್ಯ_subslice_shared_e70(&s,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = (ಗಾತ್ರ_t)0U, .ಕೊನೆ = (ಗಾತ್ರ_t)256U })));
}

/**
A monomorphic instance of libcrux_ml_kem.sampling.sample_from_xof
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
*/
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_bb0
libcrux_ml_kem_sampling_sample_from_xof_91(ಸ್ಥಿರಾಂಕ Eurydice_arr_810 *seeds)
{
  Eurydice_arr_eb sampled_coefficients = { .ದತ್ತಾಂಶ = { 0U } };
  Eurydice_arr_b1
  ಹೊರಹೋಗು = { .ದತ್ತಾಂಶ = { { .ದತ್ತಾಂಶ = { 0U } }, { .ದತ್ತಾಂಶ = { 0U } }, { .ದತ್ತಾಂಶ = { 0U } } } };
  Eurydice_arr_1b0
  xof_state = libcrux_ml_kem_hash_functions_portable_shake128_init_absorb_final_4a_78(seeds);
  Eurydice_arr_7e
  randomness0 =
    libcrux_ml_kem_hash_functions_portable_shake128_squeeze_ಮೊದಲ_three_ಖಂಡಗಳು_4a_78(&xof_state);
  bool
  ಮುಗಿದ =
    libcrux_ml_kem_sampling_sample_from_ಏಕರೂಪ_distribution_ಮುಂದಿನ_b6(&randomness0,
      &sampled_coefficients,
      &ಹೊರಹೋಗು);
  ಆಗ (true)
  {
    ಆದರೆ (ಮುಗಿದ)
    {
      ನಿಲ್ಲಿಸು;
    }
    ಇಲ್ಲದಿದ್ದರೆ
    {
      Eurydice_arr_2c
      randomness =
        libcrux_ml_kem_hash_functions_portable_shake128_squeeze_ಮುಂದಿನ_ಖಂಡ_4a_78(&xof_state);
      ಮುಗಿದ =
        libcrux_ml_kem_sampling_sample_from_ಏಕರೂಪ_distribution_ಮುಂದಿನ_b60(&randomness,
          &sampled_coefficients,
          &ಹೊರಹೋಗು);
    }
  }
  Eurydice_arr_bb0 arr_mapped_str;
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    ಶೂನ್ಯ *lvalue = (ಶೂನ್ಯ *)0U;
    arr_mapped_str.ದತ್ತಾಂಶ[i] =
      libcrux_ml_kem_sampling_sample_from_xof_call_mut_0a_91(&lvalue,
        ಹೊರಹೋಗು.ದತ್ತಾಂಶ[i]);
  }
  ಹಿಂತಿರುಗಿ arr_mapped_str;
}

/**
A monomorphic instance of libcrux_ml_kem.matrix.sample_matrix_A
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_kem_ಮಾತೃಕೆ_sample_ಮಾತೃಕೆ_A_91(
  Eurydice_arr_c10 *A_transpose,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_31 *ಬೀಜ,
  bool transpose
)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i0 = (ಗಾತ್ರ_t)0U; i0 < (ಗಾತ್ರ_t)3U; i0++)
  {
    ಗಾತ್ರ_t i1 = i0;
    Eurydice_arr_810 seeds;
    Eurydice_arr_31 repeat_ಅಭಿವ್ಯಕ್ತಿ[3U];
    ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)3U; i++)
    {
      repeat_ಅಭಿವ್ಯಕ್ತಿ[i] =
        core_array__core__clone__Clone_for__T__N___clone((ಗಾತ್ರ_t)34U,
          ಬೀಜ,
          uint8_t,
          Eurydice_arr_31);
    }
    ಸ್ಮರಣೆ_ನಕಲು(seeds.ದತ್ತಾಂಶ, repeat_ಅಭಿವ್ಯಕ್ತಿ, (ಗಾತ್ರ_t)3U * ಗಾತ್ರ (Eurydice_arr_31));
    ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)3U; i++)
    {
      ಗಾತ್ರ_t j = i;
      seeds.ದತ್ತಾಂಶ[j].ದತ್ತಾಂಶ[32U] = (uint8_t)i1;
      seeds.ದತ್ತಾಂಶ[j].ದತ್ತಾಂಶ[33U] = (uint8_t)j;
    }
    Eurydice_arr_bb0 sampled = libcrux_ml_kem_sampling_sample_from_xof_91(&seeds);
    ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)3U; i++)
    {
      ಗಾತ್ರ_t j = i;
      Eurydice_arr_9e sample = sampled.ದತ್ತಾಂಶ[j];
      ಆದರೆ (transpose)
      {
        A_transpose->ದತ್ತಾಂಶ[j].ದತ್ತಾಂಶ[i1] = sample;
      }
      ಇಲ್ಲದಿದ್ದರೆ
      {
        A_transpose->ದತ್ತಾಂಶ[i1].ದತ್ತಾಂಶ[j] = sample;
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_kem_ind_cpa_build_unpacked_ಬಹಿರಂಗ_ಕೀಲಿ_mut_05(
  Eurydice_borrow_ತುಂಡು_u8 ಬಹಿರಂಗ_ಕೀಲಿ,
  libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_ಬಹಿರಂಗ_ಕೀಲಿ_Unpacked_51 *unpacked_ಬಹಿರಂಗ_ಕೀಲಿ
)
{
  libcrux_ml_kem_serialize_deserialize_ring_elements_reduced_68(Eurydice_ತುಂಡು_subslice_ಗಮ್ಯ_shared_72(ಬಹಿರಂಗ_ಕೀಲಿ,
      (ಗಾತ್ರ_t)1152U),
    &unpacked_ಬಹಿರಂಗ_ಕೀಲಿ->t_as_ntt);
  Eurydice_borrow_ತುಂಡು_u8
  ಬೀಜ = Eurydice_ತುಂಡು_subslice_from_shared_6d(ಬಹಿರಂಗ_ಕೀಲಿ, (ಗಾತ್ರ_t)1152U);
  Eurydice_arr_c10 *uu____0 = &unpacked_ಬಹಿರಂಗ_ಕೀಲಿ->A;
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_31 lvalue = libcrux_ml_kem_utils_into_padded_array_de(ಬೀಜ);
  libcrux_ml_kem_ಮಾತೃಕೆ_sample_ಮಾತೃಕೆ_A_91(uu____0, &lvalue, false);
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.build_unpacked_public_key
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector, libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- T_AS_NTT_ENCODED_SIZE= 1152
*/
ಸ್ಥಿರ KRML_MUSTINLINE libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_ಬಹಿರಂಗ_ಕೀಲಿ_Unpacked_51
libcrux_ml_kem_ind_cpa_build_unpacked_ಬಹಿರಂಗ_ಕೀಲಿ_05(Eurydice_borrow_ತುಂಡು_u8 ಬಹಿರಂಗ_ಕೀಲಿ)
{
  libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_ಬಹಿರಂಗ_ಕೀಲಿ_Unpacked_51
  unpacked_ಬಹಿರಂಗ_ಕೀಲಿ = libcrux_ml_kem_ind_cpa_unpacked_default_8b_68();
  libcrux_ml_kem_ind_cpa_build_unpacked_ಬಹಿರಂಗ_ಕೀಲಿ_mut_05(ಬಹಿರಂಗ_ಕೀಲಿ, &unpacked_ಬಹಿರಂಗ_ಕೀಲಿ);
  ಹಿಂತಿರುಗಿ unpacked_ಬಹಿರಂಗ_ಕೀಲಿ;
}

/**
A monomorphic instance of n-tuple
with types Eurydice_arr_bb0, libcrux_ml_kem_polynomial_PolynomialRingElement_1d

*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ tuple_c6_s
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_9e
libcrux_ml_kem_ind_cpa_encrypt_c1_call_mut_f1_87(ಶೂನ್ಯ **_, ಗಾತ್ರ_t tupled_ವಾದಗಳು)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_polynomial_ZERO_d6_ea();
}

/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.PRFxN
with const generics
- K= 3
- LEN= 128
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_58
libcrux_ml_kem_hash_functions_portable_PRFxN_3b(ಸ್ಥಿರಾಂಕ Eurydice_arr_fd *ಒಳಹರಿವು)
{
  Eurydice_arr_58
  ಹೊರಹೋಗು = { .ದತ್ತಾಂಶ = { { .ದತ್ತಾಂಶ = { 0U } }, { .ದತ್ತಾಂಶ = { 0U } }, { .ದತ್ತಾಂಶ = { 0U } } } };
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)3U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    libcrux_sha3_portable_shake256(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_78(&ಹೊರಹೋಗು.ದತ್ತಾಂಶ[i0]),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_b5(&ಒಳಹರಿವು->ದತ್ತಾಂಶ[i0]));
  }
  ಹಿಂತಿರುಗಿ ಹೊರಹೋಗು;
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_58
libcrux_ml_kem_hash_functions_portable_PRFxN_4a_3b(ಸ್ಥಿರಾಂಕ Eurydice_arr_fd *ಒಳಹರಿವು)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_hash_functions_portable_PRFxN_3b(ಒಳಹರಿವು);
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
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_sampling_sample_from_ದ್ವಿಪದ_distribution_2_ea(
  Eurydice_borrow_ತುಂಡು_u8 randomness
)
{
  Eurydice_arr_04 sampled_i16s = { .ದತ್ತಾಂಶ = { 0U } };
  ಗಾಗಿ (ಗಾತ್ರ_t i0 = (ಗಾತ್ರ_t)0U; i0 < randomness.meta / (ಗಾತ್ರ_t)4U; i0++)
  {
    ಗಾತ್ರ_t chunk_ಸಂಖ್ಯೆ = i0;
    Eurydice_borrow_ತುಂಡು_u8
    byte_chunk =
      Eurydice_ತುಂಡು_subslice_shared_c8(randomness,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ಆರಂಭ = chunk_ಸಂಖ್ಯೆ * (ಗಾತ್ರ_t)4U,
            .ಕೊನೆ = chunk_ಸಂಖ್ಯೆ * (ಗಾತ್ರ_t)4U + (ಗಾತ್ರ_t)4U
          }
        ));
    uint32_t
    random_ಬಿಟ್ಟುಗಳು_as_u32 =
      (((uint32_t)byte_chunk.ptr[0U] | (uint32_t)byte_chunk.ptr[1U] << 8U) |
        (uint32_t)byte_chunk.ptr[2U] << 16U)
      | (uint32_t)byte_chunk.ptr[3U] << 24U;
    uint32_t even_ಬಿಟ್ಟುಗಳು = random_ಬಿಟ್ಟುಗಳು_as_u32 & 1431655765U;
    uint32_t odd_ಬಿಟ್ಟುಗಳು = random_ಬಿಟ್ಟುಗಳು_as_u32 >> 1U & 1431655765U;
    uint32_t coin_toss_outcomes = even_ಬಿಟ್ಟುಗಳು + odd_ಬಿಟ್ಟುಗಳು;
    ಗಾಗಿ (uint32_t i = 0U; i < 32U / 4U; i++)
    {
      uint32_t outcome_ಗಣ = i;
      uint32_t outcome_set0 = outcome_ಗಣ * 4U;
      int16_t outcome_1 = (int16_t)(coin_toss_outcomes >> (uint32_t)outcome_set0 & 3U);
      int16_t outcome_2 = (int16_t)(coin_toss_outcomes >> (uint32_t)(outcome_set0 + 2U) & 3U);
      ಗಾತ್ರ_t ಸ್ಥಾನಾಂತರ = (ಗಾತ್ರ_t)(outcome_set0 >> 2U);
      sampled_i16s.ದತ್ತಾಂಶ[(ಗಾತ್ರ_t)8U * chunk_ಸಂಖ್ಯೆ + ಸ್ಥಾನಾಂತರ] = outcome_1 - outcome_2;
    }
  }
  ಹಿಂತಿರುಗಿ
    libcrux_ml_kem_polynomial_from_i16_array_d6_ea(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_99(&sampled_i16s));
}

/**
A monomorphic instance of libcrux_ml_kem.sampling.sample_from_binomial_distribution
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- ETA= 2
*/
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_sampling_sample_from_ದ್ವಿಪದ_distribution_66(
  Eurydice_borrow_ತುಂಡು_u8 randomness
)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_sampling_sample_from_ದ್ವಿಪದ_distribution_2_ea(randomness);
}

/**
A monomorphic instance of libcrux_ml_kem.ntt.ntt_at_layer_7
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ libcrux_ml_kem_ntt_ntt_at_layer_7_ea(Eurydice_arr_9e *re)
{
  ಗಾತ್ರ_t ಹೆಜ್ಜೆ = LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_ಒಳ_RING_ELEMENT / (ಗಾತ್ರ_t)2U;
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < ಹೆಜ್ಜೆ; i++)
  {
    ಗಾತ್ರ_t j = i;
    Eurydice_arr_d6
    t = libcrux_ml_kem_ಸದಿಶ_portable_multiply_by_constant_b8(re->ದತ್ತಾಂಶ[j + ಹೆಜ್ಜೆ], -1600);
    re->ದತ್ತಾಂಶ[j + ಹೆಜ್ಜೆ] = libcrux_ml_kem_ಸದಿಶ_portable_sub_b8(re->ದತ್ತಾಂಶ[j], &t);
    Eurydice_arr_d6 uu____1 = libcrux_ml_kem_ಸದಿಶ_portable_ಕೂಡಿಸು_b8(re->ದತ್ತಾಂಶ[j], &t);
    re->ದತ್ತಾಂಶ[j] = uu____1;
  }
}

/**
A monomorphic instance of libcrux_ml_kem.ntt.ntt_binomially_sampled_ring_element
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_kem_ntt_ntt_binomially_sampled_ring_element_ea(Eurydice_arr_9e *re)
{
  libcrux_ml_kem_ntt_ntt_at_layer_7_ea(re);
  ಗಾತ್ರ_t zeta_i = (ಗಾತ್ರ_t)1U;
  libcrux_ml_kem_ntt_ntt_at_layer_4_plus_ea(&zeta_i, re, (ಗಾತ್ರ_t)6U, (ಗಾತ್ರ_t)11207U);
  libcrux_ml_kem_ntt_ntt_at_layer_4_plus_ea(&zeta_i,
    re,
    (ಗಾತ್ರ_t)5U,
    (ಗಾತ್ರ_t)11207U + (ಗಾತ್ರ_t)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_4_plus_ea(&zeta_i,
    re,
    (ಗಾತ್ರ_t)4U,
    (ಗಾತ್ರ_t)11207U + (ಗಾತ್ರ_t)2U * (ಗಾತ್ರ_t)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_3_ea(&zeta_i, re, (ಗಾತ್ರ_t)11207U + (ಗಾತ್ರ_t)3U * (ಗಾತ್ರ_t)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_2_ea(&zeta_i, re, (ಗಾತ್ರ_t)11207U + (ಗಾತ್ರ_t)4U * (ಗಾತ್ರ_t)3328U);
  libcrux_ml_kem_ntt_ntt_at_layer_1_ea(&zeta_i, re, (ಗಾತ್ರ_t)11207U + (ಗಾತ್ರ_t)5U * (ಗಾತ್ರ_t)3328U);
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
ಸ್ಥಿರ KRML_MUSTINLINE uint8_t
libcrux_ml_kem_ind_cpa_sample_ಸದಿಶ_cbd_then_ntt_bf(
  Eurydice_arr_bb0 *re_as_ntt,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_fa0 *prf_ಒಳಹರಿವು,
  uint8_t domain_separator
)
{
  Eurydice_arr_fd prf_inputs;
  Eurydice_arr_fa0 repeat_ಅಭಿವ್ಯಕ್ತಿ[3U];
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)3U; i++)
  {
    repeat_ಅಭಿವ್ಯಕ್ತಿ[i] =
      core_array__core__clone__Clone_for__T__N___clone((ಗಾತ್ರ_t)33U,
        prf_ಒಳಹರಿವು,
        uint8_t,
        Eurydice_arr_fa0);
  }
  ಸ್ಮರಣೆ_ನಕಲು(prf_inputs.ದತ್ತಾಂಶ, repeat_ಅಭಿವ್ಯಕ್ತಿ, (ಗಾತ್ರ_t)3U * ಗಾತ್ರ (Eurydice_arr_fa0));
  domain_separator = libcrux_ml_kem_utils_prf_ಒಳಹರಿವು_inc_78(&prf_inputs, domain_separator);
  Eurydice_arr_58 prf_outputs = libcrux_ml_kem_hash_functions_portable_PRFxN_4a_3b(&prf_inputs);
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)3U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    Eurydice_arr_9e
    uu____0 =
      libcrux_ml_kem_sampling_sample_from_ದ್ವಿಪದ_distribution_66(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_78(&prf_outputs.ದತ್ತಾಂಶ[i0]));
    re_as_ntt->ದತ್ತಾಂಶ[i0] = uu____0;
    libcrux_ml_kem_ntt_ntt_binomially_sampled_ring_element_ea(&re_as_ntt->ದತ್ತಾಂಶ[i0]);
  }
  ಹಿಂತಿರುಗಿ domain_separator;
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_9e
libcrux_ml_kem_ind_cpa_encrypt_c1_call_mut_dd_87(ಶೂನ್ಯ **_, ಗಾತ್ರ_t tupled_ವಾದಗಳು)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_polynomial_ZERO_d6_ea();
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
ಸ್ಥಿರ KRML_MUSTINLINE uint8_t
libcrux_ml_kem_ind_cpa_sample_ring_element_cbd_bf(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_fa0 *prf_ಒಳಹರಿವು,
  uint8_t domain_separator,
  Eurydice_arr_bb0 *error_1
)
{
  Eurydice_arr_fd prf_inputs;
  Eurydice_arr_fa0 repeat_ಅಭಿವ್ಯಕ್ತಿ[3U];
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)3U; i++)
  {
    repeat_ಅಭಿವ್ಯಕ್ತಿ[i] =
      core_array__core__clone__Clone_for__T__N___clone((ಗಾತ್ರ_t)33U,
        prf_ಒಳಹರಿವು,
        uint8_t,
        Eurydice_arr_fa0);
  }
  ಸ್ಮರಣೆ_ನಕಲು(prf_inputs.ದತ್ತಾಂಶ, repeat_ಅಭಿವ್ಯಕ್ತಿ, (ಗಾತ್ರ_t)3U * ಗಾತ್ರ (Eurydice_arr_fa0));
  domain_separator = libcrux_ml_kem_utils_prf_ಒಳಹರಿವು_inc_78(&prf_inputs, domain_separator);
  Eurydice_arr_58 prf_outputs = libcrux_ml_kem_hash_functions_portable_PRFxN_4a_3b(&prf_inputs);
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)3U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    Eurydice_arr_9e
    uu____0 =
      libcrux_ml_kem_sampling_sample_from_ದ್ವಿಪದ_distribution_66(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_78(&prf_outputs.ದತ್ತಾಂಶ[i0]));
    error_1->ದತ್ತಾಂಶ[i0] = uu____0;
  }
  ಹಿಂತಿರುಗಿ domain_separator;
}

/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.PRF
with const generics
- LEN= 128
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_89
libcrux_ml_kem_hash_functions_portable_PRF_ec(Eurydice_borrow_ತುಂಡು_u8 ಒಳಹರಿವು)
{
  Eurydice_arr_89 digest = { .ದತ್ತಾಂಶ = { 0U } };
  libcrux_sha3_portable_shake256(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_78(&digest), ಒಳಹರಿವು);
  ಹಿಂತಿರುಗಿ digest;
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_89
libcrux_ml_kem_hash_functions_portable_PRF_4a_3b0(Eurydice_borrow_ತುಂಡು_u8 ಒಳಹರಿವು)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_hash_functions_portable_PRF_ec(ಒಳಹರಿವು);
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_9e
libcrux_ml_kem_ಮಾತೃಕೆ_compute_ಸದಿಶ_u_call_mut_a8_68(ಶೂನ್ಯ **_, ಗಾತ್ರ_t tupled_ವಾದಗಳು)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_polynomial_ZERO_d6_ea();
}

/**
A monomorphic instance of libcrux_ml_kem.polynomial.add_error_reduce
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_kem_polynomial_ಕೂಡಿಸು_error_reduce_ea(
  Eurydice_arr_9e *myself,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_9e *error
)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_ಒಳ_RING_ELEMENT; i++)
  {
    ಗಾತ್ರ_t j = i;
    Eurydice_arr_d6
    coefficient_ಸಾಮಾನ್ಯ_form =
      libcrux_ml_kem_ಸದಿಶ_portable_montgomery_multiply_by_constant_b8(myself->ದತ್ತಾಂಶ[j],
        1441);
    Eurydice_arr_d6
    ಮೊತ್ತ = libcrux_ml_kem_ಸದಿಶ_portable_ಕೂಡಿಸು_b8(coefficient_ಸಾಮಾನ್ಯ_form, &error->ದತ್ತಾಂಶ[j]);
    Eurydice_arr_d6 red = libcrux_ml_kem_ಸದಿಶ_portable_barrett_reduce_b8(ಮೊತ್ತ);
    myself->ದತ್ತಾಂಶ[j] = red;
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_kem_polynomial_ಕೂಡಿಸು_error_reduce_d6_ea(
  Eurydice_arr_9e *self,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_9e *error
)
{
  libcrux_ml_kem_polynomial_ಕೂಡಿಸು_error_reduce_ea(self, error);
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
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_bb0
libcrux_ml_kem_ಮಾತೃಕೆ_compute_ಸದಿಶ_u_68(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_c10 *a_as_ntt,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_bb0 *r_as_ntt,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_bb0 *error_1
)
{
  Eurydice_arr_bb0 arr_struct;
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    ಶೂನ್ಯ *lvalue = (ಶೂನ್ಯ *)0U;
    arr_struct.ದತ್ತಾಂಶ[i] = libcrux_ml_kem_ಮಾತೃಕೆ_compute_ಸದಿಶ_u_call_mut_a8_68(&lvalue, i);
  }
  Eurydice_arr_bb0 ಫಲಿತಾಂಶ = arr_struct;
  ಗಾಗಿ (ಗಾತ್ರ_t i0 = (ಗಾತ್ರ_t)0U; i0 < (ಗಾತ್ರ_t)3U; i0++)
  {
    ಗಾತ್ರ_t i1 = i0;
    ಸ್ಥಿರಾಂಕ Eurydice_arr_bb0 *ಅಡ್ಡಸಾಲು = &a_as_ntt->ದತ್ತಾಂಶ[i1];
    ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)3U; i++)
    {
      ಗಾತ್ರ_t j = i;
      ಸ್ಥಿರಾಂಕ Eurydice_arr_9e *a_element = &ಅಡ್ಡಸಾಲು->ದತ್ತಾಂಶ[j];
      Eurydice_arr_9e
      ಗುಣಲಬ್ಧ = libcrux_ml_kem_polynomial_ntt_multiply_d6_ea(a_element, &r_as_ntt->ದತ್ತಾಂಶ[j]);
      libcrux_ml_kem_polynomial_ಕೂಡಿಸು_ಗಮ್ಯ_ring_element_d6_68(&ಫಲಿತಾಂಶ.ದತ್ತಾಂಶ[i1], &ಗುಣಲಬ್ಧ);
    }
    libcrux_ml_kem_invert_ntt_invert_ntt_montgomery_68(&ಫಲಿತಾಂಶ.ದತ್ತಾಂಶ[i1]);
    libcrux_ml_kem_polynomial_ಕೂಡಿಸು_error_reduce_d6_ea(&ಫಲಿತಾಂಶ.ದತ್ತಾಂಶ[i1], &error_1->ದತ್ತಾಂಶ[i1]);
  }
  ಹಿಂತಿರುಗಿ ಫಲಿತಾಂಶ;
}

/**
A monomorphic instance of libcrux_ml_kem.vector.portable.compress.compress
with const generics
- COEFFICIENT_BITS= 10
*/
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_compress_compress_ef(Eurydice_arr_d6 a)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < LIBCRUX_ML_KEM_ಸದಿಶ_TRAITS_ಕ್ಷೇತ್ರ_ELEMENTS_ಒಳ_ಸದಿಶ; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    int16_t
    uu____0 =
      libcrux_secrets_int_as_i16_f5(libcrux_ml_kem_ಸದಿಶ_portable_compress_compress_ciphertext_coefficient((uint8_t)10,
          libcrux_secrets_int_as_u16_f5(a.ದತ್ತಾಂಶ[i0])));
    a.ದತ್ತಾಂಶ[i0] = uu____0;
  }
  ಹಿಂತಿರುಗಿ a;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
/**
A monomorphic instance of libcrux_ml_kem.vector.portable.compress_b8
with const generics
- COEFFICIENT_BITS= 10
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_d6 libcrux_ml_kem_ಸದಿಶ_portable_compress_b8_ef(Eurydice_arr_d6 a)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ಸದಿಶ_portable_compress_compress_ef(a);
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.compress_then_serialize_10
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- OUT_LEN= 320
*/
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_b0
libcrux_ml_kem_serialize_compress_then_serialize_10_e1(ಸ್ಥಿರಾಂಕ Eurydice_arr_9e *re)
{
  Eurydice_arr_b0 serialized = { .ದತ್ತಾಂಶ = { 0U } };
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_ಒಳ_RING_ELEMENT; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    Eurydice_arr_d6
    coefficient =
      libcrux_ml_kem_ಸದಿಶ_portable_compress_b8_ef(libcrux_ml_kem_serialize_ಗಮ್ಯ_unsigned_ಕ್ಷೇತ್ರ_modulus_ea(re->ದತ್ತಾಂಶ[i0]));
    Eurydice_arr_fc ಬೈಟುಗಳು = libcrux_ml_kem_ಸದಿಶ_portable_serialize_10_b8(coefficient);
    Eurydice_ತುಂಡು_copy(Eurydice_array_ಗಮ್ಯ_subslice_mut_d413(&serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ಆರಂಭ = (ಗಾತ್ರ_t)20U * i0,
            .ಕೊನೆ = (ಗಾತ್ರ_t)20U * i0 + (ಗಾತ್ರ_t)20U
          }
        )),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_8f(&ಬೈಟುಗಳು),
      uint8_t);
  }
  ಹಿಂತಿರುಗಿ serialized;
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.compress_then_serialize_ring_element_u
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- COMPRESSION_FACTOR= 10
- OUT_LEN= 320
*/
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_b0
libcrux_ml_kem_serialize_compress_then_serialize_ring_element_u_f7(ಸ್ಥಿರಾಂಕ Eurydice_arr_9e *re)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_serialize_compress_then_serialize_10_e1(re);
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_kem_ind_cpa_compress_then_serialize_u_21(
  Eurydice_arr_bb0 ಒಳಹರಿವು,
  Eurydice_mut_borrow_ತುಂಡು_u8 ಹೊರಹೋಗು
)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)3U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    Eurydice_arr_9e re = ಒಳಹರಿವು.ದತ್ತಾಂಶ[i0];
    Eurydice_mut_borrow_ತುಂಡು_u8
    uu____0 =
      Eurydice_ತುಂಡು_subslice_mut_c8(ಹೊರಹೋಗು,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ಆರಂಭ = i0 * ((ಗಾತ್ರ_t)960U / (ಗಾತ್ರ_t)3U),
            .ಕೊನೆ = (i0 + (ಗಾತ್ರ_t)1U) * ((ಗಾತ್ರ_t)960U / (ಗಾತ್ರ_t)3U)
          }
        ));
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_b0
    lvalue = libcrux_ml_kem_serialize_compress_then_serialize_ring_element_u_f7(&re);
    Eurydice_ತುಂಡು_copy(uu____0, Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_56(&lvalue), uint8_t);
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
ಸ್ಥಿರ KRML_MUSTINLINE tuple_c6
libcrux_ml_kem_ind_cpa_encrypt_c1_87(
  Eurydice_borrow_ತುಂಡು_u8 randomness,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_c10 *ಮಾತೃಕೆ,
  Eurydice_mut_borrow_ತುಂಡು_u8 ciphertext
)
{
  Eurydice_arr_fa0 prf_ಒಳಹರಿವು = libcrux_ml_kem_utils_into_padded_array_29(randomness);
  Eurydice_arr_bb0 arr_struct0;
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    ಶೂನ್ಯ *lvalue = (ಶೂನ್ಯ *)0U;
    arr_struct0.ದತ್ತಾಂಶ[i] = libcrux_ml_kem_ind_cpa_encrypt_c1_call_mut_f1_87(&lvalue, i);
  }
  Eurydice_arr_bb0 r_as_ntt = arr_struct0;
  uint8_t
  domain_separator0 =
    libcrux_ml_kem_ind_cpa_sample_ಸದಿಶ_cbd_then_ntt_bf(&r_as_ntt,
      &prf_ಒಳಹರಿವು,
      0U);
  Eurydice_arr_bb0 arr_struct;
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    ಶೂನ್ಯ *lvalue = (ಶೂನ್ಯ *)0U;
    arr_struct.ದತ್ತಾಂಶ[i] = libcrux_ml_kem_ind_cpa_encrypt_c1_call_mut_dd_87(&lvalue, i);
  }
  Eurydice_arr_bb0 error_1 = arr_struct;
  uint8_t
  domain_separator =
    libcrux_ml_kem_ind_cpa_sample_ring_element_cbd_bf(&prf_ಒಳಹರಿವು,
      domain_separator0,
      &error_1);
  prf_ಒಳಹರಿವು.ದತ್ತಾಂಶ[32U] = domain_separator;
  Eurydice_arr_89
  prf_output =
    libcrux_ml_kem_hash_functions_portable_PRF_4a_3b0(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_b5(&prf_ಒಳಹರಿವು));
  Eurydice_arr_9e
  error_2 =
    libcrux_ml_kem_sampling_sample_from_ದ್ವಿಪದ_distribution_66(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_78(&prf_output));
  Eurydice_arr_bb0 u = libcrux_ml_kem_ಮಾತೃಕೆ_compute_ಸದಿಶ_u_68(ಮಾತೃಕೆ, &r_as_ntt, &error_1);
  libcrux_ml_kem_ind_cpa_compress_then_serialize_u_21(u, ciphertext);
  ಹಿಂತಿರುಗಿ (KRML_CLITERAL(tuple_c6){ .fst = r_as_ntt, .snd = error_2 });
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.deserialize_then_decompress_message
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_serialize_deserialize_then_decompress_ಸಂದೇಶ_ea(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_ec *serialized
)
{
  Eurydice_arr_9e re = libcrux_ml_kem_polynomial_ZERO_d6_ea();
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)16U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    Eurydice_arr_d6
    coefficient_compressed =
      libcrux_ml_kem_ಸದಿಶ_portable_deserialize_1_b8(Eurydice_array_ಗಮ್ಯ_subslice_shared_d4(serialized,
          (
            KRML_CLITERAL(core_ops_range_Range_87){
              .ಆರಂಭ = (ಗಾತ್ರ_t)2U * i0,
              .ಕೊನೆ = (ಗಾತ್ರ_t)2U * i0 + (ಗಾತ್ರ_t)2U
            }
          )));
    Eurydice_arr_d6
    uu____0 = libcrux_ml_kem_ಸದಿಶ_portable_decompress_1_b8(coefficient_compressed);
    re.ದತ್ತಾಂಶ[i0] = uu____0;
  }
  ಹಿಂತಿರುಗಿ re;
}

/**
A monomorphic instance of libcrux_ml_kem.polynomial.add_message_error_reduce
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_polynomial_ಕೂಡಿಸು_ಸಂದೇಶ_error_reduce_ea(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_9e *myself,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_9e *ಸಂದೇಶ_2,
  Eurydice_arr_9e ಫಲಿತಾಂಶ
)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_ಒಳ_RING_ELEMENT; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    Eurydice_arr_d6
    coefficient_ಸಾಮಾನ್ಯ_form =
      libcrux_ml_kem_ಸದಿಶ_portable_montgomery_multiply_by_constant_b8(ಫಲಿತಾಂಶ.ದತ್ತಾಂಶ[i0],
        1441);
    Eurydice_arr_d6
    sum1 = libcrux_ml_kem_ಸದಿಶ_portable_ಕೂಡಿಸು_b8(myself->ದತ್ತಾಂಶ[i0], &ಸಂದೇಶ_2->ದತ್ತಾಂಶ[i0]);
    Eurydice_arr_d6 sum2 = libcrux_ml_kem_ಸದಿಶ_portable_ಕೂಡಿಸು_b8(coefficient_ಸಾಮಾನ್ಯ_form, &sum1);
    Eurydice_arr_d6 red = libcrux_ml_kem_ಸದಿಶ_portable_barrett_reduce_b8(sum2);
    ಫಲಿತಾಂಶ.ದತ್ತಾಂಶ[i0] = red;
  }
  ಹಿಂತಿರುಗಿ ಫಲಿತಾಂಶ;
}

/**
This function found in impl {libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@1]}
*/
/**
A monomorphic instance of libcrux_ml_kem.polynomial.add_message_error_reduce_d6
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_polynomial_ಕೂಡಿಸು_ಸಂದೇಶ_error_reduce_d6_ea(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_9e *self,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_9e *ಸಂದೇಶ_2,
  Eurydice_arr_9e ಫಲಿತಾಂಶ
)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_polynomial_ಕೂಡಿಸು_ಸಂದೇಶ_error_reduce_ea(self, ಸಂದೇಶ_2, ಫಲಿತಾಂಶ);
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
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_9e
libcrux_ml_kem_ಮಾತೃಕೆ_compute_ring_element_v_68(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_bb0 *t_as_ntt,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_bb0 *r_as_ntt,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_9e *error_2,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_9e *ಸಂದೇಶ_2
)
{
  Eurydice_arr_9e ಫಲಿತಾಂಶ = libcrux_ml_kem_polynomial_ZERO_d6_ea();
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)3U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    Eurydice_arr_9e
    ಗುಣಲಬ್ಧ =
      libcrux_ml_kem_polynomial_ntt_multiply_d6_ea(&t_as_ntt->ದತ್ತಾಂಶ[i0],
        &r_as_ntt->ದತ್ತಾಂಶ[i0]);
    libcrux_ml_kem_polynomial_ಕೂಡಿಸು_ಗಮ್ಯ_ring_element_d6_68(&ಫಲಿತಾಂಶ, &ಗುಣಲಬ್ಧ);
  }
  libcrux_ml_kem_invert_ntt_invert_ntt_montgomery_68(&ಫಲಿತಾಂಶ);
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_polynomial_ಕೂಡಿಸು_ಸಂದೇಶ_error_reduce_d6_ea(error_2, ಸಂದೇಶ_2, ಫಲಿತಾಂಶ);
}

/**
A monomorphic instance of libcrux_ml_kem.vector.portable.compress.compress
with const generics
- COEFFICIENT_BITS= 4
*/
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_ಸದಿಶ_portable_compress_compress_d1(Eurydice_arr_d6 a)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < LIBCRUX_ML_KEM_ಸದಿಶ_TRAITS_ಕ್ಷೇತ್ರ_ELEMENTS_ಒಳ_ಸದಿಶ; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    int16_t
    uu____0 =
      libcrux_secrets_int_as_i16_f5(libcrux_ml_kem_ಸದಿಶ_portable_compress_compress_ciphertext_coefficient((uint8_t)4,
          libcrux_secrets_int_as_u16_f5(a.ದತ್ತಾಂಶ[i0])));
    a.ದತ್ತಾಂಶ[i0] = uu____0;
  }
  ಹಿಂತಿರುಗಿ a;
}

/**
This function found in impl {libcrux_ml_kem::vector::traits::Operations for libcrux_ml_kem::vector::portable::vector_type::PortableVector}
*/
/**
A monomorphic instance of libcrux_ml_kem.vector.portable.compress_b8
with const generics
- COEFFICIENT_BITS= 4
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_d6 libcrux_ml_kem_ಸದಿಶ_portable_compress_b8_d1(Eurydice_arr_d6 a)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ಸದಿಶ_portable_compress_compress_d1(a);
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.compress_then_serialize_4
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_kem_serialize_compress_then_serialize_4_ea(
  Eurydice_arr_9e re,
  Eurydice_mut_borrow_ತುಂಡು_u8 serialized
)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_ಒಳ_RING_ELEMENT; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    Eurydice_arr_d6
    coefficient =
      libcrux_ml_kem_ಸದಿಶ_portable_compress_b8_d1(libcrux_ml_kem_serialize_ಗಮ್ಯ_unsigned_ಕ್ಷೇತ್ರ_modulus_ea(re.ದತ್ತಾಂಶ[i0]));
    Eurydice_array_u8x8 ಬೈಟುಗಳು = libcrux_ml_kem_ಸದಿಶ_portable_serialize_4_b8(coefficient);
    Eurydice_ತುಂಡು_copy(Eurydice_ತುಂಡು_subslice_mut_c8(serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ಆರಂಭ = (ಗಾತ್ರ_t)8U * i0,
            .ಕೊನೆ = (ಗಾತ್ರ_t)8U * i0 + (ಗಾತ್ರ_t)8U
          }
        )),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_6e(&ಬೈಟುಗಳು),
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_kem_serialize_compress_then_serialize_ring_element_v_30(
  Eurydice_arr_9e re,
  Eurydice_mut_borrow_ತುಂಡು_u8 ಹೊರಹೋಗು
)
{
  libcrux_ml_kem_serialize_compress_then_serialize_4_ea(re, ಹೊರಹೋಗು);
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cpa.encrypt_c2
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- K= 3
- V_COMPRESSION_FACTOR= 4
- C2_LEN= 128
*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_kem_ind_cpa_encrypt_c2_30(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_bb0 *t_as_ntt,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_bb0 *r_as_ntt,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_9e *error_2,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_ec *ಸಂದೇಶ_2,
  Eurydice_mut_borrow_ತುಂಡು_u8 ciphertext
)
{
  Eurydice_arr_9e
  ಸಂದೇಶ_as_ring_element =
    libcrux_ml_kem_serialize_deserialize_then_decompress_ಸಂದೇಶ_ea(ಸಂದೇಶ_2);
  Eurydice_arr_9e
  v =
    libcrux_ml_kem_ಮಾತೃಕೆ_compute_ring_element_v_68(t_as_ntt,
      r_as_ntt,
      error_2,
      &ಸಂದೇಶ_as_ring_element);
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
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_2b
libcrux_ml_kem_ind_cpa_encrypt_unpacked_d5(
  ಸ್ಥಿರಾಂಕ libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_ಬಹಿರಂಗ_ಕೀಲಿ_Unpacked_51 *ಬಹಿರಂಗ_ಕೀಲಿ,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_ec *ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 randomness
)
{
  Eurydice_arr_2b ciphertext = { .ದತ್ತಾಂಶ = { 0U } };
  tuple_c6
  uu____0 =
    libcrux_ml_kem_ind_cpa_encrypt_c1_87(randomness,
      &ಬಹಿರಂಗ_ಕೀಲಿ->A,
      Eurydice_array_ಗಮ್ಯ_subslice_mut_d414(&ciphertext,
        (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = (ಗಾತ್ರ_t)0U, .ಕೊನೆ = (ಗಾತ್ರ_t)960U })));
  Eurydice_arr_bb0 r_as_ntt = uu____0.fst;
  Eurydice_arr_9e error_2 = uu____0.snd;
  libcrux_ml_kem_ind_cpa_encrypt_c2_30(&ಬಹಿರಂಗ_ಕೀಲಿ->t_as_ntt,
    &r_as_ntt,
    &error_2,
    ಸಂದೇಶ_2,
    Eurydice_array_ಗಮ್ಯ_subslice_from_mut_5f3(&ciphertext, (ಗಾತ್ರ_t)960U));
  ಹಿಂತಿರುಗಿ ciphertext;
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
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_2b
libcrux_ml_kem_ind_cpa_encrypt_d5(
  Eurydice_borrow_ತುಂಡು_u8 ಬಹಿರಂಗ_ಕೀಲಿ,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_ec *ಸಂದೇಶ_2,
  Eurydice_borrow_ತುಂಡು_u8 randomness
)
{
  libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_ಬಹಿರಂಗ_ಕೀಲಿ_Unpacked_51
  unpacked_ಬಹಿರಂಗ_ಕೀಲಿ = libcrux_ml_kem_ind_cpa_build_unpacked_ಬಹಿರಂಗ_ಕೀಲಿ_05(ಬಹಿರಂಗ_ಕೀಲಿ);
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ind_cpa_encrypt_unpacked_d5(&unpacked_ಬಹಿರಂಗ_ಕೀಲಿ, ಸಂದೇಶ_2, randomness);
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
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_ec
libcrux_ml_kem_variant_kdf_39_52(
  Eurydice_borrow_ತುಂಡು_u8 shared_secret,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_2b *_
)
{
  Eurydice_arr_ec ಹೊರಹೋಗು = { .ದತ್ತಾಂಶ = { 0U } };
  Eurydice_ತುಂಡು_copy(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_01(&ಹೊರಹೋಗು), shared_secret, uint8_t);
  ಹಿಂತಿರುಗಿ ಹೊರಹೋಗು;
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
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_ec
libcrux_ml_kem_ind_cca_decapsulate_fd(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_7d *ಖಾಸಗಿ_ಕೀಲಿ,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_2b *ciphertext
)
{
  Eurydice_borrow_ತುಂಡು_u8_x4
  uu____0 =
    libcrux_ml_kem_types_unpack_ಖಾಸಗಿ_ಕೀಲಿ_64(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_51(ಖಾಸಗಿ_ಕೀಲಿ));
  Eurydice_borrow_ತುಂಡು_u8 ind_cpa_secret_ಕೀಲಿ = uu____0.fst;
  Eurydice_borrow_ತುಂಡು_u8 ind_cpa_ಬಹಿರಂಗ_ಕೀಲಿ = uu____0.snd;
  Eurydice_borrow_ತುಂಡು_u8 ind_cpa_ಬಹಿರಂಗ_ಕೀಲಿ_hash = uu____0.thd;
  Eurydice_borrow_ತುಂಡು_u8 implicit_rejection_ಮೌಲ್ಯ = uu____0.f3;
  Eurydice_arr_ec decrypted = libcrux_ml_kem_ind_cpa_decrypt_01(ind_cpa_secret_ಕೀಲಿ, ciphertext);
  Eurydice_arr_c7
  ಗಮ್ಯ_hash0 =
    libcrux_ml_kem_utils_into_padded_array_c9(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_01(&decrypted));
  Eurydice_ತುಂಡು_copy(Eurydice_array_ಗಮ್ಯ_subslice_from_mut_5f1(&ಗಮ್ಯ_hash0,
      LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_ಗಾತ್ರ),
    ind_cpa_ಬಹಿರಂಗ_ಕೀಲಿ_hash,
    uint8_t);
  Eurydice_arr_c7
  hashed =
    libcrux_ml_kem_hash_functions_portable_G_4a_78(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_17(&ಗಮ್ಯ_hash0));
  Eurydice_borrow_ತುಂಡು_u8_x2
  uu____1 =
    Eurydice_ತುಂಡು_ವಿಭಜಿಸು_at(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_17(&hashed),
      LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_ಗಾತ್ರ,
      uint8_t,
      Eurydice_borrow_ತುಂಡು_u8_x2);
  Eurydice_borrow_ತುಂಡು_u8 shared_secret0 = uu____1.fst;
  Eurydice_borrow_ತುಂಡು_u8 pseudorandomness = uu____1.snd;
  Eurydice_arr_af ಗಮ್ಯ_hash = libcrux_ml_kem_utils_into_padded_array_66(implicit_rejection_ಮೌಲ್ಯ);
  Eurydice_mut_borrow_ತುಂಡು_u8
  uu____2 =
    Eurydice_array_ಗಮ್ಯ_subslice_from_mut_5f2(&ಗಮ್ಯ_hash,
      LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_ಗಾತ್ರ);
  Eurydice_ತುಂಡು_copy(uu____2, libcrux_ml_kem_types_as_ref_c1_52(ciphertext), uint8_t);
  Eurydice_arr_ec
  implicit_rejection_shared_secret =
    libcrux_ml_kem_hash_functions_portable_PRF_4a_3b(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_81(&ಗಮ್ಯ_hash));
  Eurydice_arr_2b
  expected_ciphertext =
    libcrux_ml_kem_ind_cpa_encrypt_d5(ind_cpa_ಬಹಿರಂಗ_ಕೀಲಿ,
      &decrypted,
      pseudorandomness);
  Eurydice_borrow_ತುಂಡು_u8
  uu____3 = Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_01(&implicit_rejection_shared_secret);
  Eurydice_arr_ec
  implicit_rejection_shared_secret0 =
    libcrux_ml_kem_variant_kdf_39_52(uu____3,
      libcrux_ml_kem_types_as_ತುಂಡು_a9_52(ciphertext));
  Eurydice_arr_ec
  shared_secret =
    libcrux_ml_kem_variant_kdf_39_52(shared_secret0,
      libcrux_ml_kem_types_as_ತುಂಡು_a9_52(ciphertext));
  Eurydice_borrow_ತುಂಡು_u8 uu____4 = libcrux_ml_kem_types_as_ref_c1_52(ciphertext);
  ಹಿಂತಿರುಗಿ
    libcrux_ml_kem_constant_ಸಮಯ_ops_compare_ciphertexts_select_shared_secret_ಒಳ_constant_ಸಮಯ(uu____4,
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_06(&expected_ciphertext),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_01(&shared_secret),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_01(&implicit_rejection_shared_secret0));
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_ec
libcrux_ml_kem_ind_cca_instantiations_portable_decapsulate_19(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_7d *ಖಾಸಗಿ_ಕೀಲಿ,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_2b *ciphertext
)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ind_cca_decapsulate_fd(ಖಾಸಗಿ_ಕೀಲಿ, ciphertext);
}

/**
 Decapsulate ML-KEM 768

 Generates an [`MlKemSharedSecret`].
 The input is a reference to an [`MlKem768PrivateKey`] and an [`MlKem768Ciphertext`].
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_ec
libcrux_ml_kem_mlkem768_portable_decapsulate(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_7d *ಖಾಸಗಿ_ಕೀಲಿ,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_2b *ciphertext
)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ind_cca_instantiations_portable_decapsulate_19(ಖಾಸಗಿ_ಕೀಲಿ, ciphertext);
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
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_ec
libcrux_ml_kem_variant_entropy_preprocess_39_13(Eurydice_borrow_ತುಂಡು_u8 randomness)
{
  Eurydice_arr_ec ಹೊರಹೋಗು = { .ದತ್ತಾಂಶ = { 0U } };
  Eurydice_ತುಂಡು_copy(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_01(&ಹೊರಹೋಗು), randomness, uint8_t);
  ಹಿಂತಿರುಗಿ ಹೊರಹೋಗು;
}

/**
This function found in impl {libcrux_ml_kem::hash_functions::Hash<K> for libcrux_ml_kem::hash_functions::portable::PortableHash<K>}
*/
/**
A monomorphic instance of libcrux_ml_kem.hash_functions.portable.H_4a
with const generics
- K= 3
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_ec
libcrux_ml_kem_hash_functions_portable_H_4a_78(Eurydice_borrow_ತುಂಡು_u8 ಒಳಹರಿವು)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_hash_functions_portable_H(ಒಳಹರಿವು);
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
ಸ್ಥಿರ KRML_MUSTINLINE tuple_f4
libcrux_ml_kem_ind_cca_encapsulate_99(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_5f *ಬಹಿರಂಗ_ಕೀಲಿ,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_ec *randomness
)
{
  Eurydice_arr_ec
  randomness0 =
    libcrux_ml_kem_variant_entropy_preprocess_39_13(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_01(randomness));
  Eurydice_arr_c7
  ಗಮ್ಯ_hash =
    libcrux_ml_kem_utils_into_padded_array_c9(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_01(&randomness0));
  Eurydice_mut_borrow_ತುಂಡು_u8
  uu____0 =
    Eurydice_array_ಗಮ್ಯ_subslice_from_mut_5f1(&ಗಮ್ಯ_hash,
      LIBCRUX_ML_KEM_CONSTANTS_H_DIGEST_ಗಾತ್ರ);
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_ec
  lvalue =
    libcrux_ml_kem_hash_functions_portable_H_4a_78(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_ff(libcrux_ml_kem_types_as_ತುಂಡು_e6_3d(ಬಹಿರಂಗ_ಕೀಲಿ)));
  Eurydice_ತುಂಡು_copy(uu____0, Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_01(&lvalue), uint8_t);
  Eurydice_arr_c7
  hashed =
    libcrux_ml_kem_hash_functions_portable_G_4a_78(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_17(&ಗಮ್ಯ_hash));
  Eurydice_borrow_ತುಂಡು_u8_x2
  uu____1 =
    Eurydice_ತುಂಡು_ವಿಭಜಿಸು_at(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_17(&hashed),
      LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_ಗಾತ್ರ,
      uint8_t,
      Eurydice_borrow_ತುಂಡು_u8_x2);
  Eurydice_borrow_ತುಂಡು_u8 shared_secret = uu____1.fst;
  Eurydice_borrow_ತುಂಡು_u8 pseudorandomness = uu____1.snd;
  Eurydice_arr_2b
  ciphertext =
    libcrux_ml_kem_ind_cpa_encrypt_d5(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_ff(libcrux_ml_kem_types_as_ತುಂಡು_e6_3d(ಬಹಿರಂಗ_ಕೀಲಿ)),
      &randomness0,
      pseudorandomness);
  Eurydice_arr_2b uu____2 = libcrux_ml_kem_types_from_19_52(ciphertext);
  ಹಿಂತಿರುಗಿ
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ tuple_f4
libcrux_ml_kem_ind_cca_instantiations_portable_encapsulate_26(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_5f *ಬಹಿರಂಗ_ಕೀಲಿ,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_ec *randomness
)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ind_cca_encapsulate_99(ಬಹಿರಂಗ_ಕೀಲಿ, randomness);
}

/**
 Encapsulate ML-KEM 768

 Generates an ([`MlKem768Ciphertext`], [`MlKemSharedSecret`]) tuple.
 The input is a reference to an [`MlKem768PublicKey`] and [`SHARED_SECRET_SIZE`]
 bytes of `randomness`.
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ tuple_f4
libcrux_ml_kem_mlkem768_portable_encapsulate(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_5f *ಬಹಿರಂಗ_ಕೀಲಿ,
  Eurydice_arr_ec randomness
)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ind_cca_instantiations_portable_encapsulate_26(ಬಹಿರಂಗ_ಕೀಲಿ, &randomness);
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_bb0 libcrux_ml_kem_ind_cpa_unpacked_default_70_68(ಶೂನ್ಯ)
{
  Eurydice_arr_bb0 lit;
  Eurydice_arr_9e repeat_ಅಭಿವ್ಯಕ್ತಿ[3U];
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)3U; i++)
  {
    repeat_ಅಭಿವ್ಯಕ್ತಿ[i] = libcrux_ml_kem_polynomial_ZERO_d6_ea();
  }
  ಸ್ಮರಣೆ_ನಕಲು(lit.ದತ್ತಾಂಶ, repeat_ಅಭಿವ್ಯಕ್ತಿ, (ಗಾತ್ರ_t)3U * ಗಾತ್ರ (Eurydice_arr_9e));
  ಹಿಂತಿರುಗಿ lit;
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
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_c7
libcrux_ml_kem_variant_cpa_keygen_ಬೀಜ_39_13(Eurydice_borrow_ತುಂಡು_u8 ಕೀಲಿ_generation_ಬೀಜ)
{
  Eurydice_arr_fa0 ಬೀಜ = { .ದತ್ತಾಂಶ = { 0U } };
  Eurydice_ತುಂಡು_copy(Eurydice_array_ಗಮ್ಯ_subslice_mut_d412(&ಬೀಜ,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .ಆರಂಭ = (ಗಾತ್ರ_t)0U,
          .ಕೊನೆ = LIBCRUX_ML_KEM_CONSTANTS_CPA_PKE_ಕೀಲಿ_GENERATION_ಬೀಜ_ಗಾತ್ರ
        }
      )),
    ಕೀಲಿ_generation_ಬೀಜ,
    uint8_t);
  ಬೀಜ.ದತ್ತಾಂಶ[LIBCRUX_ML_KEM_CONSTANTS_CPA_PKE_ಕೀಲಿ_GENERATION_ಬೀಜ_ಗಾತ್ರ] = (uint8_t)(ಗಾತ್ರ_t)3U;
  ಹಿಂತಿರುಗಿ
    libcrux_ml_kem_hash_functions_portable_G_4a_78(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_b5(&ಬೀಜ));
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_9e
libcrux_ml_kem_ind_cpa_generate_keypair_unpacked_call_mut_73_39(ಶೂನ್ಯ **_, ಗಾತ್ರ_t tupled_ವಾದಗಳು)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_polynomial_ZERO_d6_ea();
}

/**
A monomorphic instance of libcrux_ml_kem.polynomial.to_standard_domain
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_d6
libcrux_ml_kem_polynomial_ಗಮ್ಯ_standard_domain_ea(Eurydice_arr_d6 ಸದಿಶ)
{
  ಹಿಂತಿರುಗಿ
    libcrux_ml_kem_ಸದಿಶ_portable_montgomery_multiply_by_constant_b8(ಸದಿಶ,
      LIBCRUX_ML_KEM_ಸದಿಶ_TRAITS_MONTGOMERY_R_SQUARED_MOD_ಕ್ಷೇತ್ರ_MODULUS);
}

/**
A monomorphic instance of libcrux_ml_kem.polynomial.add_standard_error_reduce
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_kem_polynomial_ಕೂಡಿಸು_standard_error_reduce_ea(
  Eurydice_arr_9e *myself,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_9e *error
)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_ಒಳ_RING_ELEMENT; i++)
  {
    ಗಾತ್ರ_t j = i;
    Eurydice_arr_d6
    coefficient_ಸಾಮಾನ್ಯ_form = libcrux_ml_kem_polynomial_ಗಮ್ಯ_standard_domain_ea(myself->ದತ್ತಾಂಶ[j]);
    Eurydice_arr_d6
    ಮೊತ್ತ = libcrux_ml_kem_ಸದಿಶ_portable_ಕೂಡಿಸು_b8(coefficient_ಸಾಮಾನ್ಯ_form, &error->ದತ್ತಾಂಶ[j]);
    Eurydice_arr_d6 red = libcrux_ml_kem_ಸದಿಶ_portable_barrett_reduce_b8(ಮೊತ್ತ);
    myself->ದತ್ತಾಂಶ[j] = red;
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_kem_polynomial_ಕೂಡಿಸು_standard_error_reduce_d6_ea(
  Eurydice_arr_9e *self,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_9e *error
)
{
  libcrux_ml_kem_polynomial_ಕೂಡಿಸು_standard_error_reduce_ea(self, error);
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_kem_ಮಾತೃಕೆ_compute_As_plus_e_68(
  Eurydice_arr_bb0 *t_as_ntt,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_c10 *ಮಾತೃಕೆ_A,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_bb0 *s_as_ntt,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_bb0 *error_as_ntt
)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)3U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    ಸ್ಥಿರಾಂಕ Eurydice_arr_bb0 *ಅಡ್ಡಸಾಲು = &ಮಾತೃಕೆ_A->ದತ್ತಾಂಶ[i0];
    Eurydice_arr_9e uu____0 = libcrux_ml_kem_polynomial_ZERO_d6_ea();
    t_as_ntt->ದತ್ತಾಂಶ[i0] = uu____0;
    ಗಾಗಿ (ಗಾತ್ರ_t i1 = (ಗಾತ್ರ_t)0U; i1 < (ಗಾತ್ರ_t)3U; i1++)
    {
      ಗಾತ್ರ_t j = i1;
      ಸ್ಥಿರಾಂಕ Eurydice_arr_9e *ಮಾತೃಕೆ_element = &ಅಡ್ಡಸಾಲು->ದತ್ತಾಂಶ[j];
      Eurydice_arr_9e
      ಗುಣಲಬ್ಧ = libcrux_ml_kem_polynomial_ntt_multiply_d6_ea(ಮಾತೃಕೆ_element, &s_as_ntt->ದತ್ತಾಂಶ[j]);
      libcrux_ml_kem_polynomial_ಕೂಡಿಸು_ಗಮ್ಯ_ring_element_d6_68(&t_as_ntt->ದತ್ತಾಂಶ[i0], &ಗುಣಲಬ್ಧ);
    }
    libcrux_ml_kem_polynomial_ಕೂಡಿಸು_standard_error_reduce_d6_ea(&t_as_ntt->ದತ್ತಾಂಶ[i0],
      &error_as_ntt->ದತ್ತಾಂಶ[i0]);
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_kem_ind_cpa_generate_keypair_unpacked_39(
  Eurydice_borrow_ತುಂಡು_u8 ಕೀಲಿ_generation_ಬೀಜ,
  Eurydice_arr_bb0 *ಖಾಸಗಿ_ಕೀಲಿ,
  libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_ಬಹಿರಂಗ_ಕೀಲಿ_Unpacked_51 *ಬಹಿರಂಗ_ಕೀಲಿ
)
{
  Eurydice_arr_c7 hashed = libcrux_ml_kem_variant_cpa_keygen_ಬೀಜ_39_13(ಕೀಲಿ_generation_ಬೀಜ);
  Eurydice_borrow_ತುಂಡು_u8_x2
  uu____0 =
    Eurydice_ತುಂಡು_ವಿಭಜಿಸು_at(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_17(&hashed),
      (ಗಾತ್ರ_t)32U,
      uint8_t,
      Eurydice_borrow_ತುಂಡು_u8_x2);
  Eurydice_borrow_ತುಂಡು_u8 ಬೀಜ_for_A = uu____0.fst;
  Eurydice_borrow_ತುಂಡು_u8 ಬೀಜ_for_secret_and_error = uu____0.snd;
  Eurydice_arr_c10 *uu____1 = &ಬಹಿರಂಗ_ಕೀಲಿ->A;
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_31 lvalue0 = libcrux_ml_kem_utils_into_padded_array_de(ಬೀಜ_for_A);
  libcrux_ml_kem_ಮಾತೃಕೆ_sample_ಮಾತೃಕೆ_A_91(uu____1, &lvalue0, true);
  Eurydice_arr_fa0
  prf_ಒಳಹರಿವು = libcrux_ml_kem_utils_into_padded_array_29(ಬೀಜ_for_secret_and_error);
  uint8_t
  domain_separator =
    libcrux_ml_kem_ind_cpa_sample_ಸದಿಶ_cbd_then_ntt_bf(ಖಾಸಗಿ_ಕೀಲಿ,
      &prf_ಒಳಹರಿವು,
      0U);
  Eurydice_arr_bb0 arr_struct;
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    ಶೂನ್ಯ *lvalue = (ಶೂನ್ಯ *)0U;
    arr_struct.ದತ್ತಾಂಶ[i] =
      libcrux_ml_kem_ind_cpa_generate_keypair_unpacked_call_mut_73_39(&lvalue,
        i);
  }
  Eurydice_arr_bb0 error_as_ntt = arr_struct;
  libcrux_ml_kem_ind_cpa_sample_ಸದಿಶ_cbd_then_ntt_bf(&error_as_ntt,
    &prf_ಒಳಹರಿವು,
    domain_separator);
  libcrux_ml_kem_ಮಾತೃಕೆ_compute_As_plus_e_68(&ಬಹಿರಂಗ_ಕೀಲಿ->t_as_ntt,
    &ಬಹಿರಂಗ_ಕೀಲಿ->A,
    &ಖಾಸಗಿ_ಕೀಲಿ[0U],
    &error_as_ntt);
  Eurydice_arr_ec arr;
  ಸ್ಮರಣೆ_ನಕಲು(arr.ದತ್ತಾಂಶ, ಬೀಜ_for_A.ptr, (ಗಾತ್ರ_t)32U * ಗಾತ್ರ (uint8_t));
  Eurydice_arr_ec
  uu____2 =
    core_ಫಲಿತಾಂಶ_unwrap_26_39((
        KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_07){ .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Ok, .val = { .case_Ok = arr } }
      ));
  ಬಹಿರಂಗ_ಕೀಲಿ->ಬೀಜ_for_A = uu____2;
}

/**
A monomorphic instance of libcrux_ml_kem.serialize.serialize_uncompressed_ring_element
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_b20
libcrux_ml_kem_serialize_serialize_uncompressed_ring_element_ea(ಸ್ಥಿರಾಂಕ Eurydice_arr_9e *re)
{
  Eurydice_arr_b20 serialized = { .ದತ್ತಾಂಶ = { 0U } };
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < LIBCRUX_ML_KEM_POLYNOMIAL_VECTORS_ಒಳ_RING_ELEMENT; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    Eurydice_arr_d6
    coefficient = libcrux_ml_kem_serialize_ಗಮ್ಯ_unsigned_ಕ್ಷೇತ್ರ_modulus_ea(re->ದತ್ತಾಂಶ[i0]);
    Eurydice_arr_94 ಬೈಟುಗಳು = libcrux_ml_kem_ಸದಿಶ_portable_serialize_12_b8(coefficient);
    Eurydice_ತುಂಡು_copy(Eurydice_array_ಗಮ್ಯ_subslice_mut_d415(&serialized,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ಆರಂಭ = (ಗಾತ್ರ_t)24U * i0,
            .ಕೊನೆ = (ಗಾತ್ರ_t)24U * i0 + (ಗಾತ್ರ_t)24U
          }
        )),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_ed(&ಬೈಟುಗಳು),
      uint8_t);
  }
  ಹಿಂತಿರುಗಿ serialized;
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_kem_ind_cpa_serialize_ಸದಿಶ_68(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_bb0 *ಕೀಲಿ,
  Eurydice_mut_borrow_ತುಂಡು_u8 ಹೊರಹೋಗು
)
{
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)3U; i++)
  {
    ಗಾತ್ರ_t i0 = i;
    Eurydice_arr_9e re = ಕೀಲಿ->ದತ್ತಾಂಶ[i0];
    Eurydice_mut_borrow_ತುಂಡು_u8
    uu____0 =
      Eurydice_ತುಂಡು_subslice_mut_c8(ಹೊರಹೋಗು,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ಆರಂಭ = i0 * LIBCRUX_ML_KEM_CONSTANTS_ಬೈಟುಗಳು_ಪ್ರತಿ_RING_ELEMENT,
            .ಕೊನೆ = (i0 + (ಗಾತ್ರ_t)1U) * LIBCRUX_ML_KEM_CONSTANTS_ಬೈಟುಗಳು_ಪ್ರತಿ_RING_ELEMENT
          }
        ));
    /* original Rust expression is not an lvalue in C */
    Eurydice_arr_b20 lvalue = libcrux_ml_kem_serialize_serialize_uncompressed_ring_element_ea(&re);
    Eurydice_ತುಂಡು_copy(uu____0, Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_a9(&lvalue), uint8_t);
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_kem_ind_cpa_serialize_ಬಹಿರಂಗ_ಕೀಲಿ_mut_b6(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_bb0 *t_as_ntt,
  Eurydice_borrow_ತುಂಡು_u8 ಬೀಜ_for_a,
  Eurydice_arr_5f *serialized
)
{
  libcrux_ml_kem_ind_cpa_serialize_ಸದಿಶ_68(t_as_ntt,
    Eurydice_array_ಗಮ್ಯ_subslice_mut_d416(serialized,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .ಆರಂಭ = (ಗಾತ್ರ_t)0U,
          .ಕೊನೆ = libcrux_ml_kem_constants_ranked_ಬೈಟುಗಳು_ಪ್ರತಿ_ring_element((ಗಾತ್ರ_t)3U)
        }
      )));
  Eurydice_ತುಂಡು_copy(Eurydice_array_ಗಮ್ಯ_subslice_from_mut_5f4(serialized,
      libcrux_ml_kem_constants_ranked_ಬೈಟುಗಳು_ಪ್ರತಿ_ring_element((ಗಾತ್ರ_t)3U)),
    ಬೀಜ_for_a,
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
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_5f
libcrux_ml_kem_ind_cpa_serialize_ಬಹಿರಂಗ_ಕೀಲಿ_b6(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_bb0 *t_as_ntt,
  Eurydice_borrow_ತುಂಡು_u8 ಬೀಜ_for_a
)
{
  Eurydice_arr_5f ಬಹಿರಂಗ_ಕೀಲಿ_serialized = { .ದತ್ತಾಂಶ = { 0U } };
  libcrux_ml_kem_ind_cpa_serialize_ಬಹಿರಂಗ_ಕೀಲಿ_mut_b6(t_as_ntt,
    ಬೀಜ_for_a,
    &ಬಹಿರಂಗ_ಕೀಲಿ_serialized);
  ಹಿಂತಿರುಗಿ ಬಹಿರಂಗ_ಕೀಲಿ_serialized;
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ libcrux_ml_kem_utils_extraction_helper_Keypair768
libcrux_ml_kem_ind_cpa_serialize_unpacked_secret_ಕೀಲಿ_30(
  ಸ್ಥಿರಾಂಕ libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_ಬಹಿರಂಗ_ಕೀಲಿ_Unpacked_51 *ಬಹಿರಂಗ_ಕೀಲಿ,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_bb0 *ಖಾಸಗಿ_ಕೀಲಿ
)
{
  Eurydice_arr_5f
  ಬಹಿರಂಗ_ಕೀಲಿ_serialized =
    libcrux_ml_kem_ind_cpa_serialize_ಬಹಿರಂಗ_ಕೀಲಿ_b6(&ಬಹಿರಂಗ_ಕೀಲಿ->t_as_ntt,
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_01(&ಬಹಿರಂಗ_ಕೀಲಿ->ಬೀಜ_for_A));
  Eurydice_arr_0e secret_ಕೀಲಿ_serialized = { .ದತ್ತಾಂಶ = { 0U } };
  libcrux_ml_kem_ind_cpa_serialize_ಸದಿಶ_68(ಖಾಸಗಿ_ಕೀಲಿ,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_f4(&secret_ಕೀಲಿ_serialized));
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(libcrux_ml_kem_utils_extraction_helper_Keypair768){
        .fst = secret_ಕೀಲಿ_serialized,
        .snd = ಬಹಿರಂಗ_ಕೀಲಿ_serialized
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
ಸ್ಥಿರ KRML_MUSTINLINE libcrux_ml_kem_utils_extraction_helper_Keypair768
libcrux_ml_kem_ind_cpa_generate_keypair_30(Eurydice_borrow_ತುಂಡು_u8 ಕೀಲಿ_generation_ಬೀಜ)
{
  Eurydice_arr_bb0 ಖಾಸಗಿ_ಕೀಲಿ = libcrux_ml_kem_ind_cpa_unpacked_default_70_68();
  libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_ಬಹಿರಂಗ_ಕೀಲಿ_Unpacked_51
  ಬಹಿರಂಗ_ಕೀಲಿ = libcrux_ml_kem_ind_cpa_unpacked_default_8b_68();
  libcrux_ml_kem_ind_cpa_generate_keypair_unpacked_39(ಕೀಲಿ_generation_ಬೀಜ,
    &ಖಾಸಗಿ_ಕೀಲಿ,
    &ಬಹಿರಂಗ_ಕೀಲಿ);
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ind_cpa_serialize_unpacked_secret_ಕೀಲಿ_30(&ಬಹಿರಂಗ_ಕೀಲಿ, &ಖಾಸಗಿ_ಕೀಲಿ);
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_kem_ind_cca_serialize_kem_secret_ಕೀಲಿ_mut_52(
  Eurydice_borrow_ತುಂಡು_u8 ಖಾಸಗಿ_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಬಹಿರಂಗ_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 implicit_rejection_ಮೌಲ್ಯ,
  Eurydice_arr_7d *serialized
)
{
  ಗಾತ್ರ_t ಸೂಚಕ = (ಗಾತ್ರ_t)0U;
  Eurydice_ತುಂಡು_copy(Eurydice_array_ಗಮ್ಯ_subslice_mut_d417(serialized,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .ಆರಂಭ = ಸೂಚಕ,
          .ಕೊನೆ = ಸೂಚಕ + ಖಾಸಗಿ_ಕೀಲಿ.meta
        }
      )),
    ಖಾಸಗಿ_ಕೀಲಿ,
    uint8_t);
  ಸೂಚಕ += ಖಾಸಗಿ_ಕೀಲಿ.meta;
  Eurydice_ತುಂಡು_copy(Eurydice_array_ಗಮ್ಯ_subslice_mut_d417(serialized,
      (KRML_CLITERAL(core_ops_range_Range_87){ .ಆರಂಭ = ಸೂಚಕ, .ಕೊನೆ = ಸೂಚಕ + ಬಹಿರಂಗ_ಕೀಲಿ.meta })),
    ಬಹಿರಂಗ_ಕೀಲಿ,
    uint8_t);
  ಸೂಚಕ += ಬಹಿರಂಗ_ಕೀಲಿ.meta;
  Eurydice_mut_borrow_ತುಂಡು_u8
  uu____0 =
    Eurydice_array_ಗಮ್ಯ_subslice_mut_d417(serialized,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .ಆರಂಭ = ಸೂಚಕ,
          .ಕೊನೆ = ಸೂಚಕ + LIBCRUX_ML_KEM_CONSTANTS_H_DIGEST_ಗಾತ್ರ
        }
      ));
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_ec lvalue = libcrux_ml_kem_hash_functions_portable_H_4a_78(ಬಹಿರಂಗ_ಕೀಲಿ);
  Eurydice_ತುಂಡು_copy(uu____0, Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_01(&lvalue), uint8_t);
  ಸೂಚಕ += LIBCRUX_ML_KEM_CONSTANTS_H_DIGEST_ಗಾತ್ರ;
  Eurydice_ತುಂಡು_copy(Eurydice_array_ಗಮ್ಯ_subslice_mut_d417(serialized,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .ಆರಂಭ = ಸೂಚಕ,
          .ಕೊನೆ = ಸೂಚಕ + implicit_rejection_ಮೌಲ್ಯ.meta
        }
      )),
    implicit_rejection_ಮೌಲ್ಯ,
    uint8_t);
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cca.serialize_kem_secret_key
with types libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
- SERIALIZED_KEY_LEN= 2400
*/
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_7d
libcrux_ml_kem_ind_cca_serialize_kem_secret_ಕೀಲಿ_52(
  Eurydice_borrow_ತುಂಡು_u8 ಖಾಸಗಿ_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 ಬಹಿರಂಗ_ಕೀಲಿ,
  Eurydice_borrow_ತುಂಡು_u8 implicit_rejection_ಮೌಲ್ಯ
)
{
  Eurydice_arr_7d ಹೊರಹೋಗು = { .ದತ್ತಾಂಶ = { 0U } };
  libcrux_ml_kem_ind_cca_serialize_kem_secret_ಕೀಲಿ_mut_52(ಖಾಸಗಿ_ಕೀಲಿ,
    ಬಹಿರಂಗ_ಕೀಲಿ,
    implicit_rejection_ಮೌಲ್ಯ,
    &ಹೊರಹೋಗು);
  ಹಿಂತಿರುಗಿ ಹೊರಹೋಗು;
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
ಸ್ಥಿರ KRML_MUSTINLINE libcrux_ml_kem_mlkem768_Ml_Kem768_ಕೀಲಿ_Pair
libcrux_ml_kem_ind_cca_generate_keypair_b8(ಸ್ಥಿರಾಂಕ Eurydice_arr_c7 *randomness)
{
  Eurydice_borrow_ತುಂಡು_u8
  ind_cpa_keypair_randomness =
    Eurydice_array_ಗಮ್ಯ_subslice_shared_d47(randomness,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .ಆರಂಭ = (ಗಾತ್ರ_t)0U,
          .ಕೊನೆ = LIBCRUX_ML_KEM_CONSTANTS_CPA_PKE_ಕೀಲಿ_GENERATION_ಬೀಜ_ಗಾತ್ರ
        }
      ));
  Eurydice_borrow_ತುಂಡು_u8
  implicit_rejection_ಮೌಲ್ಯ =
    Eurydice_array_ಗಮ್ಯ_subslice_from_shared_5f1(randomness,
      LIBCRUX_ML_KEM_CONSTANTS_CPA_PKE_ಕೀಲಿ_GENERATION_ಬೀಜ_ಗಾತ್ರ);
  libcrux_ml_kem_utils_extraction_helper_Keypair768
  uu____0 = libcrux_ml_kem_ind_cpa_generate_keypair_30(ind_cpa_keypair_randomness);
  Eurydice_arr_0e ind_cpa_ಖಾಸಗಿ_ಕೀಲಿ = uu____0.fst;
  Eurydice_arr_5f ಬಹಿರಂಗ_ಕೀಲಿ = uu____0.snd;
  Eurydice_arr_7d
  secret_ಕೀಲಿ_serialized =
    libcrux_ml_kem_ind_cca_serialize_kem_secret_ಕೀಲಿ_52(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_f4(&ind_cpa_ಖಾಸಗಿ_ಕೀಲಿ),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_ff(&ಬಹಿರಂಗ_ಕೀಲಿ),
      implicit_rejection_ಮೌಲ್ಯ);
  Eurydice_arr_7d ಖಾಸಗಿ_ಕೀಲಿ = libcrux_ml_kem_types_from_b2_79(secret_ಕೀಲಿ_serialized);
  ಹಿಂತಿರುಗಿ
    libcrux_ml_kem_types_from_17_bc(ಖಾಸಗಿ_ಕೀಲಿ,
      libcrux_ml_kem_types_from_51_3d(ಬಹಿರಂಗ_ಕೀಲಿ));
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ libcrux_ml_kem_mlkem768_Ml_Kem768_ಕೀಲಿ_Pair
libcrux_ml_kem_ind_cca_instantiations_portable_generate_keypair_e9(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_c7 *randomness
)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ind_cca_generate_keypair_b8(randomness);
}

/**
 Generate ML-KEM 768 Key Pair
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ libcrux_ml_kem_mlkem768_Ml_Kem768_ಕೀಲಿ_Pair
libcrux_ml_kem_mlkem768_portable_generate_ಕೀಲಿ_pair(Eurydice_arr_c7 randomness)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ind_cca_instantiations_portable_generate_keypair_e9(&randomness);
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
ಸ್ಥಿರ KRML_MUSTINLINE bool
libcrux_ml_kem_ind_cca_validate_ಖಾಸಗಿ_ಕೀಲಿ_only_52(ಸ್ಥಿರಾಂಕ Eurydice_arr_7d *ಖಾಸಗಿ_ಕೀಲಿ)
{
  Eurydice_arr_ec
  t =
    libcrux_ml_kem_hash_functions_portable_H_4a_78(Eurydice_array_ಗಮ್ಯ_subslice_shared_d48(ಖಾಸಗಿ_ಕೀಲಿ,
        (
          KRML_CLITERAL(core_ops_range_Range_87){
            .ಆರಂಭ = (ಗಾತ್ರ_t)384U * (ಗಾತ್ರ_t)3U,
            .ಕೊನೆ = (ಗಾತ್ರ_t)768U * (ಗಾತ್ರ_t)3U + (ಗಾತ್ರ_t)32U
          }
        )));
  Eurydice_borrow_ತುಂಡು_u8
  expected =
    Eurydice_array_ಗಮ್ಯ_subslice_shared_d48(ಖಾಸಗಿ_ಕೀಲಿ,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .ಆರಂಭ = (ಗಾತ್ರ_t)768U * (ಗಾತ್ರ_t)3U + (ಗಾತ್ರ_t)32U,
          .ಕೊನೆ = (ಗಾತ್ರ_t)768U * (ಗಾತ್ರ_t)3U + (ಗಾತ್ರ_t)64U
        }
      ));
  ಹಿಂತಿರುಗಿ Eurydice_array_eq_ತುಂಡು_shared((ಗಾತ್ರ_t)32U, &t, &expected, uint8_t, bool);
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
ಸ್ಥಿರ KRML_MUSTINLINE bool
libcrux_ml_kem_ind_cca_validate_ಖಾಸಗಿ_ಕೀಲಿ_ba(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_7d *ಖಾಸಗಿ_ಕೀಲಿ,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_2b *_ciphertext
)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ind_cca_validate_ಖಾಸಗಿ_ಕೀಲಿ_only_52(ಖಾಸಗಿ_ಕೀಲಿ);
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
ಸ್ಥಿರ KRML_MUSTINLINE bool
libcrux_ml_kem_ind_cca_instantiations_portable_validate_ಖಾಸಗಿ_ಕೀಲಿ_d3(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_7d *ಖಾಸಗಿ_ಕೀಲಿ,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_2b *ciphertext
)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ind_cca_validate_ಖಾಸಗಿ_ಕೀಲಿ_ba(ಖಾಸಗಿ_ಕೀಲಿ, ciphertext);
}

/**
 Validate a private key.

 Returns `true` if valid, and `false` otherwise.
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ bool
libcrux_ml_kem_mlkem768_portable_validate_ಖಾಸಗಿ_ಕೀಲಿ(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_7d *ಖಾಸಗಿ_ಕೀಲಿ,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_2b *ciphertext
)
{
  ಹಿಂತಿರುಗಿ
    libcrux_ml_kem_ind_cca_instantiations_portable_validate_ಖಾಸಗಿ_ಕೀಲಿ_d3(ಖಾಸಗಿ_ಕೀಲಿ,
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
ಸ್ಥಿರ KRML_MUSTINLINE bool
libcrux_ml_kem_ind_cca_instantiations_portable_validate_ಖಾಸಗಿ_ಕೀಲಿ_only_3b(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_7d *ಖಾಸಗಿ_ಕೀಲಿ
)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ind_cca_validate_ಖಾಸಗಿ_ಕೀಲಿ_only_52(ಖಾಸಗಿ_ಕೀಲಿ);
}

/**
 Validate the private key only.

 Returns `true` if valid, and `false` otherwise.
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ bool
libcrux_ml_kem_mlkem768_portable_validate_ಖಾಸಗಿ_ಕೀಲಿ_only(ಸ್ಥಿರಾಂಕ Eurydice_arr_7d *ಖಾಸಗಿ_ಕೀಲಿ)
{
  ಹಿಂತಿರುಗಿ
    libcrux_ml_kem_ind_cca_instantiations_portable_validate_ಖಾಸಗಿ_ಕೀಲಿ_only_3b(ಖಾಸಗಿ_ಕೀಲಿ);
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_9e
libcrux_ml_kem_serialize_deserialize_ring_elements_reduced_ಹೊರಹೋಗು_call_mut_0b_68(
  ಶೂನ್ಯ **_,
  ಗಾತ್ರ_t tupled_ವಾದಗಳು
)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_polynomial_ZERO_d6_ea();
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
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_bb0
libcrux_ml_kem_serialize_deserialize_ring_elements_reduced_ಹೊರಹೋಗು_68(
  Eurydice_borrow_ತುಂಡು_u8 ಬಹಿರಂಗ_ಕೀಲಿ
)
{
  Eurydice_arr_bb0 arr_struct;
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    ಶೂನ್ಯ *lvalue = (ಶೂನ್ಯ *)0U;
    arr_struct.ದತ್ತಾಂಶ[i] =
      libcrux_ml_kem_serialize_deserialize_ring_elements_reduced_ಹೊರಹೋಗು_call_mut_0b_68(&lvalue,
        i);
  }
  Eurydice_arr_bb0 deserialized_pk = arr_struct;
  libcrux_ml_kem_serialize_deserialize_ring_elements_reduced_68(ಬಹಿರಂಗ_ಕೀಲಿ, &deserialized_pk);
  ಹಿಂತಿರುಗಿ deserialized_pk;
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
ಸ್ಥಿರ KRML_MUSTINLINE bool
libcrux_ml_kem_ind_cca_validate_ಬಹಿರಂಗ_ಕೀಲಿ_b6(ಸ್ಥಿರಾಂಕ Eurydice_arr_5f *ಬಹಿರಂಗ_ಕೀಲಿ)
{
  Eurydice_arr_bb0
  deserialized_pk =
    libcrux_ml_kem_serialize_deserialize_ring_elements_reduced_ಹೊರಹೋಗು_68(Eurydice_array_ಗಮ್ಯ_subslice_ಗಮ್ಯ_shared_210(ಬಹಿರಂಗ_ಕೀಲಿ,
        libcrux_ml_kem_constants_ranked_ಬೈಟುಗಳು_ಪ್ರತಿ_ring_element((ಗಾತ್ರ_t)3U)));
  Eurydice_arr_5f
  ಬಹಿರಂಗ_ಕೀಲಿ_serialized =
    libcrux_ml_kem_ind_cpa_serialize_ಬಹಿರಂಗ_ಕೀಲಿ_b6(&deserialized_pk,
      Eurydice_array_ಗಮ್ಯ_subslice_from_shared_5f2(ಬಹಿರಂಗ_ಕೀಲಿ,
        libcrux_ml_kem_constants_ranked_ಬೈಟುಗಳು_ಪ್ರತಿ_ring_element((ಗಾತ್ರ_t)3U)));
  ಹಿಂತಿರುಗಿ Eurydice_array_eq((ಗಾತ್ರ_t)1184U, ಬಹಿರಂಗ_ಕೀಲಿ, &ಬಹಿರಂಗ_ಕೀಲಿ_serialized, uint8_t);
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
ಸ್ಥಿರ KRML_MUSTINLINE bool
libcrux_ml_kem_ind_cca_instantiations_portable_validate_ಬಹಿರಂಗ_ಕೀಲಿ_3b(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_5f *ಬಹಿರಂಗ_ಕೀಲಿ
)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ind_cca_validate_ಬಹಿರಂಗ_ಕೀಲಿ_b6(ಬಹಿರಂಗ_ಕೀಲಿ);
}

/**
 Validate a public key.

 Returns `true` if valid, and `false` otherwise.
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ bool
libcrux_ml_kem_mlkem768_portable_validate_ಬಹಿರಂಗ_ಕೀಲಿ(ಸ್ಥಿರಾಂಕ Eurydice_arr_5f *ಬಹಿರಂಗ_ಕೀಲಿ)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ind_cca_instantiations_portable_validate_ಬಹಿರಂಗ_ಕೀಲಿ_3b(ಬಹಿರಂಗ_ಕೀಲಿ);
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.MlKemPublicKeyUnpacked
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- $3size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_ಬಹಿರಂಗ_ಕೀಲಿ_Unpacked_51_s
{
  libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_ಬಹಿರಂಗ_ಕೀಲಿ_Unpacked_51 ind_cpa_ಬಹಿರಂಗ_ಕೀಲಿ;
  Eurydice_arr_ec ಬಹಿರಂಗ_ಕೀಲಿ_hash;
}
libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_ಬಹಿರಂಗ_ಕೀಲಿ_Unpacked_51;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_ಬಹಿರಂಗ_ಕೀಲಿ_Unpacked_51
libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_ಬಹಿರಂಗ_ಕೀಲಿ_Unpacked;

/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.MlKemPrivateKeyUnpacked
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics
- $3size_t
*/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_ಖಾಸಗಿ_ಕೀಲಿ_Unpacked_51_s
{
  Eurydice_arr_bb0 ind_cpa_ಖಾಸಗಿ_ಕೀಲಿ;
  Eurydice_arr_ec implicit_rejection_ಮೌಲ್ಯ;
}
libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_ಖಾಸಗಿ_ಕೀಲಿ_Unpacked_51;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_ಕೀಲಿ_Pair_Unpacked_s
{
  libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_ಖಾಸಗಿ_ಕೀಲಿ_Unpacked_51 ಖಾಸಗಿ_ಕೀಲಿ;
  libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_ಬಹಿರಂಗ_ಕೀಲಿ_Unpacked_51 ಬಹಿರಂಗ_ಕೀಲಿ;
}
libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_ಕೀಲಿ_Pair_Unpacked;

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
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_ec
libcrux_ml_kem_ind_cca_unpacked_decapsulate_0c(
  ಸ್ಥಿರಾಂಕ libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_ಕೀಲಿ_Pair_Unpacked *ಕೀಲಿ_pair,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_2b *ciphertext
)
{
  Eurydice_arr_ec
  decrypted =
    libcrux_ml_kem_ind_cpa_decrypt_unpacked_01(&ಕೀಲಿ_pair->ಖಾಸಗಿ_ಕೀಲಿ.ind_cpa_ಖಾಸಗಿ_ಕೀಲಿ,
      ciphertext);
  Eurydice_arr_c7
  ಗಮ್ಯ_hash0 =
    libcrux_ml_kem_utils_into_padded_array_c9(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_01(&decrypted));
  Eurydice_mut_borrow_ತುಂಡು_u8
  uu____0 =
    Eurydice_array_ಗಮ್ಯ_subslice_from_mut_5f1(&ಗಮ್ಯ_hash0,
      LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_ಗಾತ್ರ);
  Eurydice_ತುಂಡು_copy(uu____0,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_01(&ಕೀಲಿ_pair->ಬಹಿರಂಗ_ಕೀಲಿ.ಬಹಿರಂಗ_ಕೀಲಿ_hash),
    uint8_t);
  Eurydice_arr_c7
  hashed =
    libcrux_ml_kem_hash_functions_portable_G_4a_78(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_17(&ಗಮ್ಯ_hash0));
  Eurydice_borrow_ತುಂಡು_u8_x2
  uu____1 =
    Eurydice_ತುಂಡು_ವಿಭಜಿಸು_at(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_17(&hashed),
      LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_ಗಾತ್ರ,
      uint8_t,
      Eurydice_borrow_ತುಂಡು_u8_x2);
  Eurydice_borrow_ತುಂಡು_u8 shared_secret = uu____1.fst;
  Eurydice_borrow_ತುಂಡು_u8 pseudorandomness = uu____1.snd;
  Eurydice_arr_af
  ಗಮ್ಯ_hash =
    libcrux_ml_kem_utils_into_padded_array_66(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_01(&ಕೀಲಿ_pair->ಖಾಸಗಿ_ಕೀಲಿ.implicit_rejection_ಮೌಲ್ಯ));
  Eurydice_mut_borrow_ತುಂಡು_u8
  uu____2 =
    Eurydice_array_ಗಮ್ಯ_subslice_from_mut_5f2(&ಗಮ್ಯ_hash,
      LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_ಗಾತ್ರ);
  Eurydice_ತುಂಡು_copy(uu____2, libcrux_ml_kem_types_as_ref_c1_52(ciphertext), uint8_t);
  Eurydice_arr_ec
  implicit_rejection_shared_secret =
    libcrux_ml_kem_hash_functions_portable_PRF_4a_3b(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_81(&ಗಮ್ಯ_hash));
  Eurydice_arr_2b
  expected_ciphertext =
    libcrux_ml_kem_ind_cpa_encrypt_unpacked_d5(&ಕೀಲಿ_pair->ಬಹಿರಂಗ_ಕೀಲಿ.ind_cpa_ಬಹಿರಂಗ_ಕೀಲಿ,
      &decrypted,
      pseudorandomness);
  Eurydice_borrow_ತುಂಡು_u8 uu____3 = libcrux_ml_kem_types_as_ref_c1_52(ciphertext);
  uint8_t
  selector =
    libcrux_ml_kem_constant_ಸಮಯ_ops_compare_ciphertexts_ಒಳ_constant_ಸಮಯ(uu____3,
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_06(&expected_ciphertext));
  ಹಿಂತಿರುಗಿ
    libcrux_ml_kem_constant_ಸಮಯ_ops_select_shared_secret_ಒಳ_constant_ಸಮಯ(shared_secret,
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_01(&implicit_rejection_shared_secret),
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
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_ec
libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_decapsulate_19(
  ಸ್ಥಿರಾಂಕ libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_ಕೀಲಿ_Pair_Unpacked *ಕೀಲಿ_pair,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_2b *ciphertext
)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ind_cca_unpacked_decapsulate_0c(ಕೀಲಿ_pair, ciphertext);
}

/**
 Decapsulate ML-KEM 768 (unpacked)

 Generates an [`MlKemSharedSecret`].
 The input is a reference to an unpacked key pair of type [`MlKem768KeyPairUnpacked`]
 and an [`MlKem768Ciphertext`].
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_ec
libcrux_ml_kem_mlkem768_portable_unpacked_decapsulate(
  ಸ್ಥಿರಾಂಕ libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_ಕೀಲಿ_Pair_Unpacked *ಖಾಸಗಿ_ಕೀಲಿ,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_2b *ciphertext
)
{
  ಹಿಂತಿರುಗಿ
    libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_decapsulate_19(ಖಾಸಗಿ_ಕೀಲಿ,
      ciphertext);
}

/**
A monomorphic instance of libcrux_ml_kem.ind_cca.unpacked.encaps_prepare
with types libcrux_ml_kem_hash_functions_portable_PortableHash[[$3size_t]]
with const generics
- K= 3
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_c7
libcrux_ml_kem_ind_cca_unpacked_encaps_prepare_13(
  Eurydice_borrow_ತುಂಡು_u8 randomness,
  Eurydice_borrow_ತುಂಡು_u8 pk_hash
)
{
  Eurydice_arr_c7 ಗಮ್ಯ_hash = libcrux_ml_kem_utils_into_padded_array_c9(randomness);
  Eurydice_ತುಂಡು_copy(Eurydice_array_ಗಮ್ಯ_subslice_from_mut_5f1(&ಗಮ್ಯ_hash,
      LIBCRUX_ML_KEM_CONSTANTS_H_DIGEST_ಗಾತ್ರ),
    pk_hash,
    uint8_t);
  ಹಿಂತಿರುಗಿ
    libcrux_ml_kem_hash_functions_portable_G_4a_78(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_17(&ಗಮ್ಯ_hash));
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
ಸ್ಥಿರ KRML_MUSTINLINE tuple_f4
libcrux_ml_kem_ind_cca_unpacked_encapsulate_a7(
  ಸ್ಥಿರಾಂಕ libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_ಬಹಿರಂಗ_ಕೀಲಿ_Unpacked_51 *ಬಹಿರಂಗ_ಕೀಲಿ,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_ec *randomness
)
{
  Eurydice_arr_c7
  hashed =
    libcrux_ml_kem_ind_cca_unpacked_encaps_prepare_13(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_01(randomness),
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_01(&ಬಹಿರಂಗ_ಕೀಲಿ->ಬಹಿರಂಗ_ಕೀಲಿ_hash));
  Eurydice_borrow_ತುಂಡು_u8_x2
  uu____0 =
    Eurydice_ತುಂಡು_ವಿಭಜಿಸು_at(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_17(&hashed),
      LIBCRUX_ML_KEM_CONSTANTS_SHARED_SECRET_ಗಾತ್ರ,
      uint8_t,
      Eurydice_borrow_ತುಂಡು_u8_x2);
  Eurydice_borrow_ತುಂಡು_u8 shared_secret = uu____0.fst;
  Eurydice_borrow_ತುಂಡು_u8 pseudorandomness = uu____0.snd;
  Eurydice_arr_2b
  ciphertext =
    libcrux_ml_kem_ind_cpa_encrypt_unpacked_d5(&ಬಹಿರಂಗ_ಕೀಲಿ->ind_cpa_ಬಹಿರಂಗ_ಕೀಲಿ,
      randomness,
      pseudorandomness);
  Eurydice_arr_ec shared_secret_array = { .ದತ್ತಾಂಶ = { 0U } };
  Eurydice_ತುಂಡು_copy(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_01(&shared_secret_array),
    shared_secret,
    uint8_t);
  ಹಿಂತಿರುಗಿ
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
ಸ್ಥಿರ KRML_MUSTINLINE tuple_f4
libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_encapsulate_26(
  ಸ್ಥಿರಾಂಕ libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_ಬಹಿರಂಗ_ಕೀಲಿ_Unpacked_51 *ಬಹಿರಂಗ_ಕೀಲಿ,
  ಸ್ಥಿರಾಂಕ Eurydice_arr_ec *randomness
)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ind_cca_unpacked_encapsulate_a7(ಬಹಿರಂಗ_ಕೀಲಿ, randomness);
}

/**
 Encapsulate ML-KEM 768 (unpacked)

 Generates an ([`MlKem768Ciphertext`], [`MlKemSharedSecret`]) tuple.
 The input is a reference to an unpacked public key of type [`MlKem768PublicKeyUnpacked`],
 the SHA3-256 hash of this public key, and [`SHARED_SECRET_SIZE`] bytes of `randomness`.
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ tuple_f4
libcrux_ml_kem_mlkem768_portable_unpacked_encapsulate(
  ಸ್ಥಿರಾಂಕ libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_ಬಹಿರಂಗ_ಕೀಲಿ_Unpacked_51 *ಬಹಿರಂಗ_ಕೀಲಿ,
  Eurydice_arr_ec randomness
)
{
  ಹಿಂತಿರುಗಿ
    libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_encapsulate_26(ಬಹಿರಂಗ_ಕೀಲಿ,
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_9e
libcrux_ml_kem_ind_cca_unpacked_transpose_a_ಆವರಣ_call_mut_b4_68(
  ಶೂನ್ಯ **_,
  ಗಾತ್ರ_t tupled_ವಾದಗಳು
)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_polynomial_ZERO_d6_ea();
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_bb0
libcrux_ml_kem_ind_cca_unpacked_transpose_a_call_mut_22_68(ಶೂನ್ಯ **_, ಗಾತ್ರ_t tupled_ವಾದಗಳು)
{
  Eurydice_arr_bb0 arr_struct;
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    ಶೂನ್ಯ *lvalue = (ಶೂನ್ಯ *)0U;
    arr_struct.ದತ್ತಾಂಶ[i] =
      libcrux_ml_kem_ind_cca_unpacked_transpose_a_ಆವರಣ_call_mut_b4_68(&lvalue,
        i);
  }
  ಹಿಂತಿರುಗಿ arr_struct;
}

/**
This function found in impl {core::clone::Clone for libcrux_ml_kem::polynomial::PolynomialRingElement<Vector>[TraitClause@0, TraitClause@2]}
*/
/**
A monomorphic instance of libcrux_ml_kem.polynomial.clone_c1
with types libcrux_ml_kem_vector_portable_vector_type_PortableVector
with const generics

*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_9e
libcrux_ml_kem_polynomial_clone_c1_ea(ಸ್ಥಿರಾಂಕ Eurydice_arr_9e *self)
{
  ಹಿಂತಿರುಗಿ
    core_array__core__clone__Clone_for__T__N___clone((ಗಾತ್ರ_t)16U,
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_c10
libcrux_ml_kem_ind_cca_unpacked_transpose_a_68(Eurydice_arr_c10 ind_cpa_a)
{
  Eurydice_arr_c10 arr_struct;
  ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)3U; i++)
  {
    /* original Rust expression is not an lvalue in C */
    ಶೂನ್ಯ *lvalue = (ಶೂನ್ಯ *)0U;
    arr_struct.ದತ್ತಾಂಶ[i] = libcrux_ml_kem_ind_cca_unpacked_transpose_a_call_mut_22_68(&lvalue, i);
  }
  Eurydice_arr_c10 A = arr_struct;
  ಗಾಗಿ (ಗಾತ್ರ_t i0 = (ಗಾತ್ರ_t)0U; i0 < (ಗಾತ್ರ_t)3U; i0++)
  {
    ಗಾತ್ರ_t i1 = i0;
    ಗಾಗಿ (ಗಾತ್ರ_t i = (ಗಾತ್ರ_t)0U; i < (ಗಾತ್ರ_t)3U; i++)
    {
      ಗಾತ್ರ_t j = i;
      Eurydice_arr_9e uu____0 = libcrux_ml_kem_polynomial_clone_c1_ea(&ind_cpa_a.ದತ್ತಾಂಶ[j].ದತ್ತಾಂಶ[i1]);
      A.ದತ್ತಾಂಶ[i1].ದತ್ತಾಂಶ[j] = uu____0;
    }
  }
  ಹಿಂತಿರುಗಿ A;
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_kem_ind_cca_unpacked_generate_keypair_b8(
  Eurydice_arr_c7 randomness,
  libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_ಕೀಲಿ_Pair_Unpacked *ಹೊರಹೋಗು
)
{
  Eurydice_borrow_ತುಂಡು_u8
  ind_cpa_keypair_randomness =
    Eurydice_array_ಗಮ್ಯ_subslice_shared_d47(&randomness,
      (
        KRML_CLITERAL(core_ops_range_Range_87){
          .ಆರಂಭ = (ಗಾತ್ರ_t)0U,
          .ಕೊನೆ = LIBCRUX_ML_KEM_CONSTANTS_CPA_PKE_ಕೀಲಿ_GENERATION_ಬೀಜ_ಗಾತ್ರ
        }
      ));
  Eurydice_borrow_ತುಂಡು_u8
  implicit_rejection_ಮೌಲ್ಯ =
    Eurydice_array_ಗಮ್ಯ_subslice_from_shared_5f1(&randomness,
      LIBCRUX_ML_KEM_CONSTANTS_CPA_PKE_ಕೀಲಿ_GENERATION_ಬೀಜ_ಗಾತ್ರ);
  libcrux_ml_kem_ind_cpa_generate_keypair_unpacked_39(ind_cpa_keypair_randomness,
    &ಹೊರಹೋಗು->ಖಾಸಗಿ_ಕೀಲಿ.ind_cpa_ಖಾಸಗಿ_ಕೀಲಿ,
    &ಹೊರಹೋಗು->ಬಹಿರಂಗ_ಕೀಲಿ.ind_cpa_ಬಹಿರಂಗ_ಕೀಲಿ);
  Eurydice_arr_c10
  A = libcrux_ml_kem_ind_cca_unpacked_transpose_a_68(ಹೊರಹೋಗು->ಬಹಿರಂಗ_ಕೀಲಿ.ind_cpa_ಬಹಿರಂಗ_ಕೀಲಿ.A);
  ಹೊರಹೋಗು->ಬಹಿರಂಗ_ಕೀಲಿ.ind_cpa_ಬಹಿರಂಗ_ಕೀಲಿ.A = A;
  Eurydice_arr_5f
  pk_serialized =
    libcrux_ml_kem_ind_cpa_serialize_ಬಹಿರಂಗ_ಕೀಲಿ_b6(&ಹೊರಹೋಗು->ಬಹಿರಂಗ_ಕೀಲಿ.ind_cpa_ಬಹಿರಂಗ_ಕೀಲಿ.t_as_ntt,
      Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_01(&ಹೊರಹೋಗು->ಬಹಿರಂಗ_ಕೀಲಿ.ind_cpa_ಬಹಿರಂಗ_ಕೀಲಿ.ಬೀಜ_for_A));
  Eurydice_arr_ec
  uu____0 =
    libcrux_ml_kem_hash_functions_portable_H_4a_78(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_ff(&pk_serialized));
  ಹೊರಹೋಗು->ಬಹಿರಂಗ_ಕೀಲಿ.ಬಹಿರಂಗ_ಕೀಲಿ_hash = uu____0;
  Eurydice_arr_ec arr;
  ಸ್ಮರಣೆ_ನಕಲು(arr.ದತ್ತಾಂಶ, implicit_rejection_ಮೌಲ್ಯ.ptr, (ಗಾತ್ರ_t)32U * ಗಾತ್ರ (uint8_t));
  Eurydice_arr_ec
  uu____1 =
    core_ಫಲಿತಾಂಶ_unwrap_26_39((
        KRML_CLITERAL(core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_07){ .ಟ್ಯಾಗ್ = core_ಫಲಿತಾಂಶ_Ok, .val = { .case_Ok = arr } }
      ));
  ಹೊರಹೋಗು->ಖಾಸಗಿ_ಕೀಲಿ.implicit_rejection_ಮೌಲ್ಯ = uu____1;
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_generate_keypair_e9(
  Eurydice_arr_c7 randomness,
  libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_ಕೀಲಿ_Pair_Unpacked *ಹೊರಹೋಗು
)
{
  libcrux_ml_kem_ind_cca_unpacked_generate_keypair_b8(randomness, ಹೊರಹೋಗು);
}

/**
 Generate ML-KEM 768 Key Pair in "unpacked" form.
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_ml_kem_mlkem768_portable_unpacked_generate_ಕೀಲಿ_pair_mut(
  Eurydice_arr_c7 randomness,
  libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_ಕೀಲಿ_Pair_Unpacked *ಕೀಲಿ_pair
)
{
  libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_generate_keypair_e9(randomness,
    ಕೀಲಿ_pair);
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
ಸ್ಥಿರ KRML_MUSTINLINE libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_ಬಹಿರಂಗ_ಕೀಲಿ_Unpacked_51
libcrux_ml_kem_ind_cca_unpacked_default_30_68(ಶೂನ್ಯ)
{
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_ಬಹಿರಂಗ_ಕೀಲಿ_Unpacked_51){
        .ind_cpa_ಬಹಿರಂಗ_ಕೀಲಿ = libcrux_ml_kem_ind_cpa_unpacked_default_8b_68(),
        .ಬಹಿರಂಗ_ಕೀಲಿ_hash = { .ದತ್ತಾಂಶ = { 0U } }
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
ಸ್ಥಿರ KRML_MUSTINLINE libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_ಕೀಲಿ_Pair_Unpacked
libcrux_ml_kem_ind_cca_unpacked_default_7b_68(ಶೂನ್ಯ)
{
  libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_ಖಾಸಗಿ_ಕೀಲಿ_Unpacked_51
  uu____0 =
    {
      .ind_cpa_ಖಾಸಗಿ_ಕೀಲಿ = libcrux_ml_kem_ind_cpa_unpacked_default_70_68(),
      .implicit_rejection_ಮೌಲ್ಯ = { .ದತ್ತಾಂಶ = { 0U } }
    };
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_ಕೀಲಿ_Pair_Unpacked){
        .ಖಾಸಗಿ_ಕೀಲಿ = uu____0,
        .ಬಹಿರಂಗ_ಕೀಲಿ = libcrux_ml_kem_ind_cca_unpacked_default_30_68()
      }
    );
}

/**
 Generate ML-KEM 768 Key Pair in "unpacked" form.
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_ಕೀಲಿ_Pair_Unpacked
libcrux_ml_kem_mlkem768_portable_unpacked_generate_ಕೀಲಿ_pair(Eurydice_arr_c7 randomness)
{
  libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_ಕೀಲಿ_Pair_Unpacked
  ಕೀಲಿ_pair = libcrux_ml_kem_ind_cca_unpacked_default_7b_68();
  libcrux_ml_kem_mlkem768_portable_unpacked_generate_ಕೀಲಿ_pair_mut(randomness, &ಕೀಲಿ_pair);
  ಹಿಂತಿರುಗಿ ಕೀಲಿ_pair;
}

/**
 Create a new, empty unpacked key.
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_ಕೀಲಿ_Pair_Unpacked
libcrux_ml_kem_mlkem768_portable_unpacked_init_ಕೀಲಿ_pair(ಶೂನ್ಯ)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ind_cca_unpacked_default_7b_68();
}

/**
 Create a new, empty unpacked public key.
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_ಬಹಿರಂಗ_ಕೀಲಿ_Unpacked_51
libcrux_ml_kem_mlkem768_portable_unpacked_init_ಬಹಿರಂಗ_ಕೀಲಿ(ಶೂನ್ಯ)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ind_cca_unpacked_default_30_68();
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_kem_ind_cca_unpacked_ಕೀಲಿಗಳು_from_ಖಾಸಗಿ_ಕೀಲಿ_01(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_7d *ಖಾಸಗಿ_ಕೀಲಿ,
  libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_ಕೀಲಿ_Pair_Unpacked *ಕೀಲಿ_pair
)
{
  Eurydice_borrow_ತುಂಡು_u8_x4
  uu____0 =
    libcrux_ml_kem_types_unpack_ಖಾಸಗಿ_ಕೀಲಿ_64(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_51(ಖಾಸಗಿ_ಕೀಲಿ));
  Eurydice_borrow_ತುಂಡು_u8 ind_cpa_secret_ಕೀಲಿ = uu____0.fst;
  Eurydice_borrow_ತುಂಡು_u8 ind_cpa_ಬಹಿರಂಗ_ಕೀಲಿ = uu____0.snd;
  Eurydice_borrow_ತುಂಡು_u8 ind_cpa_ಬಹಿರಂಗ_ಕೀಲಿ_hash = uu____0.thd;
  Eurydice_borrow_ತುಂಡು_u8 implicit_rejection_ಮೌಲ್ಯ = uu____0.f3;
  libcrux_ml_kem_ind_cpa_deserialize_ಸದಿಶ_68(ind_cpa_secret_ಕೀಲಿ,
    &ಕೀಲಿ_pair->ಖಾಸಗಿ_ಕೀಲಿ.ind_cpa_ಖಾಸಗಿ_ಕೀಲಿ);
  libcrux_ml_kem_ind_cpa_build_unpacked_ಬಹಿರಂಗ_ಕೀಲಿ_mut_05(ind_cpa_ಬಹಿರಂಗ_ಕೀಲಿ,
    &ಕೀಲಿ_pair->ಬಹಿರಂಗ_ಕೀಲಿ.ind_cpa_ಬಹಿರಂಗ_ಕೀಲಿ);
  Eurydice_ತುಂಡು_copy(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_01(&ಕೀಲಿ_pair->ಬಹಿರಂಗ_ಕೀಲಿ.ಬಹಿರಂಗ_ಕೀಲಿ_hash),
    ind_cpa_ಬಹಿರಂಗ_ಕೀಲಿ_hash,
    uint8_t);
  Eurydice_ತುಂಡು_copy(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_01(&ಕೀಲಿ_pair->ಖಾಸಗಿ_ಕೀಲಿ.implicit_rejection_ಮೌಲ್ಯ),
    implicit_rejection_ಮೌಲ್ಯ,
    uint8_t);
  Eurydice_ತುಂಡು_copy(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_mut_01(&ಕೀಲಿ_pair->ಬಹಿರಂಗ_ಕೀಲಿ.ind_cpa_ಬಹಿರಂಗ_ಕೀಲಿ.ಬೀಜ_for_A),
    Eurydice_ತುಂಡು_subslice_from_shared_6d(ind_cpa_ಬಹಿರಂಗ_ಕೀಲಿ, (ಗಾತ್ರ_t)1152U),
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_keypair_from_ಖಾಸಗಿ_ಕೀಲಿ_71(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_7d *ಖಾಸಗಿ_ಕೀಲಿ,
  libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_ಕೀಲಿ_Pair_Unpacked *ಕೀಲಿ_pair
)
{
  libcrux_ml_kem_ind_cca_unpacked_ಕೀಲಿಗಳು_from_ಖಾಸಗಿ_ಕೀಲಿ_01(ಖಾಸಗಿ_ಕೀಲಿ, ಕೀಲಿ_pair);
}

/**
 Get an unpacked key from a private key.
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_ml_kem_mlkem768_portable_unpacked_ಕೀಲಿ_pair_from_ಖಾಸಗಿ_mut(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_7d *ಖಾಸಗಿ_ಕೀಲಿ,
  libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_ಕೀಲಿ_Pair_Unpacked *ಕೀಲಿ_pair
)
{
  libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_keypair_from_ಖಾಸಗಿ_ಕೀಲಿ_71(ಖಾಸಗಿ_ಕೀಲಿ,
    ಕೀಲಿ_pair);
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_kem_ind_cca_unpacked_serialized_ಖಾಸಗಿ_ಕೀಲಿ_mut_11_21(
  ಸ್ಥಿರಾಂಕ libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_ಕೀಲಿ_Pair_Unpacked *self,
  Eurydice_arr_7d *serialized
)
{
  libcrux_ml_kem_utils_extraction_helper_Keypair768
  uu____0 =
    libcrux_ml_kem_ind_cpa_serialize_unpacked_secret_ಕೀಲಿ_30(&self->ಬಹಿರಂಗ_ಕೀಲಿ.ind_cpa_ಬಹಿರಂಗ_ಕೀಲಿ,
      &self->ಖಾಸಗಿ_ಕೀಲಿ.ind_cpa_ಖಾಸಗಿ_ಕೀಲಿ);
  Eurydice_arr_0e ind_cpa_ಖಾಸಗಿ_ಕೀಲಿ = uu____0.fst;
  Eurydice_arr_5f ind_cpa_ಬಹಿರಂಗ_ಕೀಲಿ = uu____0.snd;
  libcrux_ml_kem_ind_cca_serialize_kem_secret_ಕೀಲಿ_mut_52(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_f4(&ind_cpa_ಖಾಸಗಿ_ಕೀಲಿ),
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_ff(&ind_cpa_ಬಹಿರಂಗ_ಕೀಲಿ),
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_01(&self->ಖಾಸಗಿ_ಕೀಲಿ.implicit_rejection_ಮೌಲ್ಯ),
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
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_7d
libcrux_ml_kem_ind_cca_unpacked_serialized_ಖಾಸಗಿ_ಕೀಲಿ_11_21(
  ಸ್ಥಿರಾಂಕ libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_ಕೀಲಿ_Pair_Unpacked *self
)
{
  Eurydice_arr_7d sk = libcrux_ml_kem_types_default_d3_79();
  libcrux_ml_kem_ind_cca_unpacked_serialized_ಖಾಸಗಿ_ಕೀಲಿ_mut_11_21(self, &sk);
  ಹಿಂತಿರುಗಿ sk;
}

/**
 Get the serialized private key.
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_7d
libcrux_ml_kem_mlkem768_portable_unpacked_ಕೀಲಿ_pair_serialized_ಖಾಸಗಿ_ಕೀಲಿ(
  ಸ್ಥಿರಾಂಕ libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_ಕೀಲಿ_Pair_Unpacked *ಕೀಲಿ_pair
)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ind_cca_unpacked_serialized_ಖಾಸಗಿ_ಕೀಲಿ_11_21(ಕೀಲಿ_pair);
}

/**
 Get the serialized private key.
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_ml_kem_mlkem768_portable_unpacked_ಕೀಲಿ_pair_serialized_ಖಾಸಗಿ_ಕೀಲಿ_mut(
  ಸ್ಥಿರಾಂಕ libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_ಕೀಲಿ_Pair_Unpacked *ಕೀಲಿ_pair,
  Eurydice_arr_7d *serialized
)
{
  libcrux_ml_kem_ind_cca_unpacked_serialized_ಖಾಸಗಿ_ಕೀಲಿ_mut_11_21(ಕೀಲಿ_pair, serialized);
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
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_5f
libcrux_ml_kem_ind_cca_unpacked_serialized_dd_b6(
  ಸ್ಥಿರಾಂಕ libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_ಬಹಿರಂಗ_ಕೀಲಿ_Unpacked_51 *self
)
{
  ಹಿಂತಿರುಗಿ
    libcrux_ml_kem_types_from_51_3d(libcrux_ml_kem_ind_cpa_serialize_ಬಹಿರಂಗ_ಕೀಲಿ_b6(&self->ind_cpa_ಬಹಿರಂಗ_ಕೀಲಿ.t_as_ntt,
        Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_01(&self->ind_cpa_ಬಹಿರಂಗ_ಕೀಲಿ.ಬೀಜ_for_A)));
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
ಸ್ಥಿರ KRML_MUSTINLINE Eurydice_arr_5f
libcrux_ml_kem_ind_cca_unpacked_serialized_ಬಹಿರಂಗ_ಕೀಲಿ_11_b6(
  ಸ್ಥಿರಾಂಕ libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_ಕೀಲಿ_Pair_Unpacked *self
)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ind_cca_unpacked_serialized_dd_b6(&self->ಬಹಿರಂಗ_ಕೀಲಿ);
}

/**
 Get the serialized public key.
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ Eurydice_arr_5f
libcrux_ml_kem_mlkem768_portable_unpacked_ಕೀಲಿ_pair_serialized_ಬಹಿರಂಗ_ಕೀಲಿ(
  ಸ್ಥಿರಾಂಕ libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_ಕೀಲಿ_Pair_Unpacked *ಕೀಲಿ_pair
)
{
  ಹಿಂತಿರುಗಿ libcrux_ml_kem_ind_cca_unpacked_serialized_ಬಹಿರಂಗ_ಕೀಲಿ_11_b6(ಕೀಲಿ_pair);
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_kem_ind_cca_unpacked_serialized_mut_dd_b6(
  ಸ್ಥಿರಾಂಕ libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_ಬಹಿರಂಗ_ಕೀಲಿ_Unpacked_51 *self,
  Eurydice_arr_5f *serialized
)
{
  libcrux_ml_kem_ind_cpa_serialize_ಬಹಿರಂಗ_ಕೀಲಿ_mut_b6(&self->ind_cpa_ಬಹಿರಂಗ_ಕೀಲಿ.t_as_ntt,
    Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_01(&self->ind_cpa_ಬಹಿರಂಗ_ಕೀಲಿ.ಬೀಜ_for_A),
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_kem_ind_cca_unpacked_serialized_ಬಹಿರಂಗ_ಕೀಲಿ_mut_11_b6(
  ಸ್ಥಿರಾಂಕ libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_ಕೀಲಿ_Pair_Unpacked *self,
  Eurydice_arr_5f *serialized
)
{
  libcrux_ml_kem_ind_cca_unpacked_serialized_mut_dd_b6(&self->ಬಹಿರಂಗ_ಕೀಲಿ, serialized);
}

/**
 Get the serialized public key.
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_ml_kem_mlkem768_portable_unpacked_ಕೀಲಿ_pair_serialized_ಬಹಿರಂಗ_ಕೀಲಿ_mut(
  ಸ್ಥಿರಾಂಕ libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_ಕೀಲಿ_Pair_Unpacked *ಕೀಲಿ_pair,
  Eurydice_arr_5f *serialized
)
{
  libcrux_ml_kem_ind_cca_unpacked_serialized_ಬಹಿರಂಗ_ಕೀಲಿ_mut_11_b6(ಕೀಲಿ_pair, serialized);
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_ಬಹಿರಂಗ_ಕೀಲಿ_Unpacked_51
libcrux_ml_kem_ind_cpa_unpacked_clone_91_68(
  ಸ್ಥಿರಾಂಕ libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_ಬಹಿರಂಗ_ಕೀಲಿ_Unpacked_51 *self
)
{
  Eurydice_arr_bb0
  uu____0 =
    core_array__core__clone__Clone_for__T__N___clone((ಗಾತ್ರ_t)3U,
      &self->t_as_ntt,
      Eurydice_arr_9e,
      Eurydice_arr_bb0);
  Eurydice_arr_ec
  uu____1 =
    core_array__core__clone__Clone_for__T__N___clone((ಗಾತ್ರ_t)32U,
      &self->ಬೀಜ_for_A,
      uint8_t,
      Eurydice_arr_ec);
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_ಬಹಿರಂಗ_ಕೀಲಿ_Unpacked_51){
        .t_as_ntt = uu____0,
        .ಬೀಜ_for_A = uu____1,
        .A = core_array__core__clone__Clone_for__T__N___clone((ಗಾತ್ರ_t)3U,
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
ಸ್ಥಿರ ಸಾಲೊಳಗೆ libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_ಬಹಿರಂಗ_ಕೀಲಿ_Unpacked_51
libcrux_ml_kem_ind_cca_unpacked_clone_d7_68(
  ಸ್ಥಿರಾಂಕ libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_ಬಹಿರಂಗ_ಕೀಲಿ_Unpacked_51 *self
)
{
  libcrux_ml_kem_ind_cpa_unpacked_Ind_Cpa_ಬಹಿರಂಗ_ಕೀಲಿ_Unpacked_51
  uu____0 = libcrux_ml_kem_ind_cpa_unpacked_clone_91_68(&self->ind_cpa_ಬಹಿರಂಗ_ಕೀಲಿ);
  ಹಿಂತಿರುಗಿ
    (
      KRML_CLITERAL(libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_ಬಹಿರಂಗ_ಕೀಲಿ_Unpacked_51){
        .ind_cpa_ಬಹಿರಂಗ_ಕೀಲಿ = uu____0,
        .ಬಹಿರಂಗ_ಕೀಲಿ_hash = core_array__core__clone__Clone_for__T__N___clone((ಗಾತ್ರ_t)32U,
          &self->ಬಹಿರಂಗ_ಕೀಲಿ_hash,
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
ಸ್ಥಿರ KRML_MUSTINLINE ಸ್ಥಿರಾಂಕ
libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_ಬಹಿರಂಗ_ಕೀಲಿ_Unpacked_51
*libcrux_ml_kem_ind_cca_unpacked_ಬಹಿರಂಗ_ಕೀಲಿ_11_68(
  ಸ್ಥಿರಾಂಕ libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_ಕೀಲಿ_Pair_Unpacked *self
)
{
  ಹಿಂತಿರುಗಿ &self->ಬಹಿರಂಗ_ಕೀಲಿ;
}

/**
 Get the unpacked public key.
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_ml_kem_mlkem768_portable_unpacked_ಬಹಿರಂಗ_ಕೀಲಿ(
  ಸ್ಥಿರಾಂಕ libcrux_ml_kem_mlkem768_portable_unpacked_Ml_Kem768_ಕೀಲಿ_Pair_Unpacked *ಕೀಲಿ_pair,
  libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_ಬಹಿರಂಗ_ಕೀಲಿ_Unpacked_51 *pk
)
{
  libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_ಬಹಿರಂಗ_ಕೀಲಿ_Unpacked_51
  uu____0 =
    libcrux_ml_kem_ind_cca_unpacked_clone_d7_68(libcrux_ml_kem_ind_cca_unpacked_ಬಹಿರಂಗ_ಕೀಲಿ_11_68(ಕೀಲಿ_pair));
  pk[0U] = uu____0;
}

/**
 Get the serialized public key.
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_ml_kem_mlkem768_portable_unpacked_serialized_ಬಹಿರಂಗ_ಕೀಲಿ(
  ಸ್ಥಿರಾಂಕ libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_ಬಹಿರಂಗ_ಕೀಲಿ_Unpacked_51 *ಬಹಿರಂಗ_ಕೀಲಿ,
  Eurydice_arr_5f *serialized
)
{
  libcrux_ml_kem_ind_cca_unpacked_serialized_mut_dd_b6(ಬಹಿರಂಗ_ಕೀಲಿ, serialized);
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_kem_ind_cca_unpacked_unpack_ಬಹಿರಂಗ_ಕೀಲಿ_22(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_5f *ಬಹಿರಂಗ_ಕೀಲಿ,
  libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_ಬಹಿರಂಗ_ಕೀಲಿ_Unpacked_51 *unpacked_ಬಹಿರಂಗ_ಕೀಲಿ
)
{
  Eurydice_borrow_ತುಂಡು_u8
  uu____0 = Eurydice_array_ಗಮ್ಯ_subslice_ಗಮ್ಯ_shared_210(ಬಹಿರಂಗ_ಕೀಲಿ, (ಗಾತ್ರ_t)1152U);
  libcrux_ml_kem_serialize_deserialize_ring_elements_reduced_68(uu____0,
    &unpacked_ಬಹಿರಂಗ_ಕೀಲಿ->ind_cpa_ಬಹಿರಂಗ_ಕೀಲಿ.t_as_ntt);
  unpacked_ಬಹಿರಂಗ_ಕೀಲಿ->ind_cpa_ಬಹಿರಂಗ_ಕೀಲಿ.ಬೀಜ_for_A =
    libcrux_ml_kem_utils_into_padded_array_ce(Eurydice_array_ಗಮ್ಯ_subslice_from_shared_5f2(ಬಹಿರಂಗ_ಕೀಲಿ,
        (ಗಾತ್ರ_t)1152U));
  Eurydice_arr_c10 *uu____2 = &unpacked_ಬಹಿರಂಗ_ಕೀಲಿ->ind_cpa_ಬಹಿರಂಗ_ಕೀಲಿ.A;
  /* original Rust expression is not an lvalue in C */
  Eurydice_arr_31
  lvalue =
    libcrux_ml_kem_utils_into_padded_array_de(Eurydice_array_ಗಮ್ಯ_subslice_from_shared_5f2(ಬಹಿರಂಗ_ಕೀಲಿ,
        (ಗಾತ್ರ_t)1152U));
  libcrux_ml_kem_ಮಾತೃಕೆ_sample_ಮಾತೃಕೆ_A_91(uu____2, &lvalue, false);
  Eurydice_arr_ec
  uu____3 =
    libcrux_ml_kem_hash_functions_portable_H_4a_78(Eurydice_array_ಗಮ್ಯ_ತುಂಡು_shared_ff(libcrux_ml_kem_types_as_ತುಂಡು_e6_3d(ಬಹಿರಂಗ_ಕೀಲಿ)));
  unpacked_ಬಹಿರಂಗ_ಕೀಲಿ->ಬಹಿರಂಗ_ಕೀಲಿ_hash = uu____3;
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
ಸ್ಥಿರ KRML_MUSTINLINE ಶೂನ್ಯ
libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_unpack_ಬಹಿರಂಗ_ಕೀಲಿ_d3(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_5f *ಬಹಿರಂಗ_ಕೀಲಿ,
  libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_ಬಹಿರಂಗ_ಕೀಲಿ_Unpacked_51 *unpacked_ಬಹಿರಂಗ_ಕೀಲಿ
)
{
  libcrux_ml_kem_ind_cca_unpacked_unpack_ಬಹಿರಂಗ_ಕೀಲಿ_22(ಬಹಿರಂಗ_ಕೀಲಿ, unpacked_ಬಹಿರಂಗ_ಕೀಲಿ);
}

/**
 Get the unpacked public key.
*/
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
libcrux_ml_kem_mlkem768_portable_unpacked_unpacked_ಬಹಿರಂಗ_ಕೀಲಿ(
  ಸ್ಥಿರಾಂಕ Eurydice_arr_5f *ಬಹಿರಂಗ_ಕೀಲಿ,
  libcrux_ml_kem_ind_cca_unpacked_Ml_Kem_ಬಹಿರಂಗ_ಕೀಲಿ_Unpacked_51 *unpacked_ಬಹಿರಂಗ_ಕೀಲಿ
)
{
  libcrux_ml_kem_ind_cca_instantiations_portable_unpacked_unpack_ಬಹಿರಂಗ_ಕೀಲಿ_d3(ಬಹಿರಂಗ_ಕೀಲಿ,
    unpacked_ಬಹಿರಂಗ_ಕೀಲಿ);
}

#ಆದರೆ defined(__cplusplus)
}
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿಸು libcrux_mlkem768_portable_H_DEFINED
#ಆದರೆ_ಅಂತ್ಯ /* libcrux_mlkem768_portable_H */


/* rename some types to be a bit more ergonomic */

/* ML-KEM 768 */
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ Eurydice_arr_c7 libcrux_mlkem768_keypair_rnd;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ Eurydice_arr_ec libcrux_mlkem768_enc_rnd;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ libcrux_ml_kem_mlkem768_Ml_Kem768_ಕೀಲಿ_Pair libcrux_mlkem768_keypair;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ Eurydice_arr_5f libcrux_mlkem768_pk;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ Eurydice_arr_7d libcrux_mlkem768_sk;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ Eurydice_arr_2b libcrux_mlkem768_ciphertext;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ tuple_f4 libcrux_mlkem768_enc_ಫಲಿತಾಂಶ;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ Eurydice_arr_ec libcrux_mlkem768_dec_ಫಲಿತಾಂಶ;
/* ML-DSA 44 */
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ Eurydice_arr_ec libcrux_mldsa44_keypair_rnd;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ libcrux_ml_dsa_ml_dsa_generic_ml_dsa_44_MLDSA44_ಕೀಲಿ_Pair
    libcrux_mldsa44_keypair;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ Eurydice_arr_10 libcrux_mldsa44_sk;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ Eurydice_arr_02 libcrux_mldsa44_pk;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ Eurydice_borrow_ತುಂಡು_u8 libcrux_mldsa44_ಸಂದೇಶ;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ Eurydice_arr_ec libcrux_mldsa44_sign_rnd;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_48 libcrux_mldsa44_sign_ಫಲಿತಾಂಶ;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41 libcrux_mldsa44_verify_ಫಲಿತಾಂಶ;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ Eurydice_arr_85 libcrux_mldsa44_signature;
/* ML-DSA 65 */
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ Eurydice_arr_ec libcrux_mldsa65_keypair_rnd;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ libcrux_ml_dsa_ml_dsa_generic_ml_dsa_65_MLDSA65_ಕೀಲಿ_Pair
    libcrux_mldsa65_keypair;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ Eurydice_arr_24 libcrux_mldsa65_sk;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ Eurydice_arr_29 libcrux_mldsa65_pk;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ Eurydice_borrow_ತುಂಡು_u8 libcrux_mldsa65_ಸಂದೇಶ;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ Eurydice_arr_ec libcrux_mldsa65_sign_rnd;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_8c libcrux_mldsa65_sign_ಫಲಿತಾಂಶ;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41 libcrux_mldsa65_verify_ಫಲಿತಾಂಶ;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ Eurydice_arr_0c libcrux_mldsa65_signature;
/* ML-DSA 87 */
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ Eurydice_arr_ec libcrux_mldsa87_keypair_rnd;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ libcrux_ml_dsa_ml_dsa_generic_ml_dsa_87_MLDSA87_ಕೀಲಿ_Pair
    libcrux_mldsa87_keypair;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ Eurydice_arr_e2 libcrux_mldsa87_sk;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ Eurydice_arr_43 libcrux_mldsa87_pk;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ Eurydice_borrow_ತುಂಡು_u8 libcrux_mldsa87_ಸಂದೇಶ;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ Eurydice_arr_ec libcrux_mldsa87_sign_rnd;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_8b libcrux_mldsa87_sign_ಫಲಿತಾಂಶ;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ core_ಫಲಿತಾಂಶ_ಫಲಿತಾಂಶ_41 libcrux_mldsa87_verify_ಫಲಿತಾಂಶ;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ Eurydice_arr_93 libcrux_mldsa87_signature;

#ವ್ಯಾಖ್ಯಾನಿಸು LIBCRUX_ಫಲಿತಾಂಶ_OK	core_ಫಲಿತಾಂಶ_Ok

