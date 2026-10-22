/*	$OpenBSD: queue.h,v 1.45 2018/07/12 14:22:54 sashan Exp $	*/
/*	$NetBSD: queue.h,v 1.11 1996/05/16 05:17:14 mycroft Exp $	*/

/*
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)queue.h	8.5 (Berkeley) 8/20/94
 */

/* OPENBSD ORIGINAL: sys/sys/queue.h */

#اگر_تعریف_نشده	FAKE_صف_H
#تعریف_کن	FAKE_صف_H

/*
 * Require for OS/X and other platforms that have old/broken/incomplete
 * <sys/queue.h>.
 */
#لغو_تعریف CIRCLEQ_EMPTY
#لغو_تعریف CIRCLEQ_انتها
#لغو_تعریف CIRCLEQ_ENTRY
#لغو_تعریف CIRCLEQ_FIRST
#لغو_تعریف CIRCLEQ_FOREACH
#لغو_تعریف CIRCLEQ_FOREACH_REVERSE
#لغو_تعریف CIRCLEQ_HEAD
#لغو_تعریف CIRCLEQ_HEAD_INITIALIZER
#لغو_تعریف CIRCLEQ_INIT
#لغو_تعریف CIRCLEQ_INSERT_AFTER
#لغو_تعریف CIRCLEQ_INSERT_BEFORE
#لغو_تعریف CIRCLEQ_INSERT_HEAD
#لغو_تعریف CIRCLEQ_INSERT_TAIL
#لغو_تعریف CIRCLEQ_LAST
#لغو_تعریف CIRCLEQ_NEXT
#لغو_تعریف CIRCLEQ_PREV
#لغو_تعریف CIRCLEQ_REMOVE
#لغو_تعریف CIRCLEQ_REPLACE
#لغو_تعریف LIST_EMPTY
#لغو_تعریف LIST_انتها
#لغو_تعریف LIST_ENTRY
#لغو_تعریف LIST_FIRST
#لغو_تعریف LIST_FOREACH
#لغو_تعریف LIST_FOREACH_امن
#لغو_تعریف LIST_HEAD
#لغو_تعریف LIST_HEAD_INITIALIZER
#لغو_تعریف LIST_INIT
#لغو_تعریف LIST_INSERT_AFTER
#لغو_تعریف LIST_INSERT_BEFORE
#لغو_تعریف LIST_INSERT_HEAD
#لغو_تعریف LIST_NEXT
#لغو_تعریف LIST_REMOVE
#لغو_تعریف LIST_REPLACE
#لغو_تعریف SIMPLEQ_CONCAT
#لغو_تعریف SIMPLEQ_EMPTY
#لغو_تعریف SIMPLEQ_انتها
#لغو_تعریف SIMPLEQ_ENTRY
#لغو_تعریف SIMPLEQ_FIRST
#لغو_تعریف SIMPLEQ_FOREACH
#لغو_تعریف SIMPLEQ_FOREACH_امن
#لغو_تعریف SIMPLEQ_HEAD
#لغو_تعریف SIMPLEQ_HEAD_INITIALIZER
#لغو_تعریف SIMPLEQ_INIT
#لغو_تعریف SIMPLEQ_INSERT_AFTER
#لغو_تعریف SIMPLEQ_INSERT_HEAD
#لغو_تعریف SIMPLEQ_INSERT_TAIL
#لغو_تعریف SIMPLEQ_NEXT
#لغو_تعریف SIMPLEQ_REMOVE_AFTER
#لغو_تعریف SIMPLEQ_REMOVE_HEAD
#لغو_تعریف SLIST_EMPTY
#لغو_تعریف SLIST_انتها
#لغو_تعریف SLIST_ENTRY
#لغو_تعریف SLIST_FIRST
#لغو_تعریف SLIST_FOREACH
#لغو_تعریف SLIST_FOREACH_PREVPTR
#لغو_تعریف SLIST_FOREACH_امن
#لغو_تعریف SLIST_HEAD
#لغو_تعریف SLIST_HEAD_INITIALIZER
#لغو_تعریف SLIST_INIT
#لغو_تعریف SLIST_INSERT_AFTER
#لغو_تعریف SLIST_INSERT_HEAD
#لغو_تعریف SLIST_NEXT
#لغو_تعریف SLIST_REMOVE
#لغو_تعریف SLIST_REMOVE_AFTER
#لغو_تعریف SLIST_REMOVE_HEAD
#لغو_تعریف SLIST_REMOVE_بعدی
#لغو_تعریف TAILQ_CONCAT
#لغو_تعریف TAILQ_EMPTY
#لغو_تعریف TAILQ_انتها
#لغو_تعریف TAILQ_ENTRY
#لغو_تعریف TAILQ_FIRST
#لغو_تعریف TAILQ_FOREACH
#لغو_تعریف TAILQ_FOREACH_معکوس
#لغو_تعریف TAILQ_FOREACH_معکوس_امن
#لغو_تعریف TAILQ_FOREACH_امن
#لغو_تعریف TAILQ_HEAD
#لغو_تعریف TAILQ_HEAD_INITIALIZER
#لغو_تعریف TAILQ_INIT
#لغو_تعریف TAILQ_INSERT_AFTER
#لغو_تعریف TAILQ_INSERT_BEFORE
#لغو_تعریف TAILQ_INSERT_HEAD
#لغو_تعریف TAILQ_INSERT_TAIL
#لغو_تعریف TAILQ_LAST
#لغو_تعریف TAILQ_NEXT
#لغو_تعریف TAILQ_PREV
#لغو_تعریف TAILQ_REMOVE
#لغو_تعریف TAILQ_REPLACE

/*
 * This file defines five types of data structures: singly-linked lists,
 * lists, simple queues, tail queues and XOR simple queues.
 *
 *
 * A singly-linked list is headed by a single forward pointer. The elements
 * are singly linked for minimum space and pointer manipulation overhead at
 * the expense of O(n) removal for arbitrary elements. New elements can be
 * added to the list after an existing element or at the head of the list.
 * Elements being removed from the head of the list should use the explicit
 * macro for this purpose for optimum efficiency. A singly-linked list may
 * only be traversed in the forward direction.  Singly-linked lists are ideal
 * for applications with large datasets and few or no removals or for
 * implementing a LIFO queue.
 *
 * A list is headed by a single forward pointer (or an array of forward
 * pointers for a hash table header). The elements are doubly linked
 * so that an arbitrary element can be removed without a need to
 * traverse the list. New elements can be added to the list before
 * or after an existing element or at the head of the list. A list
 * may only be traversed in the forward direction.
 *
 * A simple queue is headed by a pair of pointers, one to the head of the
 * list and the other to the tail of the list. The elements are singly
 * linked to save space, so elements can only be removed from the
 * head of the list. New elements can be added to the list before or after
 * an existing element, at the head of the list, or at the end of the
 * list. A simple queue may only be traversed in the forward direction.
 *
 * A tail queue is headed by a pair of pointers, one to the head of the
 * list and the other to the tail of the list. The elements are doubly
 * linked so that an arbitrary element can be removed without a need to
 * traverse the list. New elements can be added to the list before or
 * after an existing element, at the head of the list, or at the end of
 * the list. A tail queue may be traversed in either direction.
 *
 * An XOR simple queue is used in the same way as a regular simple queue.
 * The difference is that the head structure also includes a "cookie" that
 * is XOR'd with the queue pointer (first, last or next) to generate the
 * real pointer value.
 *
 * For details on the use of these macros, see the queue(3) manual page.
 */

#إذا defined(صف_MACRO_DEBUG) || (defined(_KERNEL) && defined(DIAGNOSTIC))
#تعریف_کن _Q_INVALID ((فراغ *)-1)
#تعریف_کن _Q_INVALIDATE(a) (a) = _Q_INVALID
#وإلا
#تعریف_کن _Q_INVALIDATE(a)
#پایان_اگر

/*
 * Singly-linked List definitions.
 */
#تعریف_کن SLIST_HEAD(name, type)						\
بنية name {								\
	بنية type *slh_اولی;	/* first element */			\
}

#تعریف_کن	SLIST_HEAD_INITIALIZER(سر)					\
	{ عدم }

#تعریف_کن SLIST_ENTRY(type)						\
بنية {								\
	بنية type *sle_بعدی;	/* next element */			\
}

/*
 * Singly-linked List access methods.
 */
#تعریف_کن	SLIST_FIRST(سر)	((سر)->slh_اولی)
#تعریف_کن	SLIST_انتها(سر)		عدم
#تعریف_کن	SLIST_EMPTY(سر)	(SLIST_FIRST(سر) == SLIST_انتها(سر))
#تعریف_کن	SLIST_NEXT(elm, فیلد)	((elm)->فیلد.sle_بعدی)

#تعریف_کن	SLIST_FOREACH(var, سر, فیلد)					\
	لكل((var) = SLIST_FIRST(سر);					\
	    (var) != SLIST_انتها(سر);					\
	    (var) = SLIST_NEXT(var, فیلد))

#تعریف_کن	SLIST_FOREACH_امن(var, سر, فیلد, tvar)			\
	لكل ((var) = SLIST_FIRST(سر);				\
	    (var) && ((tvar) = SLIST_NEXT(var, فیلد), 1);		\
	    (var) = (tvar))

/*
 * Singly-linked List functions.
 */
#تعریف_کن	SLIST_INIT(سر) {						\
	SLIST_FIRST(سر) = SLIST_انتها(سر);				\
}

#تعریف_کن	SLIST_INSERT_AFTER(slistelm, elm, فیلد) افعل {			\
	(elm)->فیلد.sle_بعدی = (slistelm)->فیلد.sle_بعدی;		\
	(slistelm)->فیلد.sle_بعدی = (elm);				\
} طالما (0)

#تعریف_کن	SLIST_INSERT_HEAD(سر, elm, فیلد) افعل {			\
	(elm)->فیلد.sle_بعدی = (سر)->slh_اولی;			\
	(سر)->slh_اولی = (elm);					\
} طالما (0)

#تعریف_کن	SLIST_REMOVE_AFTER(elm, فیلد) افعل {				\
	(elm)->فیلد.sle_بعدی = (elm)->فیلد.sle_بعدی->فیلد.sle_بعدی;	\
} طالما (0)

#تعریف_کن	SLIST_REMOVE_HEAD(سر, فیلد) افعل {				\
	(سر)->slh_اولی = (سر)->slh_اولی->فیلد.sle_بعدی;		\
} طالما (0)

#تعریف_کن SLIST_REMOVE(سر, elm, type, فیلد) افعل {			\
	إذا ((سر)->slh_اولی == (elm)) {				\
		SLIST_REMOVE_HEAD((سر), فیلد);			\
	} وإلا {							\
		بنية type *curelm = (سر)->slh_اولی;		\
									\
		طالما (curelm->فیلد.sle_بعدی != (elm))			\
			curelm = curelm->فیلد.sle_بعدی;		\
		curelm->فیلد.sle_بعدی =				\
		    curelm->فیلد.sle_بعدی->فیلد.sle_بعدی;		\
	}								\
	_Q_INVALIDATE((elm)->فیلد.sle_بعدی);				\
} طالما (0)

/*
 * List definitions.
 */
#تعریف_کن LIST_HEAD(name, type)						\
بنية name {								\
	بنية type *lh_اولی;	/* first element */			\
}

#تعریف_کن LIST_HEAD_INITIALIZER(سر)					\
	{ عدم }

#تعریف_کن LIST_ENTRY(type)						\
بنية {								\
	بنية type *le_بعدی;	/* next element */			\
	بنية type **le_prev;	/* address of previous next element */	\
}

/*
 * List access methods.
 */
#تعریف_کن	LIST_FIRST(سر)		((سر)->lh_اولی)
#تعریف_کن	LIST_انتها(سر)			عدم
#تعریف_کن	LIST_EMPTY(سر)		(LIST_FIRST(سر) == LIST_انتها(سر))
#تعریف_کن	LIST_NEXT(elm, فیلد)		((elm)->فیلد.le_بعدی)

#تعریف_کن LIST_FOREACH(var, سر, فیلد)					\
	لكل((var) = LIST_FIRST(سر);					\
	    (var)!= LIST_انتها(سر);					\
	    (var) = LIST_NEXT(var, فیلد))

#تعریف_کن	LIST_FOREACH_امن(var, سر, فیلد, tvar)			\
	لكل ((var) = LIST_FIRST(سر);				\
	    (var) && ((tvar) = LIST_NEXT(var, فیلد), 1);		\
	    (var) = (tvar))

/*
 * List functions.
 */
#تعریف_کن	LIST_INIT(سر) افعل {						\
	LIST_FIRST(سر) = LIST_انتها(سر);				\
} طالما (0)

#تعریف_کن LIST_INSERT_AFTER(listelm, elm, فیلد) افعل {			\
	إذا (((elm)->فیلد.le_بعدی = (listelm)->فیلد.le_بعدی) != عدم)	\
		(listelm)->فیلد.le_بعدی->فیلد.le_prev =		\
		    &(elm)->فیلد.le_بعدی;				\
	(listelm)->فیلد.le_بعدی = (elm);				\
	(elm)->فیلد.le_prev = &(listelm)->فیلد.le_بعدی;		\
} طالما (0)

#تعریف_کن	LIST_INSERT_BEFORE(listelm, elm, فیلد) افعل {			\
	(elm)->فیلد.le_prev = (listelm)->فیلد.le_prev;		\
	(elm)->فیلد.le_بعدی = (listelm);				\
	*(listelm)->فیلد.le_prev = (elm);				\
	(listelm)->فیلد.le_prev = &(elm)->فیلد.le_بعدی;		\
} طالما (0)

#تعریف_کن LIST_INSERT_HEAD(سر, elm, فیلد) افعل {				\
	إذا (((elm)->فیلد.le_بعدی = (سر)->lh_اولی) != عدم)		\
		(سر)->lh_اولی->فیلد.le_prev = &(elm)->فیلد.le_بعدی;\
	(سر)->lh_اولی = (elm);					\
	(elm)->فیلد.le_prev = &(سر)->lh_اولی;			\
} طالما (0)

#تعریف_کن LIST_REMOVE(elm, فیلد) افعل {					\
	إذا ((elm)->فیلد.le_بعدی != عدم)				\
		(elm)->فیلد.le_بعدی->فیلد.le_prev =			\
		    (elm)->فیلد.le_prev;				\
	*(elm)->فیلد.le_prev = (elm)->فیلد.le_بعدی;			\
	_Q_INVALIDATE((elm)->فیلد.le_prev);				\
	_Q_INVALIDATE((elm)->فیلد.le_بعدی);				\
} طالما (0)

#تعریف_کن LIST_REPLACE(elm, elm2, فیلد) افعل {				\
	إذا (((elm2)->فیلد.le_بعدی = (elm)->فیلد.le_بعدی) != عدم)	\
		(elm2)->فیلد.le_بعدی->فیلد.le_prev =			\
		    &(elm2)->فیلد.le_بعدی;				\
	(elm2)->فیلد.le_prev = (elm)->فیلد.le_prev;			\
	*(elm2)->فیلد.le_prev = (elm2);				\
	_Q_INVALIDATE((elm)->فیلد.le_prev);				\
	_Q_INVALIDATE((elm)->فیلد.le_بعدی);				\
} طالما (0)

/*
 * Simple queue definitions.
 */
#تعریف_کن SIMPLEQ_HEAD(name, type)					\
بنية name {								\
	بنية type *sqh_اولی;	/* first element */			\
	بنية type **sqh_آخرین;	/* addr of last next element */		\
}

#تعریف_کن SIMPLEQ_HEAD_INITIALIZER(سر)					\
	{ عدم, &(سر).sqh_اولی }

#تعریف_کن SIMPLEQ_ENTRY(type)						\
بنية {								\
	بنية type *sqe_بعدی;	/* next element */			\
}

/*
 * Simple queue access methods.
 */
#تعریف_کن	SIMPLEQ_FIRST(سر)	    ((سر)->sqh_اولی)
#تعریف_کن	SIMPLEQ_انتها(سر)	    عدم
#تعریف_کن	SIMPLEQ_EMPTY(سر)	    (SIMPLEQ_FIRST(سر) == SIMPLEQ_انتها(سر))
#تعریف_کن	SIMPLEQ_NEXT(elm, فیلد)    ((elm)->فیلد.sqe_بعدی)

#تعریف_کن SIMPLEQ_FOREACH(var, سر, فیلد)				\
	لكل((var) = SIMPLEQ_FIRST(سر);				\
	    (var) != SIMPLEQ_انتها(سر);					\
	    (var) = SIMPLEQ_NEXT(var, فیلد))

#تعریف_کن	SIMPLEQ_FOREACH_امن(var, سر, فیلد, tvar)			\
	لكل ((var) = SIMPLEQ_FIRST(سر);				\
	    (var) && ((tvar) = SIMPLEQ_NEXT(var, فیلد), 1);		\
	    (var) = (tvar))

/*
 * Simple queue functions.
 */
#تعریف_کن	SIMPLEQ_INIT(سر) افعل {						\
	(سر)->sqh_اولی = عدم;					\
	(سر)->sqh_آخرین = &(سر)->sqh_اولی;				\
} طالما (0)

#تعریف_کن SIMPLEQ_INSERT_HEAD(سر, elm, فیلد) افعل {			\
	إذا (((elm)->فیلد.sqe_بعدی = (سر)->sqh_اولی) == عدم)	\
		(سر)->sqh_آخرین = &(elm)->فیلد.sqe_بعدی;		\
	(سر)->sqh_اولی = (elm);					\
} طالما (0)

#تعریف_کن SIMPLEQ_INSERT_TAIL(سر, elm, فیلد) افعل {			\
	(elm)->فیلد.sqe_بعدی = عدم;					\
	*(سر)->sqh_آخرین = (elm);					\
	(سر)->sqh_آخرین = &(elm)->فیلد.sqe_بعدی;			\
} طالما (0)

#تعریف_کن SIMPLEQ_INSERT_AFTER(سر, listelm, elm, فیلد) افعل {		\
	إذا (((elm)->فیلد.sqe_بعدی = (listelm)->فیلد.sqe_بعدی) == عدم)\
		(سر)->sqh_آخرین = &(elm)->فیلد.sqe_بعدی;		\
	(listelm)->فیلد.sqe_بعدی = (elm);				\
} طالما (0)

#تعریف_کن SIMPLEQ_REMOVE_HEAD(سر, فیلد) افعل {			\
	إذا (((سر)->sqh_اولی = (سر)->sqh_اولی->فیلد.sqe_بعدی) == عدم) \
		(سر)->sqh_آخرین = &(سر)->sqh_اولی;			\
} طالما (0)

#تعریف_کن SIMPLEQ_REMOVE_AFTER(سر, elm, فیلد) افعل {			\
	إذا (((elm)->فیلد.sqe_بعدی = (elm)->فیلد.sqe_بعدی->فیلد.sqe_بعدی) \
	    == عدم)							\
		(سر)->sqh_آخرین = &(elm)->فیلد.sqe_بعدی;		\
} طالما (0)

#تعریف_کن SIMPLEQ_CONCAT(head1, head2) افعل {				\
	إذا (!SIMPLEQ_EMPTY((head2))) {					\
		*(head1)->sqh_آخرین = (head2)->sqh_اولی;		\
		(head1)->sqh_آخرین = (head2)->sqh_آخرین;			\
		SIMPLEQ_INIT((head2));					\
	}								\
} طالما (0)

/*
 * XOR Simple queue definitions.
 */
#تعریف_کن XSIMPLEQ_سر(name, type)					\
بنية name {								\
	بنية type *sqx_اولی;	/* first element */			\
	بنية type **sqx_آخرین;	/* addr of last next element */		\
	بیعلامت دراز sqx_cookie;					\
}

#تعریف_کن XSIMPLEQ_مدخل(type)						\
بنية {								\
	بنية type *sqx_بعدی;	/* next element */			\
}

/*
 * XOR Simple queue access methods.
 */
#تعریف_کن XSIMPLEQ_XOR(سر, ptr)	    ((__typeof(ptr))((سر)->sqx_cookie ^ \
					(بیعلامت دراز)(ptr)))
#تعریف_کن	XSIMPLEQ_اولی(سر)	    XSIMPLEQ_XOR(سر, ((سر)->sqx_اولی))
#تعریف_کن	XSIMPLEQ_انتها(سر)	    عدم
#تعریف_کن	XSIMPLEQ_خالی(سر)	    (XSIMPLEQ_اولی(سر) == XSIMPLEQ_انتها(سر))
#تعریف_کن	XSIMPLEQ_بعدی(سر, elm, فیلد)    XSIMPLEQ_XOR(سر, ((elm)->فیلد.sqx_بعدی))


#تعریف_کن XSIMPLEQ_FOREACH(var, سر, فیلد)				\
	لكل ((var) = XSIMPLEQ_اولی(سر);				\
	    (var) != XSIMPLEQ_انتها(سر);				\
	    (var) = XSIMPLEQ_بعدی(سر, var, فیلد))

#تعریف_کن	XSIMPLEQ_FOREACH_امن(var, سر, فیلد, tvar)			\
	لكل ((var) = XSIMPLEQ_اولی(سر);				\
	    (var) && ((tvar) = XSIMPLEQ_بعدی(سر, var, فیلد), 1);	\
	    (var) = (tvar))

/*
 * XOR Simple queue functions.
 */
#تعریف_کن	XSIMPLEQ_INIT(سر) افعل {					\
	arc4random_buf(&(سر)->sqx_cookie, حجم((سر)->sqx_cookie)); \
	(سر)->sqx_اولی = XSIMPLEQ_XOR(سر, عدم);			\
	(سر)->sqx_آخرین = XSIMPLEQ_XOR(سر, &(سر)->sqx_اولی);	\
} طالما (0)

#تعریف_کن XSIMPLEQ_درج_سر(سر, elm, فیلد) افعل {			\
	إذا (((elm)->فیلد.sqx_بعدی = (سر)->sqx_اولی) ==		\
	    XSIMPLEQ_XOR(سر, عدم))					\
		(سر)->sqx_آخرین = XSIMPLEQ_XOR(سر, &(elm)->فیلد.sqx_بعدی); \
	(سر)->sqx_اولی = XSIMPLEQ_XOR(سر, (elm));			\
} طالما (0)

#تعریف_کن XSIMPLEQ_درج_دم(سر, elm, فیلد) افعل {			\
	(elm)->فیلد.sqx_بعدی = XSIMPLEQ_XOR(سر, عدم);		\
	*(XSIMPLEQ_XOR(سر, (سر)->sqx_آخرین)) = XSIMPLEQ_XOR(سر, (elm)); \
	(سر)->sqx_آخرین = XSIMPLEQ_XOR(سر, &(elm)->فیلد.sqx_بعدی);	\
} طالما (0)

#تعریف_کن XSIMPLEQ_درج_AFTER(سر, listelm, elm, فیلد) افعل {		\
	إذا (((elm)->فیلد.sqx_بعدی = (listelm)->فیلد.sqx_بعدی) ==	\
	    XSIMPLEQ_XOR(سر, عدم))					\
		(سر)->sqx_آخرین = XSIMPLEQ_XOR(سر, &(elm)->فیلد.sqx_بعدی); \
	(listelm)->فیلد.sqx_بعدی = XSIMPLEQ_XOR(سر, (elm));		\
} طالما (0)

#تعریف_کن XSIMPLEQ_REMOVE_سر(سر, فیلد) افعل {				\
	إذا (((سر)->sqx_اولی = XSIMPLEQ_XOR(سر,			\
	    (سر)->sqx_اولی)->فیلد.sqx_بعدی) == XSIMPLEQ_XOR(سر, عدم)) \
		(سر)->sqx_آخرین = XSIMPLEQ_XOR(سر, &(سر)->sqx_اولی); \
} طالما (0)

#تعریف_کن XSIMPLEQ_REMOVE_AFTER(سر, elm, فیلد) افعل {			\
	إذا (((elm)->فیلد.sqx_بعدی = XSIMPLEQ_XOR(سر,			\
	    (elm)->فیلد.sqx_بعدی)->فیلد.sqx_بعدی)			\
	    == XSIMPLEQ_XOR(سر, عدم))				\
		(سر)->sqx_آخرین = 					\
		    XSIMPLEQ_XOR(سر, &(elm)->فیلد.sqx_بعدی);		\
} طالما (0)


/*
 * Tail queue definitions.
 */
#تعریف_کن TAILQ_HEAD(name, type)						\
بنية name {								\
	بنية type *tqh_first;	/* first element */			\
	بنية type **tqh_last;	/* addr of last next element */		\
}

#تعریف_کن TAILQ_HEAD_INITIALIZER(سر)					\
	{ عدم, &(سر).tqh_first }

#تعریف_کن TAILQ_ENTRY(type)						\
بنية {								\
	بنية type *tqe_next;	/* next element */			\
	بنية type **tqe_prev;	/* address of previous next element */	\
}

/*
 * Tail queue access methods.
 */
#تعریف_کن	TAILQ_FIRST(سر)		((سر)->tqh_first)
#تعریف_کن	TAILQ_انتها(سر)			عدم
#تعریف_کن	TAILQ_NEXT(elm, فیلد)		((elm)->فیلد.tqe_next)
#تعریف_کن TAILQ_LAST(سر, headname)					\
	(*(((بنية headname *)((سر)->tqh_last))->tqh_last))
/* XXX */
#تعریف_کن TAILQ_PREV(elm, headname, فیلد)				\
	(*(((بنية headname *)((elm)->فیلد.tqe_prev))->tqh_last))
#تعریف_کن	TAILQ_EMPTY(سر)						\
	(TAILQ_FIRST(سر) == TAILQ_انتها(سر))

#تعریف_کن TAILQ_FOREACH(var, سر, فیلد)					\
	لكل((var) = TAILQ_FIRST(سر);					\
	    (var) != TAILQ_انتها(سر);					\
	    (var) = TAILQ_NEXT(var, فیلد))

#تعریف_کن	TAILQ_FOREACH_امن(var, سر, فیلد, tvar)			\
	لكل ((var) = TAILQ_FIRST(سر);					\
	    (var) != TAILQ_انتها(سر) &&					\
	    ((tvar) = TAILQ_NEXT(var, فیلد), 1);			\
	    (var) = (tvar))


#تعریف_کن TAILQ_FOREACH_معکوس(var, سر, headname, فیلد)		\
	لكل((var) = TAILQ_LAST(سر, headname);				\
	    (var) != TAILQ_انتها(سر);					\
	    (var) = TAILQ_PREV(var, headname, فیلد))

#تعریف_کن	TAILQ_FOREACH_معکوس_امن(var, سر, headname, فیلد, tvar)	\
	لكل ((var) = TAILQ_LAST(سر, headname);			\
	    (var) != TAILQ_انتها(سر) &&					\
	    ((tvar) = TAILQ_PREV(var, headname, فیلد), 1);		\
	    (var) = (tvar))

/*
 * Tail queue functions.
 */
#تعریف_کن	TAILQ_INIT(سر) افعل {						\
	(سر)->tqh_first = عدم;					\
	(سر)->tqh_last = &(سر)->tqh_first;				\
} طالما (0)

#تعریف_کن TAILQ_INSERT_HEAD(سر, elm, فیلد) افعل {			\
	إذا (((elm)->فیلد.tqe_next = (سر)->tqh_first) != عدم)	\
		(سر)->tqh_first->فیلد.tqe_prev =			\
		    &(elm)->فیلد.tqe_next;				\
	وإلا								\
		(سر)->tqh_last = &(elm)->فیلد.tqe_next;		\
	(سر)->tqh_first = (elm);					\
	(elm)->فیلد.tqe_prev = &(سر)->tqh_first;			\
} طالما (0)

#تعریف_کن TAILQ_INSERT_TAIL(سر, elm, فیلد) افعل {			\
	(elm)->فیلد.tqe_next = عدم;					\
	(elm)->فیلد.tqe_prev = (سر)->tqh_last;			\
	*(سر)->tqh_last = (elm);					\
	(سر)->tqh_last = &(elm)->فیلد.tqe_next;			\
} طالما (0)

#تعریف_کن TAILQ_INSERT_AFTER(سر, listelm, elm, فیلد) افعل {		\
	إذا (((elm)->فیلد.tqe_next = (listelm)->فیلد.tqe_next) != عدم)\
		(elm)->فیلد.tqe_next->فیلد.tqe_prev =			\
		    &(elm)->فیلد.tqe_next;				\
	وإلا								\
		(سر)->tqh_last = &(elm)->فیلد.tqe_next;		\
	(listelm)->فیلد.tqe_next = (elm);				\
	(elm)->فیلد.tqe_prev = &(listelm)->فیلد.tqe_next;		\
} طالما (0)

#تعریف_کن	TAILQ_INSERT_BEFORE(listelm, elm, فیلد) افعل {			\
	(elm)->فیلد.tqe_prev = (listelm)->فیلد.tqe_prev;		\
	(elm)->فیلد.tqe_next = (listelm);				\
	*(listelm)->فیلد.tqe_prev = (elm);				\
	(listelm)->فیلد.tqe_prev = &(elm)->فیلد.tqe_next;		\
} طالما (0)

#تعریف_کن TAILQ_REMOVE(سر, elm, فیلد) افعل {				\
	إذا (((elm)->فیلد.tqe_next) != عدم)				\
		(elm)->فیلد.tqe_next->فیلد.tqe_prev =			\
		    (elm)->فیلد.tqe_prev;				\
	وإلا								\
		(سر)->tqh_last = (elm)->فیلد.tqe_prev;		\
	*(elm)->فیلد.tqe_prev = (elm)->فیلد.tqe_next;			\
	_Q_INVALIDATE((elm)->فیلد.tqe_prev);				\
	_Q_INVALIDATE((elm)->فیلد.tqe_next);				\
} طالما (0)

#تعریف_کن TAILQ_REPLACE(سر, elm, elm2, فیلد) افعل {			\
	إذا (((elm2)->فیلد.tqe_next = (elm)->فیلد.tqe_next) != عدم)	\
		(elm2)->فیلد.tqe_next->فیلد.tqe_prev =		\
		    &(elm2)->فیلد.tqe_next;				\
	وإلا								\
		(سر)->tqh_last = &(elm2)->فیلد.tqe_next;		\
	(elm2)->فیلد.tqe_prev = (elm)->فیلد.tqe_prev;			\
	*(elm2)->فیلد.tqe_prev = (elm2);				\
	_Q_INVALIDATE((elm)->فیلد.tqe_prev);				\
	_Q_INVALIDATE((elm)->فیلد.tqe_next);				\
} طالما (0)

#تعریف_کن TAILQ_CONCAT(head1, head2, فیلد) افعل {				\
	إذا (!TAILQ_EMPTY(head2)) {					\
		*(head1)->tqh_last = (head2)->tqh_first;		\
		(head2)->tqh_first->فیلد.tqe_prev = (head1)->tqh_last;	\
		(head1)->tqh_last = (head2)->tqh_last;			\
		TAILQ_INIT((head2));					\
	}								\
} طالما (0)

#پایان_اگر	/* !_SYS_QUEUE_H_ */
