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

#ifndef	_FAKE_QUEUE_H_
#define	_FAKE_QUEUE_H_

/*
 * Require for OS/X and other platforms that have old/broken/incomplete
 * <sys/queue.h>.
 */
#undef CIRCLEQ_EMPTY
#undef CIRCLEQ_END
#undef CIRCLEQ_ENTRY
#undef CIRCLEQ_FIRST
#undef CIRCLEQ_FOREACH
#undef CIRCLEQ_FOREACH_REVERSE
#undef CIRCLEQ_HEAD
#undef CIRCLEQ_HEAD_INITIALIZER
#undef CIRCLEQ_INIT
#undef CIRCLEQ_INSERT_AFTER
#undef CIRCLEQ_INSERT_BEFORE
#undef CIRCLEQ_INSERT_HEAD
#undef CIRCLEQ_INSERT_TAIL
#undef CIRCLEQ_LAST
#undef CIRCLEQ_NEXT
#undef CIRCLEQ_PREV
#undef CIRCLEQ_REMOVE
#undef CIRCLEQ_REPLACE
#undef LIST_EMPTY
#undef LIST_END
#undef LIST_ENTRY
#undef LIST_FIRST
#undef LIST_FOREACH
#undef LIST_FOREACH_SAFE
#undef LIST_HEAD
#undef LIST_HEAD_INITIALIZER
#undef LIST_INIT
#undef LIST_INSERT_AFTER
#undef LIST_INSERT_BEFORE
#undef LIST_INSERT_HEAD
#undef LIST_NEXT
#undef LIST_REMOVE
#undef LIST_REPLACE
#undef SIMPLEQ_CONCAT
#undef SIMPLEQ_EMPTY
#undef SIMPLEQ_END
#undef SIMPLEQ_ENTRY
#undef SIMPLEQ_FIRST
#undef SIMPLEQ_FOREACH
#undef SIMPLEQ_FOREACH_SAFE
#undef SIMPLEQ_HEAD
#undef SIMPLEQ_HEAD_INITIALIZER
#undef SIMPLEQ_INIT
#undef SIMPLEQ_INSERT_AFTER
#undef SIMPLEQ_INSERT_HEAD
#undef SIMPLEQ_INSERT_TAIL
#undef SIMPLEQ_NEXT
#undef SIMPLEQ_REMOVE_AFTER
#undef SIMPLEQ_REMOVE_HEAD
#undef SLIST_EMPTY
#undef SLIST_END
#undef SLIST_ENTRY
#undef SLIST_FIRST
#undef SLIST_FOREACH
#undef SLIST_FOREACH_PREVPTR
#undef SLIST_FOREACH_SAFE
#undef SLIST_HEAD
#undef SLIST_HEAD_INITIALIZER
#undef SLIST_INIT
#undef SLIST_INSERT_AFTER
#undef SLIST_INSERT_HEAD
#undef SLIST_NEXT
#undef SLIST_REMOVE
#undef SLIST_REMOVE_AFTER
#undef SLIST_REMOVE_HEAD
#undef SLIST_REMOVE_পরবর্তী
#undef TAILQ_CONCAT
#undef TAILQ_EMPTY
#undef TAILQ_END
#undef TAILQ_ENTRY
#undef TAILQ_FIRST
#undef TAILQ_FOREACH
#undef TAILQ_FOREACH_REVERSE
#undef TAILQ_FOREACH_REVERSE_SAFE
#undef TAILQ_FOREACH_SAFE
#undef TAILQ_HEAD
#undef TAILQ_HEAD_INITIALIZER
#undef TAILQ_INIT
#undef TAILQ_INSERT_AFTER
#undef TAILQ_INSERT_BEFORE
#undef TAILQ_INSERT_HEAD
#undef TAILQ_INSERT_TAIL
#undef TAILQ_LAST
#undef TAILQ_NEXT
#undef TAILQ_PREV
#undef TAILQ_REMOVE
#undef TAILQ_REPLACE

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

#যদি defined(QUEUE_MACRO_DEBUG) || (defined(_KERNEL) && defined(DIAGNOSTIC))
#define _Q_INVALID ((শূন্য *)-1)
#define _Q_INVALIDATE(a) (a) = _Q_INVALID
#অন্যথা
#define _Q_INVALIDATE(a)
#endif

/*
 * Singly-linked List definitions.
 */
#define SLIST_HEAD(name, type)						\
কাঠামো name {								\
	কাঠামো type *slh_first;	/* first element */			\
}

#define	SLIST_HEAD_INITIALIZER(শীর্ষ_2)					\
	{ ফাঁকা }

#define SLIST_ENTRY(type)						\
কাঠামো {								\
	কাঠামো type *sle_পরবর্তী;	/* next element */			\
}

/*
 * Singly-linked List access methods.
 */
#define	SLIST_FIRST(শীর্ষ_2)	((শীর্ষ_2)->slh_first)
#define	SLIST_END(শীর্ষ_2)		ফাঁকা
#define	SLIST_EMPTY(শীর্ষ_2)	(SLIST_FIRST(শীর্ষ_2) == SLIST_END(শীর্ষ_2))
#define	SLIST_NEXT(elm, field)	((elm)->field.sle_পরবর্তী)

#define	SLIST_FOREACH(var, শীর্ষ_2, field)					\
	জন্য((var) = SLIST_FIRST(শীর্ষ_2);					\
	    (var) != SLIST_END(শীর্ষ_2);					\
	    (var) = SLIST_NEXT(var, field))

#define	SLIST_FOREACH_SAFE(var, শীর্ষ_2, field, tvar)			\
	জন্য ((var) = SLIST_FIRST(শীর্ষ_2);				\
	    (var) && ((tvar) = SLIST_NEXT(var, field), 1);		\
	    (var) = (tvar))

/*
 * Singly-linked List functions.
 */
#define	SLIST_INIT(শীর্ষ_2) {						\
	SLIST_FIRST(শীর্ষ_2) = SLIST_END(শীর্ষ_2);				\
}

#define	SLIST_INSERT_AFTER(slistelm, elm, field) করো {			\
	(elm)->field.sle_পরবর্তী = (slistelm)->field.sle_পরবর্তী;		\
	(slistelm)->field.sle_পরবর্তী = (elm);				\
} যখন (0)

#define	SLIST_INSERT_HEAD(শীর্ষ_2, elm, field) করো {			\
	(elm)->field.sle_পরবর্তী = (শীর্ষ_2)->slh_first;			\
	(শীর্ষ_2)->slh_first = (elm);					\
} যখন (0)

#define	SLIST_REMOVE_AFTER(elm, field) করো {				\
	(elm)->field.sle_পরবর্তী = (elm)->field.sle_পরবর্তী->field.sle_পরবর্তী;	\
} যখন (0)

#define	SLIST_REMOVE_HEAD(শীর্ষ_2, field) করো {				\
	(শীর্ষ_2)->slh_first = (শীর্ষ_2)->slh_first->field.sle_পরবর্তী;		\
} যখন (0)

#define SLIST_REMOVE(শীর্ষ_2, elm, type, field) করো {			\
	যদি ((শীর্ষ_2)->slh_first == (elm)) {				\
		SLIST_REMOVE_HEAD((শীর্ষ_2), field);			\
	} অন্যথা {							\
		কাঠামো type *curelm = (শীর্ষ_2)->slh_first;		\
									\
		যখন (curelm->field.sle_পরবর্তী != (elm))			\
			curelm = curelm->field.sle_পরবর্তী;		\
		curelm->field.sle_পরবর্তী =				\
		    curelm->field.sle_পরবর্তী->field.sle_পরবর্তী;		\
	}								\
	_Q_INVALIDATE((elm)->field.sle_পরবর্তী);				\
} যখন (0)

/*
 * List definitions.
 */
#define LIST_HEAD(name, type)						\
কাঠামো name {								\
	কাঠামো type *lh_first;	/* first element */			\
}

#define LIST_HEAD_INITIALIZER(শীর্ষ_2)					\
	{ ফাঁকা }

#define LIST_ENTRY(type)						\
কাঠামো {								\
	কাঠামো type *le_পরবর্তী;	/* next element */			\
	কাঠামো type **le_পূর্ব;	/* address of previous next element */	\
}

/*
 * List access methods.
 */
#define	LIST_FIRST(শীর্ষ_2)		((শীর্ষ_2)->lh_first)
#define	LIST_END(শীর্ষ_2)			ফাঁকা
#define	LIST_EMPTY(শীর্ষ_2)		(LIST_FIRST(শীর্ষ_2) == LIST_END(শীর্ষ_2))
#define	LIST_NEXT(elm, field)		((elm)->field.le_পরবর্তী)

#define LIST_FOREACH(var, শীর্ষ_2, field)					\
	জন্য((var) = LIST_FIRST(শীর্ষ_2);					\
	    (var)!= LIST_END(শীর্ষ_2);					\
	    (var) = LIST_NEXT(var, field))

#define	LIST_FOREACH_SAFE(var, শীর্ষ_2, field, tvar)			\
	জন্য ((var) = LIST_FIRST(শীর্ষ_2);				\
	    (var) && ((tvar) = LIST_NEXT(var, field), 1);		\
	    (var) = (tvar))

/*
 * List functions.
 */
#define	LIST_INIT(শীর্ষ_2) করো {						\
	LIST_FIRST(শীর্ষ_2) = LIST_END(শীর্ষ_2);				\
} যখন (0)

#define LIST_INSERT_AFTER(listelm, elm, field) করো {			\
	যদি (((elm)->field.le_পরবর্তী = (listelm)->field.le_পরবর্তী) != ফাঁকা)	\
		(listelm)->field.le_পরবর্তী->field.le_পূর্ব =		\
		    &(elm)->field.le_পরবর্তী;				\
	(listelm)->field.le_পরবর্তী = (elm);				\
	(elm)->field.le_পূর্ব = &(listelm)->field.le_পরবর্তী;		\
} যখন (0)

#define	LIST_INSERT_BEFORE(listelm, elm, field) করো {			\
	(elm)->field.le_পূর্ব = (listelm)->field.le_পূর্ব;		\
	(elm)->field.le_পরবর্তী = (listelm);				\
	*(listelm)->field.le_পূর্ব = (elm);				\
	(listelm)->field.le_পূর্ব = &(elm)->field.le_পরবর্তী;		\
} যখন (0)

#define LIST_INSERT_HEAD(শীর্ষ_2, elm, field) করো {				\
	যদি (((elm)->field.le_পরবর্তী = (শীর্ষ_2)->lh_first) != ফাঁকা)		\
		(শীর্ষ_2)->lh_first->field.le_পূর্ব = &(elm)->field.le_পরবর্তী;\
	(শীর্ষ_2)->lh_first = (elm);					\
	(elm)->field.le_পূর্ব = &(শীর্ষ_2)->lh_first;			\
} যখন (0)

#define LIST_REMOVE(elm, field) করো {					\
	যদি ((elm)->field.le_পরবর্তী != ফাঁকা)				\
		(elm)->field.le_পরবর্তী->field.le_পূর্ব =			\
		    (elm)->field.le_পূর্ব;				\
	*(elm)->field.le_পূর্ব = (elm)->field.le_পরবর্তী;			\
	_Q_INVALIDATE((elm)->field.le_পূর্ব);				\
	_Q_INVALIDATE((elm)->field.le_পরবর্তী);				\
} যখন (0)

#define LIST_REPLACE(elm, elm2, field) করো {				\
	যদি (((elm2)->field.le_পরবর্তী = (elm)->field.le_পরবর্তী) != ফাঁকা)	\
		(elm2)->field.le_পরবর্তী->field.le_পূর্ব =			\
		    &(elm2)->field.le_পরবর্তী;				\
	(elm2)->field.le_পূর্ব = (elm)->field.le_পূর্ব;			\
	*(elm2)->field.le_পূর্ব = (elm2);				\
	_Q_INVALIDATE((elm)->field.le_পূর্ব);				\
	_Q_INVALIDATE((elm)->field.le_পরবর্তী);				\
} যখন (0)

/*
 * Simple queue definitions.
 */
#define SIMPLEQ_HEAD(name, type)					\
কাঠামো name {								\
	কাঠামো type *sqh_first;	/* first element */			\
	কাঠামো type **sqh_last;	/* addr of last next element */		\
}

#define SIMPLEQ_HEAD_INITIALIZER(শীর্ষ_2)					\
	{ ফাঁকা, &(শীর্ষ_2).sqh_first }

#define SIMPLEQ_ENTRY(type)						\
কাঠামো {								\
	কাঠামো type *sqe_পরবর্তী;	/* next element */			\
}

/*
 * Simple queue access methods.
 */
#define	SIMPLEQ_FIRST(শীর্ষ_2)	    ((শীর্ষ_2)->sqh_first)
#define	SIMPLEQ_END(শীর্ষ_2)	    ফাঁকা
#define	SIMPLEQ_EMPTY(শীর্ষ_2)	    (SIMPLEQ_FIRST(শীর্ষ_2) == SIMPLEQ_END(শীর্ষ_2))
#define	SIMPLEQ_NEXT(elm, field)    ((elm)->field.sqe_পরবর্তী)

#define SIMPLEQ_FOREACH(var, শীর্ষ_2, field)				\
	জন্য((var) = SIMPLEQ_FIRST(শীর্ষ_2);				\
	    (var) != SIMPLEQ_END(শীর্ষ_2);					\
	    (var) = SIMPLEQ_NEXT(var, field))

#define	SIMPLEQ_FOREACH_SAFE(var, শীর্ষ_2, field, tvar)			\
	জন্য ((var) = SIMPLEQ_FIRST(শীর্ষ_2);				\
	    (var) && ((tvar) = SIMPLEQ_NEXT(var, field), 1);		\
	    (var) = (tvar))

/*
 * Simple queue functions.
 */
#define	SIMPLEQ_INIT(শীর্ষ_2) করো {						\
	(শীর্ষ_2)->sqh_first = ফাঁকা;					\
	(শীর্ষ_2)->sqh_last = &(শীর্ষ_2)->sqh_first;				\
} যখন (0)

#define SIMPLEQ_INSERT_HEAD(শীর্ষ_2, elm, field) করো {			\
	যদি (((elm)->field.sqe_পরবর্তী = (শীর্ষ_2)->sqh_first) == ফাঁকা)	\
		(শীর্ষ_2)->sqh_last = &(elm)->field.sqe_পরবর্তী;		\
	(শীর্ষ_2)->sqh_first = (elm);					\
} যখন (0)

#define SIMPLEQ_INSERT_TAIL(শীর্ষ_2, elm, field) করো {			\
	(elm)->field.sqe_পরবর্তী = ফাঁকা;					\
	*(শীর্ষ_2)->sqh_last = (elm);					\
	(শীর্ষ_2)->sqh_last = &(elm)->field.sqe_পরবর্তী;			\
} যখন (0)

#define SIMPLEQ_INSERT_AFTER(শীর্ষ_2, listelm, elm, field) করো {		\
	যদি (((elm)->field.sqe_পরবর্তী = (listelm)->field.sqe_পরবর্তী) == ফাঁকা)\
		(শীর্ষ_2)->sqh_last = &(elm)->field.sqe_পরবর্তী;		\
	(listelm)->field.sqe_পরবর্তী = (elm);				\
} যখন (0)

#define SIMPLEQ_REMOVE_HEAD(শীর্ষ_2, field) করো {			\
	যদি (((শীর্ষ_2)->sqh_first = (শীর্ষ_2)->sqh_first->field.sqe_পরবর্তী) == ফাঁকা) \
		(শীর্ষ_2)->sqh_last = &(শীর্ষ_2)->sqh_first;			\
} যখন (0)

#define SIMPLEQ_REMOVE_AFTER(শীর্ষ_2, elm, field) করো {			\
	যদি (((elm)->field.sqe_পরবর্তী = (elm)->field.sqe_পরবর্তী->field.sqe_পরবর্তী) \
	    == ফাঁকা)							\
		(শীর্ষ_2)->sqh_last = &(elm)->field.sqe_পরবর্তী;		\
} যখন (0)

#define SIMPLEQ_CONCAT(head1, head2) করো {				\
	যদি (!SIMPLEQ_EMPTY((head2))) {					\
		*(head1)->sqh_last = (head2)->sqh_first;		\
		(head1)->sqh_last = (head2)->sqh_last;			\
		SIMPLEQ_INIT((head2));					\
	}								\
} যখন (0)

/*
 * XOR Simple queue definitions.
 */
#define XSIMPLEQ_শীর্ষ(name, type)					\
কাঠামো name {								\
	কাঠামো type *sqx_first;	/* first element */			\
	কাঠামো type **sqx_last;	/* addr of last next element */		\
	unsigned long sqx_cookie;					\
}

#define XSIMPLEQ_ENTRY(type)						\
কাঠামো {								\
	কাঠামো type *sqx_পরবর্তী;	/* next element */			\
}

/*
 * XOR Simple queue access methods.
 */
#define XSIMPLEQ_XOR(শীর্ষ_2, ptr)	    ((__typeof(ptr))((শীর্ষ_2)->sqx_cookie ^ \
					(unsigned long)(ptr)))
#define	XSIMPLEQ_FIRST(শীর্ষ_2)	    XSIMPLEQ_XOR(শীর্ষ_2, ((শীর্ষ_2)->sqx_first))
#define	XSIMPLEQ_END(শীর্ষ_2)	    ফাঁকা
#define	XSIMPLEQ_EMPTY(শীর্ষ_2)	    (XSIMPLEQ_FIRST(শীর্ষ_2) == XSIMPLEQ_END(শীর্ষ_2))
#define	XSIMPLEQ_পরবর্তী(শীর্ষ_2, elm, field)    XSIMPLEQ_XOR(শীর্ষ_2, ((elm)->field.sqx_পরবর্তী))


#define XSIMPLEQ_FOREACH(var, শীর্ষ_2, field)				\
	জন্য ((var) = XSIMPLEQ_FIRST(শীর্ষ_2);				\
	    (var) != XSIMPLEQ_END(শীর্ষ_2);				\
	    (var) = XSIMPLEQ_পরবর্তী(শীর্ষ_2, var, field))

#define	XSIMPLEQ_FOREACH_SAFE(var, শীর্ষ_2, field, tvar)			\
	জন্য ((var) = XSIMPLEQ_FIRST(শীর্ষ_2);				\
	    (var) && ((tvar) = XSIMPLEQ_পরবর্তী(শীর্ষ_2, var, field), 1);	\
	    (var) = (tvar))

/*
 * XOR Simple queue functions.
 */
#define	XSIMPLEQ_INIT(শীর্ষ_2) করো {					\
	arc4random_buf(&(শীর্ষ_2)->sqx_cookie, আকার((শীর্ষ_2)->sqx_cookie)); \
	(শীর্ষ_2)->sqx_first = XSIMPLEQ_XOR(শীর্ষ_2, ফাঁকা);			\
	(শীর্ষ_2)->sqx_last = XSIMPLEQ_XOR(শীর্ষ_2, &(শীর্ষ_2)->sqx_first);	\
} যখন (0)

#define XSIMPLEQ_ঢোকাও_শীর্ষ(শীর্ষ_2, elm, field) করো {			\
	যদি (((elm)->field.sqx_পরবর্তী = (শীর্ষ_2)->sqx_first) ==		\
	    XSIMPLEQ_XOR(শীর্ষ_2, ফাঁকা))					\
		(শীর্ষ_2)->sqx_last = XSIMPLEQ_XOR(শীর্ষ_2, &(elm)->field.sqx_পরবর্তী); \
	(শীর্ষ_2)->sqx_first = XSIMPLEQ_XOR(শীর্ষ_2, (elm));			\
} যখন (0)

#define XSIMPLEQ_ঢোকাও_লেজ(শীর্ষ_2, elm, field) করো {			\
	(elm)->field.sqx_পরবর্তী = XSIMPLEQ_XOR(শীর্ষ_2, ফাঁকা);		\
	*(XSIMPLEQ_XOR(শীর্ষ_2, (শীর্ষ_2)->sqx_last)) = XSIMPLEQ_XOR(শীর্ষ_2, (elm)); \
	(শীর্ষ_2)->sqx_last = XSIMPLEQ_XOR(শীর্ষ_2, &(elm)->field.sqx_পরবর্তী);	\
} যখন (0)

#define XSIMPLEQ_ঢোকাও_AFTER(শীর্ষ_2, listelm, elm, field) করো {		\
	যদি (((elm)->field.sqx_পরবর্তী = (listelm)->field.sqx_পরবর্তী) ==	\
	    XSIMPLEQ_XOR(শীর্ষ_2, ফাঁকা))					\
		(শীর্ষ_2)->sqx_last = XSIMPLEQ_XOR(শীর্ষ_2, &(elm)->field.sqx_পরবর্তী); \
	(listelm)->field.sqx_পরবর্তী = XSIMPLEQ_XOR(শীর্ষ_2, (elm));		\
} যখন (0)

#define XSIMPLEQ_REMOVE_শীর্ষ(শীর্ষ_2, field) করো {				\
	যদি (((শীর্ষ_2)->sqx_first = XSIMPLEQ_XOR(শীর্ষ_2,			\
	    (শীর্ষ_2)->sqx_first)->field.sqx_পরবর্তী) == XSIMPLEQ_XOR(শীর্ষ_2, ফাঁকা)) \
		(শীর্ষ_2)->sqx_last = XSIMPLEQ_XOR(শীর্ষ_2, &(শীর্ষ_2)->sqx_first); \
} যখন (0)

#define XSIMPLEQ_REMOVE_AFTER(শীর্ষ_2, elm, field) করো {			\
	যদি (((elm)->field.sqx_পরবর্তী = XSIMPLEQ_XOR(শীর্ষ_2,			\
	    (elm)->field.sqx_পরবর্তী)->field.sqx_পরবর্তী)			\
	    == XSIMPLEQ_XOR(শীর্ষ_2, ফাঁকা))				\
		(শীর্ষ_2)->sqx_last = 					\
		    XSIMPLEQ_XOR(শীর্ষ_2, &(elm)->field.sqx_পরবর্তী);		\
} যখন (0)


/*
 * Tail queue definitions.
 */
#define TAILQ_HEAD(name, type)						\
কাঠামো name {								\
	কাঠামো type *tqh_first;	/* first element */			\
	কাঠামো type **tqh_last;	/* addr of last next element */		\
}

#define TAILQ_HEAD_INITIALIZER(শীর্ষ_2)					\
	{ ফাঁকা, &(শীর্ষ_2).tqh_first }

#define TAILQ_ENTRY(type)						\
কাঠামো {								\
	কাঠামো type *tqe_next;	/* next element */			\
	কাঠামো type **tqe_prev;	/* address of previous next element */	\
}

/*
 * Tail queue access methods.
 */
#define	TAILQ_FIRST(শীর্ষ_2)		((শীর্ষ_2)->tqh_first)
#define	TAILQ_END(শীর্ষ_2)			ফাঁকা
#define	TAILQ_NEXT(elm, field)		((elm)->field.tqe_next)
#define TAILQ_LAST(শীর্ষ_2, headname)					\
	(*(((কাঠামো headname *)((শীর্ষ_2)->tqh_last))->tqh_last))
/* XXX */
#define TAILQ_PREV(elm, headname, field)				\
	(*(((কাঠামো headname *)((elm)->field.tqe_prev))->tqh_last))
#define	TAILQ_EMPTY(শীর্ষ_2)						\
	(TAILQ_FIRST(শীর্ষ_2) == TAILQ_END(শীর্ষ_2))

#define TAILQ_FOREACH(var, শীর্ষ_2, field)					\
	জন্য((var) = TAILQ_FIRST(শীর্ষ_2);					\
	    (var) != TAILQ_END(শীর্ষ_2);					\
	    (var) = TAILQ_NEXT(var, field))

#define	TAILQ_FOREACH_SAFE(var, শীর্ষ_2, field, tvar)			\
	জন্য ((var) = TAILQ_FIRST(শীর্ষ_2);					\
	    (var) != TAILQ_END(শীর্ষ_2) &&					\
	    ((tvar) = TAILQ_NEXT(var, field), 1);			\
	    (var) = (tvar))


#define TAILQ_FOREACH_REVERSE(var, শীর্ষ_2, headname, field)		\
	জন্য((var) = TAILQ_LAST(শীর্ষ_2, headname);				\
	    (var) != TAILQ_END(শীর্ষ_2);					\
	    (var) = TAILQ_PREV(var, headname, field))

#define	TAILQ_FOREACH_REVERSE_SAFE(var, শীর্ষ_2, headname, field, tvar)	\
	জন্য ((var) = TAILQ_LAST(শীর্ষ_2, headname);			\
	    (var) != TAILQ_END(শীর্ষ_2) &&					\
	    ((tvar) = TAILQ_PREV(var, headname, field), 1);		\
	    (var) = (tvar))

/*
 * Tail queue functions.
 */
#define	TAILQ_INIT(শীর্ষ_2) করো {						\
	(শীর্ষ_2)->tqh_first = ফাঁকা;					\
	(শীর্ষ_2)->tqh_last = &(শীর্ষ_2)->tqh_first;				\
} যখন (0)

#define TAILQ_INSERT_HEAD(শীর্ষ_2, elm, field) করো {			\
	যদি (((elm)->field.tqe_next = (শীর্ষ_2)->tqh_first) != ফাঁকা)	\
		(শীর্ষ_2)->tqh_first->field.tqe_prev =			\
		    &(elm)->field.tqe_next;				\
	অন্যথা								\
		(শীর্ষ_2)->tqh_last = &(elm)->field.tqe_next;		\
	(শীর্ষ_2)->tqh_first = (elm);					\
	(elm)->field.tqe_prev = &(শীর্ষ_2)->tqh_first;			\
} যখন (0)

#define TAILQ_INSERT_TAIL(শীর্ষ_2, elm, field) করো {			\
	(elm)->field.tqe_next = ফাঁকা;					\
	(elm)->field.tqe_prev = (শীর্ষ_2)->tqh_last;			\
	*(শীর্ষ_2)->tqh_last = (elm);					\
	(শীর্ষ_2)->tqh_last = &(elm)->field.tqe_next;			\
} যখন (0)

#define TAILQ_INSERT_AFTER(শীর্ষ_2, listelm, elm, field) করো {		\
	যদি (((elm)->field.tqe_next = (listelm)->field.tqe_next) != ফাঁকা)\
		(elm)->field.tqe_next->field.tqe_prev =			\
		    &(elm)->field.tqe_next;				\
	অন্যথা								\
		(শীর্ষ_2)->tqh_last = &(elm)->field.tqe_next;		\
	(listelm)->field.tqe_next = (elm);				\
	(elm)->field.tqe_prev = &(listelm)->field.tqe_next;		\
} যখন (0)

#define	TAILQ_INSERT_BEFORE(listelm, elm, field) করো {			\
	(elm)->field.tqe_prev = (listelm)->field.tqe_prev;		\
	(elm)->field.tqe_next = (listelm);				\
	*(listelm)->field.tqe_prev = (elm);				\
	(listelm)->field.tqe_prev = &(elm)->field.tqe_next;		\
} যখন (0)

#define TAILQ_REMOVE(শীর্ষ_2, elm, field) করো {				\
	যদি (((elm)->field.tqe_next) != ফাঁকা)				\
		(elm)->field.tqe_next->field.tqe_prev =			\
		    (elm)->field.tqe_prev;				\
	অন্যথা								\
		(শীর্ষ_2)->tqh_last = (elm)->field.tqe_prev;		\
	*(elm)->field.tqe_prev = (elm)->field.tqe_next;			\
	_Q_INVALIDATE((elm)->field.tqe_prev);				\
	_Q_INVALIDATE((elm)->field.tqe_next);				\
} যখন (0)

#define TAILQ_REPLACE(শীর্ষ_2, elm, elm2, field) করো {			\
	যদি (((elm2)->field.tqe_next = (elm)->field.tqe_next) != ফাঁকা)	\
		(elm2)->field.tqe_next->field.tqe_prev =		\
		    &(elm2)->field.tqe_next;				\
	অন্যথা								\
		(শীর্ষ_2)->tqh_last = &(elm2)->field.tqe_next;		\
	(elm2)->field.tqe_prev = (elm)->field.tqe_prev;			\
	*(elm2)->field.tqe_prev = (elm2);				\
	_Q_INVALIDATE((elm)->field.tqe_prev);				\
	_Q_INVALIDATE((elm)->field.tqe_next);				\
} যখন (0)

#define TAILQ_CONCAT(head1, head2, field) করো {				\
	যদি (!TAILQ_EMPTY(head2)) {					\
		*(head1)->tqh_last = (head2)->tqh_first;		\
		(head2)->tqh_first->field.tqe_prev = (head1)->tqh_last;	\
		(head1)->tqh_last = (head2)->tqh_last;			\
		TAILQ_INIT((head2));					\
	}								\
} যখন (0)

#endif	/* !_SYS_QUEUE_H_ */
