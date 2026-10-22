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

#यदि_अपरिभाषितम्	_FAKE_QUEUE_H_
#परिभाषय	_FAKE_QUEUE_H_

/*
 * Require for OS/X and other platforms that have old/broken/incomplete
 * <sys/queue.h>.
 */
#अपरिभाषय CIRCLEQ_EMPTY
#अपरिभाषय CIRCLEQ_अन्तः
#अपरिभाषय CIRCLEQ_ENTRY
#अपरिभाषय CIRCLEQ_FIRST
#अपरिभाषय CIRCLEQ_FOREACH
#अपरिभाषय CIRCLEQ_FOREACH_REVERSE
#अपरिभाषय CIRCLEQ_HEAD
#अपरिभाषय CIRCLEQ_HEAD_INITIALIZER
#अपरिभाषय CIRCLEQ_INIT
#अपरिभाषय CIRCLEQ_INSERT_AFTER
#अपरिभाषय CIRCLEQ_INSERT_BEFORE
#अपरिभाषय CIRCLEQ_INSERT_HEAD
#अपरिभाषय CIRCLEQ_INSERT_TAIL
#अपरिभाषय CIRCLEQ_LAST
#अपरिभाषय CIRCLEQ_NEXT
#अपरिभाषय CIRCLEQ_PREV
#अपरिभाषय CIRCLEQ_REMOVE
#अपरिभाषय CIRCLEQ_REPLACE
#अपरिभाषय LIST_EMPTY
#अपरिभाषय LIST_अन्तः
#अपरिभाषय LIST_ENTRY
#अपरिभाषय LIST_FIRST
#अपरिभाषय LIST_FOREACH
#अपरिभाषय LIST_FOREACH_SAFE
#अपरिभाषय LIST_HEAD
#अपरिभाषय LIST_HEAD_INITIALIZER
#अपरिभाषय LIST_INIT
#अपरिभाषय LIST_INSERT_AFTER
#अपरिभाषय LIST_INSERT_BEFORE
#अपरिभाषय LIST_INSERT_HEAD
#अपरिभाषय LIST_NEXT
#अपरिभाषय LIST_REMOVE
#अपरिभाषय LIST_REPLACE
#अपरिभाषय SIMPLEQ_CONCAT
#अपरिभाषय SIMPLEQ_EMPTY
#अपरिभाषय SIMPLEQ_अन्तः
#अपरिभाषय SIMPLEQ_ENTRY
#अपरिभाषय SIMPLEQ_FIRST
#अपरिभाषय SIMPLEQ_FOREACH
#अपरिभाषय SIMPLEQ_FOREACH_SAFE
#अपरिभाषय SIMPLEQ_HEAD
#अपरिभाषय SIMPLEQ_HEAD_INITIALIZER
#अपरिभाषय SIMPLEQ_INIT
#अपरिभाषय SIMPLEQ_INSERT_AFTER
#अपरिभाषय SIMPLEQ_INSERT_HEAD
#अपरिभाषय SIMPLEQ_INSERT_TAIL
#अपरिभाषय SIMPLEQ_NEXT
#अपरिभाषय SIMPLEQ_REMOVE_AFTER
#अपरिभाषय SIMPLEQ_REMOVE_HEAD
#अपरिभाषय SLIST_EMPTY
#अपरिभाषय SLIST_अन्तः
#अपरिभाषय SLIST_ENTRY
#अपरिभाषय SLIST_FIRST
#अपरिभाषय SLIST_FOREACH
#अपरिभाषय SLIST_FOREACH_PREVPTR
#अपरिभाषय SLIST_FOREACH_SAFE
#अपरिभाषय SLIST_HEAD
#अपरिभाषय SLIST_HEAD_INITIALIZER
#अपरिभाषय SLIST_INIT
#अपरिभाषय SLIST_INSERT_AFTER
#अपरिभाषय SLIST_INSERT_HEAD
#अपरिभाषय SLIST_NEXT
#अपरिभाषय SLIST_REMOVE
#अपरिभाषय SLIST_REMOVE_AFTER
#अपरिभाषय SLIST_REMOVE_HEAD
#अपरिभाषय SLIST_REMOVE_अग्र
#अपरिभाषय TAILQ_CONCAT
#अपरिभाषय TAILQ_EMPTY
#अपरिभाषय TAILQ_अन्तः
#अपरिभाषय TAILQ_ENTRY
#अपरिभाषय TAILQ_FIRST
#अपरिभाषय TAILQ_FOREACH
#अपरिभाषय TAILQ_FOREACH_REVERSE
#अपरिभाषय TAILQ_FOREACH_REVERSE_SAFE
#अपरिभाषय TAILQ_FOREACH_SAFE
#अपरिभाषय TAILQ_HEAD
#अपरिभाषय TAILQ_HEAD_INITIALIZER
#अपरिभाषय TAILQ_INIT
#अपरिभाषय TAILQ_INSERT_AFTER
#अपरिभाषय TAILQ_INSERT_BEFORE
#अपरिभाषय TAILQ_INSERT_HEAD
#अपरिभाषय TAILQ_INSERT_TAIL
#अपरिभाषय TAILQ_LAST
#अपरिभाषय TAILQ_NEXT
#अपरिभाषय TAILQ_PREV
#अपरिभाषय TAILQ_REMOVE
#अपरिभाषय TAILQ_REPLACE

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

#यदि defined(QUEUE_MACRO_DEBUG) || (defined(_KERNEL) && defined(DIAGNOSTIC))
#परिभाषय _Q_INVALID ((शून्य *)-1)
#परिभाषय _Q_INVALIDATE(a) (a) = _Q_INVALID
#अन्यथा
#परिभाषय _Q_INVALIDATE(a)
#यदि_अन्तः

/*
 * Singly-linked List definitions.
 */
#परिभाषय SLIST_HEAD(name, type)						\
संरचना name {								\
	संरचना type *slh_first;	/* first element */			\
}

#परिभाषय	SLIST_HEAD_INITIALIZER(शीर्ष)					\
	{ रिक्त }

#परिभाषय SLIST_ENTRY(type)						\
संरचना {								\
	संरचना type *sle_अग्र;	/* next element */			\
}

/*
 * Singly-linked List access methods.
 */
#परिभाषय	SLIST_FIRST(शीर्ष)	((शीर्ष)->slh_first)
#परिभाषय	SLIST_अन्तः(शीर्ष)		रिक्त
#परिभाषय	SLIST_EMPTY(शीर्ष)	(SLIST_FIRST(शीर्ष) == SLIST_अन्तः(शीर्ष))
#परिभाषय	SLIST_NEXT(elm, क्षेत्रम्)	((elm)->क्षेत्रम्.sle_अग्र)

#परिभाषय	SLIST_FOREACH(var, शीर्ष, क्षेत्रम्)					\
	प्रति((var) = SLIST_FIRST(शीर्ष);					\
	    (var) != SLIST_अन्तः(शीर्ष);					\
	    (var) = SLIST_NEXT(var, क्षेत्रम्))

#परिभाषय	SLIST_FOREACH_SAFE(var, शीर्ष, क्षेत्रम्, tvar)			\
	प्रति ((var) = SLIST_FIRST(शीर्ष);				\
	    (var) && ((tvar) = SLIST_NEXT(var, क्षेत्रम्), 1);		\
	    (var) = (tvar))

/*
 * Singly-linked List functions.
 */
#परिभाषय	SLIST_INIT(शीर्ष) {						\
	SLIST_FIRST(शीर्ष) = SLIST_अन्तः(शीर्ष);				\
}

#परिभाषय	SLIST_INSERT_AFTER(slistelm, elm, क्षेत्रम्) कुरु {			\
	(elm)->क्षेत्रम्.sle_अग्र = (slistelm)->क्षेत्रम्.sle_अग्र;		\
	(slistelm)->क्षेत्रम्.sle_अग्र = (elm);				\
} यावत् (0)

#परिभाषय	SLIST_INSERT_HEAD(शीर्ष, elm, क्षेत्रम्) कुरु {			\
	(elm)->क्षेत्रम्.sle_अग्र = (शीर्ष)->slh_first;			\
	(शीर्ष)->slh_first = (elm);					\
} यावत् (0)

#परिभाषय	SLIST_REMOVE_AFTER(elm, क्षेत्रम्) कुरु {				\
	(elm)->क्षेत्रम्.sle_अग्र = (elm)->क्षेत्रम्.sle_अग्र->क्षेत्रम्.sle_अग्र;	\
} यावत् (0)

#परिभाषय	SLIST_REMOVE_HEAD(शीर्ष, क्षेत्रम्) कुरु {				\
	(शीर्ष)->slh_first = (शीर्ष)->slh_first->क्षेत्रम्.sle_अग्र;		\
} यावत् (0)

#परिभाषय SLIST_REMOVE(शीर्ष, elm, type, क्षेत्रम्) कुरु {			\
	यदि ((शीर्ष)->slh_first == (elm)) {				\
		SLIST_REMOVE_HEAD((शीर्ष), क्षेत्रम्);			\
	} अन्यथा {							\
		संरचना type *curelm = (शीर्ष)->slh_first;		\
									\
		यावत् (curelm->क्षेत्रम्.sle_अग्र != (elm))			\
			curelm = curelm->क्षेत्रम्.sle_अग्र;		\
		curelm->क्षेत्रम्.sle_अग्र =				\
		    curelm->क्षेत्रम्.sle_अग्र->क्षेत्रम्.sle_अग्र;		\
	}								\
	_Q_INVALIDATE((elm)->क्षेत्रम्.sle_अग्र);				\
} यावत् (0)

/*
 * List definitions.
 */
#परिभाषय LIST_HEAD(name, type)						\
संरचना name {								\
	संरचना type *lh_first;	/* first element */			\
}

#परिभाषय LIST_HEAD_INITIALIZER(शीर्ष)					\
	{ रिक्त }

#परिभाषय LIST_ENTRY(type)						\
संरचना {								\
	संरचना type *le_अग्र;	/* next element */			\
	संरचना type **le_पूर्व;	/* address of previous next element */	\
}

/*
 * List access methods.
 */
#परिभाषय	LIST_FIRST(शीर्ष)		((शीर्ष)->lh_first)
#परिभाषय	LIST_अन्तः(शीर्ष)			रिक्त
#परिभाषय	LIST_EMPTY(शीर्ष)		(LIST_FIRST(शीर्ष) == LIST_अन्तः(शीर्ष))
#परिभाषय	LIST_NEXT(elm, क्षेत्रम्)		((elm)->क्षेत्रम्.le_अग्र)

#परिभाषय LIST_FOREACH(var, शीर्ष, क्षेत्रम्)					\
	प्रति((var) = LIST_FIRST(शीर्ष);					\
	    (var)!= LIST_अन्तः(शीर्ष);					\
	    (var) = LIST_NEXT(var, क्षेत्रम्))

#परिभाषय	LIST_FOREACH_SAFE(var, शीर्ष, क्षेत्रम्, tvar)			\
	प्रति ((var) = LIST_FIRST(शीर्ष);				\
	    (var) && ((tvar) = LIST_NEXT(var, क्षेत्रम्), 1);		\
	    (var) = (tvar))

/*
 * List functions.
 */
#परिभाषय	LIST_INIT(शीर्ष) कुरु {						\
	LIST_FIRST(शीर्ष) = LIST_अन्तः(शीर्ष);				\
} यावत् (0)

#परिभाषय LIST_INSERT_AFTER(listelm, elm, क्षेत्रम्) कुरु {			\
	यदि (((elm)->क्षेत्रम्.le_अग्र = (listelm)->क्षेत्रम्.le_अग्र) != रिक्त)	\
		(listelm)->क्षेत्रम्.le_अग्र->क्षेत्रम्.le_पूर्व =		\
		    &(elm)->क्षेत्रम्.le_अग्र;				\
	(listelm)->क्षेत्रम्.le_अग्र = (elm);				\
	(elm)->क्षेत्रम्.le_पूर्व = &(listelm)->क्षेत्रम्.le_अग्र;		\
} यावत् (0)

#परिभाषय	LIST_INSERT_BEFORE(listelm, elm, क्षेत्रम्) कुरु {			\
	(elm)->क्षेत्रम्.le_पूर्व = (listelm)->क्षेत्रम्.le_पूर्व;		\
	(elm)->क्षेत्रम्.le_अग्र = (listelm);				\
	*(listelm)->क्षेत्रम्.le_पूर्व = (elm);				\
	(listelm)->क्षेत्रम्.le_पूर्व = &(elm)->क्षेत्रम्.le_अग्र;		\
} यावत् (0)

#परिभाषय LIST_INSERT_HEAD(शीर्ष, elm, क्षेत्रम्) कुरु {				\
	यदि (((elm)->क्षेत्रम्.le_अग्र = (शीर्ष)->lh_first) != रिक्त)		\
		(शीर्ष)->lh_first->क्षेत्रम्.le_पूर्व = &(elm)->क्षेत्रम्.le_अग्र;\
	(शीर्ष)->lh_first = (elm);					\
	(elm)->क्षेत्रम्.le_पूर्व = &(शीर्ष)->lh_first;			\
} यावत् (0)

#परिभाषय LIST_REMOVE(elm, क्षेत्रम्) कुरु {					\
	यदि ((elm)->क्षेत्रम्.le_अग्र != रिक्त)				\
		(elm)->क्षेत्रम्.le_अग्र->क्षेत्रम्.le_पूर्व =			\
		    (elm)->क्षेत्रम्.le_पूर्व;				\
	*(elm)->क्षेत्रम्.le_पूर्व = (elm)->क्षेत्रम्.le_अग्र;			\
	_Q_INVALIDATE((elm)->क्षेत्रम्.le_पूर्व);				\
	_Q_INVALIDATE((elm)->क्षेत्रम्.le_अग्र);				\
} यावत् (0)

#परिभाषय LIST_REPLACE(elm, elm2, क्षेत्रम्) कुरु {				\
	यदि (((elm2)->क्षेत्रम्.le_अग्र = (elm)->क्षेत्रम्.le_अग्र) != रिक्त)	\
		(elm2)->क्षेत्रम्.le_अग्र->क्षेत्रम्.le_पूर्व =			\
		    &(elm2)->क्षेत्रम्.le_अग्र;				\
	(elm2)->क्षेत्रम्.le_पूर्व = (elm)->क्षेत्रम्.le_पूर्व;			\
	*(elm2)->क्षेत्रम्.le_पूर्व = (elm2);				\
	_Q_INVALIDATE((elm)->क्षेत्रम्.le_पूर्व);				\
	_Q_INVALIDATE((elm)->क्षेत्रम्.le_अग्र);				\
} यावत् (0)

/*
 * Simple queue definitions.
 */
#परिभाषय SIMPLEQ_HEAD(name, type)					\
संरचना name {								\
	संरचना type *sqh_first;	/* first element */			\
	संरचना type **sqh_चरमः;	/* addr of last next element */		\
}

#परिभाषय SIMPLEQ_HEAD_INITIALIZER(शीर्ष)					\
	{ रिक्त, &(शीर्ष).sqh_first }

#परिभाषय SIMPLEQ_ENTRY(type)						\
संरचना {								\
	संरचना type *sqe_अग्र;	/* next element */			\
}

/*
 * Simple queue access methods.
 */
#परिभाषय	SIMPLEQ_FIRST(शीर्ष)	    ((शीर्ष)->sqh_first)
#परिभाषय	SIMPLEQ_अन्तः(शीर्ष)	    रिक्त
#परिभाषय	SIMPLEQ_EMPTY(शीर्ष)	    (SIMPLEQ_FIRST(शीर्ष) == SIMPLEQ_अन्तः(शीर्ष))
#परिभाषय	SIMPLEQ_NEXT(elm, क्षेत्रम्)    ((elm)->क्षेत्रम्.sqe_अग्र)

#परिभाषय SIMPLEQ_FOREACH(var, शीर्ष, क्षेत्रम्)				\
	प्रति((var) = SIMPLEQ_FIRST(शीर्ष);				\
	    (var) != SIMPLEQ_अन्तः(शीर्ष);					\
	    (var) = SIMPLEQ_NEXT(var, क्षेत्रम्))

#परिभाषय	SIMPLEQ_FOREACH_SAFE(var, शीर्ष, क्षेत्रम्, tvar)			\
	प्रति ((var) = SIMPLEQ_FIRST(शीर्ष);				\
	    (var) && ((tvar) = SIMPLEQ_NEXT(var, क्षेत्रम्), 1);		\
	    (var) = (tvar))

/*
 * Simple queue functions.
 */
#परिभाषय	SIMPLEQ_INIT(शीर्ष) कुरु {						\
	(शीर्ष)->sqh_first = रिक्त;					\
	(शीर्ष)->sqh_चरमः = &(शीर्ष)->sqh_first;				\
} यावत् (0)

#परिभाषय SIMPLEQ_INSERT_HEAD(शीर्ष, elm, क्षेत्रम्) कुरु {			\
	यदि (((elm)->क्षेत्रम्.sqe_अग्र = (शीर्ष)->sqh_first) == रिक्त)	\
		(शीर्ष)->sqh_चरमः = &(elm)->क्षेत्रम्.sqe_अग्र;		\
	(शीर्ष)->sqh_first = (elm);					\
} यावत् (0)

#परिभाषय SIMPLEQ_INSERT_TAIL(शीर्ष, elm, क्षेत्रम्) कुरु {			\
	(elm)->क्षेत्रम्.sqe_अग्र = रिक्त;					\
	*(शीर्ष)->sqh_चरमः = (elm);					\
	(शीर्ष)->sqh_चरमः = &(elm)->क्षेत्रम्.sqe_अग्र;			\
} यावत् (0)

#परिभाषय SIMPLEQ_INSERT_AFTER(शीर्ष, listelm, elm, क्षेत्रम्) कुरु {		\
	यदि (((elm)->क्षेत्रम्.sqe_अग्र = (listelm)->क्षेत्रम्.sqe_अग्र) == रिक्त)\
		(शीर्ष)->sqh_चरमः = &(elm)->क्षेत्रम्.sqe_अग्र;		\
	(listelm)->क्षेत्रम्.sqe_अग्र = (elm);				\
} यावत् (0)

#परिभाषय SIMPLEQ_REMOVE_HEAD(शीर्ष, क्षेत्रम्) कुरु {			\
	यदि (((शीर्ष)->sqh_first = (शीर्ष)->sqh_first->क्षेत्रम्.sqe_अग्र) == रिक्त) \
		(शीर्ष)->sqh_चरमः = &(शीर्ष)->sqh_first;			\
} यावत् (0)

#परिभाषय SIMPLEQ_REMOVE_AFTER(शीर्ष, elm, क्षेत्रम्) कुरु {			\
	यदि (((elm)->क्षेत्रम्.sqe_अग्र = (elm)->क्षेत्रम्.sqe_अग्र->क्षेत्रम्.sqe_अग्र) \
	    == रिक्त)							\
		(शीर्ष)->sqh_चरमः = &(elm)->क्षेत्रम्.sqe_अग्र;		\
} यावत् (0)

#परिभाषय SIMPLEQ_CONCAT(head1, head2) कुरु {				\
	यदि (!SIMPLEQ_EMPTY((head2))) {					\
		*(head1)->sqh_चरमः = (head2)->sqh_first;		\
		(head1)->sqh_चरमः = (head2)->sqh_चरमः;			\
		SIMPLEQ_INIT((head2));					\
	}								\
} यावत् (0)

/*
 * XOR Simple queue definitions.
 */
#परिभाषय XSIMPLEQ_शीर्ष(name, type)					\
संरचना name {								\
	संरचना type *sqx_first;	/* first element */			\
	संरचना type **sqx_चरमः;	/* addr of last next element */		\
	अचिह्नित दीर्घ sqx_cookie;					\
}

#परिभाषय XSIMPLEQ_प्रविष्टिः(type)						\
संरचना {								\
	संरचना type *sqx_अग्र;	/* next element */			\
}

/*
 * XOR Simple queue access methods.
 */
#परिभाषय XSIMPLEQ_XOR(शीर्ष, ptr)	    ((__typeof(ptr))((शीर्ष)->sqx_cookie ^ \
					(अचिह्नित दीर्घ)(ptr)))
#परिभाषय	XSIMPLEQ_FIRST(शीर्ष)	    XSIMPLEQ_XOR(शीर्ष, ((शीर्ष)->sqx_first))
#परिभाषय	XSIMPLEQ_अन्तः(शीर्ष)	    रिक्त
#परिभाषय	XSIMPLEQ_रिक्तानि(शीर्ष)	    (XSIMPLEQ_FIRST(शीर्ष) == XSIMPLEQ_अन्तः(शीर्ष))
#परिभाषय	XSIMPLEQ_अग्र(शीर्ष, elm, क्षेत्रम्)    XSIMPLEQ_XOR(शीर्ष, ((elm)->क्षेत्रम्.sqx_अग्र))


#परिभाषय XSIMPLEQ_FOREACH(var, शीर्ष, क्षेत्रम्)				\
	प्रति ((var) = XSIMPLEQ_FIRST(शीर्ष);				\
	    (var) != XSIMPLEQ_अन्तः(शीर्ष);				\
	    (var) = XSIMPLEQ_अग्र(शीर्ष, var, क्षेत्रम्))

#परिभाषय	XSIMPLEQ_FOREACH_SAFE(var, शीर्ष, क्षेत्रम्, tvar)			\
	प्रति ((var) = XSIMPLEQ_FIRST(शीर्ष);				\
	    (var) && ((tvar) = XSIMPLEQ_अग्र(शीर्ष, var, क्षेत्रम्), 1);	\
	    (var) = (tvar))

/*
 * XOR Simple queue functions.
 */
#परिभाषय	XSIMPLEQ_INIT(शीर्ष) कुरु {					\
	arc4random_buf(&(शीर्ष)->sqx_cookie, परिमाण((शीर्ष)->sqx_cookie)); \
	(शीर्ष)->sqx_first = XSIMPLEQ_XOR(शीर्ष, रिक्त);			\
	(शीर्ष)->sqx_चरमः = XSIMPLEQ_XOR(शीर्ष, &(शीर्ष)->sqx_first);	\
} यावत् (0)

#परिभाषय XSIMPLEQ_निवेशय_शीर्ष(शीर्ष, elm, क्षेत्रम्) कुरु {			\
	यदि (((elm)->क्षेत्रम्.sqx_अग्र = (शीर्ष)->sqx_first) ==		\
	    XSIMPLEQ_XOR(शीर्ष, रिक्त))					\
		(शीर्ष)->sqx_चरमः = XSIMPLEQ_XOR(शीर्ष, &(elm)->क्षेत्रम्.sqx_अग्र); \
	(शीर्ष)->sqx_first = XSIMPLEQ_XOR(शीर्ष, (elm));			\
} यावत् (0)

#परिभाषय XSIMPLEQ_निवेशय_पुच्छ(शीर्ष, elm, क्षेत्रम्) कुरु {			\
	(elm)->क्षेत्रम्.sqx_अग्र = XSIMPLEQ_XOR(शीर्ष, रिक्त);		\
	*(XSIMPLEQ_XOR(शीर्ष, (शीर्ष)->sqx_चरमः)) = XSIMPLEQ_XOR(शीर्ष, (elm)); \
	(शीर्ष)->sqx_चरमः = XSIMPLEQ_XOR(शीर्ष, &(elm)->क्षेत्रम्.sqx_अग्र);	\
} यावत् (0)

#परिभाषय XSIMPLEQ_निवेशय_AFTER(शीर्ष, listelm, elm, क्षेत्रम्) कुरु {		\
	यदि (((elm)->क्षेत्रम्.sqx_अग्र = (listelm)->क्षेत्रम्.sqx_अग्र) ==	\
	    XSIMPLEQ_XOR(शीर्ष, रिक्त))					\
		(शीर्ष)->sqx_चरमः = XSIMPLEQ_XOR(शीर्ष, &(elm)->क्षेत्रम्.sqx_अग्र); \
	(listelm)->क्षेत्रम्.sqx_अग्र = XSIMPLEQ_XOR(शीर्ष, (elm));		\
} यावत् (0)

#परिभाषय XSIMPLEQ_REMOVE_शीर्ष(शीर्ष, क्षेत्रम्) कुरु {				\
	यदि (((शीर्ष)->sqx_first = XSIMPLEQ_XOR(शीर्ष,			\
	    (शीर्ष)->sqx_first)->क्षेत्रम्.sqx_अग्र) == XSIMPLEQ_XOR(शीर्ष, रिक्त)) \
		(शीर्ष)->sqx_चरमः = XSIMPLEQ_XOR(शीर्ष, &(शीर्ष)->sqx_first); \
} यावत् (0)

#परिभाषय XSIMPLEQ_REMOVE_AFTER(शीर्ष, elm, क्षेत्रम्) कुरु {			\
	यदि (((elm)->क्षेत्रम्.sqx_अग्र = XSIMPLEQ_XOR(शीर्ष,			\
	    (elm)->क्षेत्रम्.sqx_अग्र)->क्षेत्रम्.sqx_अग्र)			\
	    == XSIMPLEQ_XOR(शीर्ष, रिक्त))				\
		(शीर्ष)->sqx_चरमः = 					\
		    XSIMPLEQ_XOR(शीर्ष, &(elm)->क्षेत्रम्.sqx_अग्र);		\
} यावत् (0)


/*
 * Tail queue definitions.
 */
#परिभाषय TAILQ_HEAD(name, type)						\
संरचना name {								\
	संरचना type *tqh_first;	/* first element */			\
	संरचना type **tqh_last;	/* addr of last next element */		\
}

#परिभाषय TAILQ_HEAD_INITIALIZER(शीर्ष)					\
	{ रिक्त, &(शीर्ष).tqh_first }

#परिभाषय TAILQ_ENTRY(type)						\
संरचना {								\
	संरचना type *tqe_next;	/* next element */			\
	संरचना type **tqe_prev;	/* address of previous next element */	\
}

/*
 * Tail queue access methods.
 */
#परिभाषय	TAILQ_FIRST(शीर्ष)		((शीर्ष)->tqh_first)
#परिभाषय	TAILQ_अन्तः(शीर्ष)			रिक्त
#परिभाषय	TAILQ_NEXT(elm, क्षेत्रम्)		((elm)->क्षेत्रम्.tqe_next)
#परिभाषय TAILQ_LAST(शीर्ष, headname)					\
	(*(((संरचना headname *)((शीर्ष)->tqh_last))->tqh_last))
/* XXX */
#परिभाषय TAILQ_PREV(elm, headname, क्षेत्रम्)				\
	(*(((संरचना headname *)((elm)->क्षेत्रम्.tqe_prev))->tqh_last))
#परिभाषय	TAILQ_EMPTY(शीर्ष)						\
	(TAILQ_FIRST(शीर्ष) == TAILQ_अन्तः(शीर्ष))

#परिभाषय TAILQ_FOREACH(var, शीर्ष, क्षेत्रम्)					\
	प्रति((var) = TAILQ_FIRST(शीर्ष);					\
	    (var) != TAILQ_अन्तः(शीर्ष);					\
	    (var) = TAILQ_NEXT(var, क्षेत्रम्))

#परिभाषय	TAILQ_FOREACH_SAFE(var, शीर्ष, क्षेत्रम्, tvar)			\
	प्रति ((var) = TAILQ_FIRST(शीर्ष);					\
	    (var) != TAILQ_अन्तः(शीर्ष) &&					\
	    ((tvar) = TAILQ_NEXT(var, क्षेत्रम्), 1);			\
	    (var) = (tvar))


#परिभाषय TAILQ_FOREACH_REVERSE(var, शीर्ष, headname, क्षेत्रम्)		\
	प्रति((var) = TAILQ_LAST(शीर्ष, headname);				\
	    (var) != TAILQ_अन्तः(शीर्ष);					\
	    (var) = TAILQ_PREV(var, headname, क्षेत्रम्))

#परिभाषय	TAILQ_FOREACH_REVERSE_SAFE(var, शीर्ष, headname, क्षेत्रम्, tvar)	\
	प्रति ((var) = TAILQ_LAST(शीर्ष, headname);			\
	    (var) != TAILQ_अन्तः(शीर्ष) &&					\
	    ((tvar) = TAILQ_PREV(var, headname, क्षेत्रम्), 1);		\
	    (var) = (tvar))

/*
 * Tail queue functions.
 */
#परिभाषय	TAILQ_INIT(शीर्ष) कुरु {						\
	(शीर्ष)->tqh_first = रिक्त;					\
	(शीर्ष)->tqh_last = &(शीर्ष)->tqh_first;				\
} यावत् (0)

#परिभाषय TAILQ_INSERT_HEAD(शीर्ष, elm, क्षेत्रम्) कुरु {			\
	यदि (((elm)->क्षेत्रम्.tqe_next = (शीर्ष)->tqh_first) != रिक्त)	\
		(शीर्ष)->tqh_first->क्षेत्रम्.tqe_prev =			\
		    &(elm)->क्षेत्रम्.tqe_next;				\
	अन्यथा								\
		(शीर्ष)->tqh_last = &(elm)->क्षेत्रम्.tqe_next;		\
	(शीर्ष)->tqh_first = (elm);					\
	(elm)->क्षेत्रम्.tqe_prev = &(शीर्ष)->tqh_first;			\
} यावत् (0)

#परिभाषय TAILQ_INSERT_TAIL(शीर्ष, elm, क्षेत्रम्) कुरु {			\
	(elm)->क्षेत्रम्.tqe_next = रिक्त;					\
	(elm)->क्षेत्रम्.tqe_prev = (शीर्ष)->tqh_last;			\
	*(शीर्ष)->tqh_last = (elm);					\
	(शीर्ष)->tqh_last = &(elm)->क्षेत्रम्.tqe_next;			\
} यावत् (0)

#परिभाषय TAILQ_INSERT_AFTER(शीर्ष, listelm, elm, क्षेत्रम्) कुरु {		\
	यदि (((elm)->क्षेत्रम्.tqe_next = (listelm)->क्षेत्रम्.tqe_next) != रिक्त)\
		(elm)->क्षेत्रम्.tqe_next->क्षेत्रम्.tqe_prev =			\
		    &(elm)->क्षेत्रम्.tqe_next;				\
	अन्यथा								\
		(शीर्ष)->tqh_last = &(elm)->क्षेत्रम्.tqe_next;		\
	(listelm)->क्षेत्रम्.tqe_next = (elm);				\
	(elm)->क्षेत्रम्.tqe_prev = &(listelm)->क्षेत्रम्.tqe_next;		\
} यावत् (0)

#परिभाषय	TAILQ_INSERT_BEFORE(listelm, elm, क्षेत्रम्) कुरु {			\
	(elm)->क्षेत्रम्.tqe_prev = (listelm)->क्षेत्रम्.tqe_prev;		\
	(elm)->क्षेत्रम्.tqe_next = (listelm);				\
	*(listelm)->क्षेत्रम्.tqe_prev = (elm);				\
	(listelm)->क्षेत्रम्.tqe_prev = &(elm)->क्षेत्रम्.tqe_next;		\
} यावत् (0)

#परिभाषय TAILQ_REMOVE(शीर्ष, elm, क्षेत्रम्) कुरु {				\
	यदि (((elm)->क्षेत्रम्.tqe_next) != रिक्त)				\
		(elm)->क्षेत्रम्.tqe_next->क्षेत्रम्.tqe_prev =			\
		    (elm)->क्षेत्रम्.tqe_prev;				\
	अन्यथा								\
		(शीर्ष)->tqh_last = (elm)->क्षेत्रम्.tqe_prev;		\
	*(elm)->क्षेत्रम्.tqe_prev = (elm)->क्षेत्रम्.tqe_next;			\
	_Q_INVALIDATE((elm)->क्षेत्रम्.tqe_prev);				\
	_Q_INVALIDATE((elm)->क्षेत्रम्.tqe_next);				\
} यावत् (0)

#परिभाषय TAILQ_REPLACE(शीर्ष, elm, elm2, क्षेत्रम्) कुरु {			\
	यदि (((elm2)->क्षेत्रम्.tqe_next = (elm)->क्षेत्रम्.tqe_next) != रिक्त)	\
		(elm2)->क्षेत्रम्.tqe_next->क्षेत्रम्.tqe_prev =		\
		    &(elm2)->क्षेत्रम्.tqe_next;				\
	अन्यथा								\
		(शीर्ष)->tqh_last = &(elm2)->क्षेत्रम्.tqe_next;		\
	(elm2)->क्षेत्रम्.tqe_prev = (elm)->क्षेत्रम्.tqe_prev;			\
	*(elm2)->क्षेत्रम्.tqe_prev = (elm2);				\
	_Q_INVALIDATE((elm)->क्षेत्रम्.tqe_prev);				\
	_Q_INVALIDATE((elm)->क्षेत्रम्.tqe_next);				\
} यावत् (0)

#परिभाषय TAILQ_CONCAT(head1, head2, क्षेत्रम्) कुरु {				\
	यदि (!TAILQ_EMPTY(head2)) {					\
		*(head1)->tqh_last = (head2)->tqh_first;		\
		(head2)->tqh_first->क्षेत्रम्.tqe_prev = (head1)->tqh_last;	\
		(head1)->tqh_last = (head2)->tqh_last;			\
		TAILQ_INIT((head2));					\
	}								\
} यावत् (0)

#यदि_अन्तः	/* !_SYS_QUEUE_H_ */
