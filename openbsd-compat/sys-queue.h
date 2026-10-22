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

#अगर_अघोषित	_FAKE_QUEUE_H_
#घोषणा	_FAKE_QUEUE_H_

/*
 * Require for OS/X and other platforms that have old/broken/incomplete
 * <sys/queue.h>.
 */
#अघोषित CIRCLEQ_EMPTY
#अघोषित CIRCLEQ_END
#अघोषित CIRCLEQ_ENTRY
#अघोषित CIRCLEQ_FIRST
#अघोषित CIRCLEQ_FOREACH
#अघोषित CIRCLEQ_FOREACH_REVERSE
#अघोषित CIRCLEQ_HEAD
#अघोषित CIRCLEQ_HEAD_INITIALIZER
#अघोषित CIRCLEQ_INIT
#अघोषित CIRCLEQ_INSERT_AFTER
#अघोषित CIRCLEQ_INSERT_BEFORE
#अघोषित CIRCLEQ_INSERT_HEAD
#अघोषित CIRCLEQ_INSERT_TAIL
#अघोषित CIRCLEQ_LAST
#अघोषित CIRCLEQ_NEXT
#अघोषित CIRCLEQ_PREV
#अघोषित CIRCLEQ_REMOVE
#अघोषित CIRCLEQ_REPLACE
#अघोषित LIST_EMPTY
#अघोषित LIST_END
#अघोषित LIST_ENTRY
#अघोषित LIST_FIRST
#अघोषित LIST_FOREACH
#अघोषित LIST_FOREACH_SAFE
#अघोषित LIST_HEAD
#अघोषित LIST_HEAD_INITIALIZER
#अघोषित LIST_INIT
#अघोषित LIST_INSERT_AFTER
#अघोषित LIST_INSERT_BEFORE
#अघोषित LIST_INSERT_HEAD
#अघोषित LIST_NEXT
#अघोषित LIST_REMOVE
#अघोषित LIST_REPLACE
#अघोषित SIMPLEQ_CONCAT
#अघोषित SIMPLEQ_EMPTY
#अघोषित SIMPLEQ_END
#अघोषित SIMPLEQ_ENTRY
#अघोषित SIMPLEQ_FIRST
#अघोषित SIMPLEQ_FOREACH
#अघोषित SIMPLEQ_FOREACH_SAFE
#अघोषित SIMPLEQ_HEAD
#अघोषित SIMPLEQ_HEAD_INITIALIZER
#अघोषित SIMPLEQ_INIT
#अघोषित SIMPLEQ_INSERT_AFTER
#अघोषित SIMPLEQ_INSERT_HEAD
#अघोषित SIMPLEQ_INSERT_TAIL
#अघोषित SIMPLEQ_NEXT
#अघोषित SIMPLEQ_REMOVE_AFTER
#अघोषित SIMPLEQ_REMOVE_HEAD
#अघोषित SLIST_EMPTY
#अघोषित SLIST_END
#अघोषित SLIST_ENTRY
#अघोषित SLIST_FIRST
#अघोषित SLIST_FOREACH
#अघोषित SLIST_FOREACH_PREVPTR
#अघोषित SLIST_FOREACH_SAFE
#अघोषित SLIST_HEAD
#अघोषित SLIST_HEAD_INITIALIZER
#अघोषित SLIST_INIT
#अघोषित SLIST_INSERT_AFTER
#अघोषित SLIST_INSERT_HEAD
#अघोषित SLIST_NEXT
#अघोषित SLIST_REMOVE
#अघोषित SLIST_REMOVE_AFTER
#अघोषित SLIST_REMOVE_HEAD
#अघोषित SLIST_REMOVE_अग्र
#अघोषित TAILQ_CONCAT
#अघोषित TAILQ_EMPTY
#अघोषित TAILQ_END
#अघोषित TAILQ_ENTRY
#अघोषित TAILQ_FIRST
#अघोषित TAILQ_FOREACH
#अघोषित TAILQ_FOREACH_REVERSE
#अघोषित TAILQ_FOREACH_REVERSE_SAFE
#अघोषित TAILQ_FOREACH_SAFE
#अघोषित TAILQ_HEAD
#अघोषित TAILQ_HEAD_INITIALIZER
#अघोषित TAILQ_INIT
#अघोषित TAILQ_INSERT_AFTER
#अघोषित TAILQ_INSERT_BEFORE
#अघोषित TAILQ_INSERT_HEAD
#अघोषित TAILQ_INSERT_TAIL
#अघोषित TAILQ_LAST
#अघोषित TAILQ_NEXT
#अघोषित TAILQ_PREV
#अघोषित TAILQ_REMOVE
#अघोषित TAILQ_REPLACE

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

#अगर defined(QUEUE_MACRO_DEBUG) || (defined(_KERNEL) && defined(DIAGNOSTIC))
#घोषणा _Q_INVALID ((व्योम *)-1)
#घोषणा _Q_INVALIDATE(a) (a) = _Q_INVALID
#अन्यथा
#घोषणा _Q_INVALIDATE(a)
#पूर्ण_अगर

/*
 * Singly-linked List definitions.
 */
#घोषणा SLIST_HEAD(name, type)						\
काष्ठा name {								\
	काष्ठा type *slh_first;	/* first element */			\
}

#घोषणा	SLIST_HEAD_INITIALIZER(शीर्ष_2)					\
	{ शून्य }

#घोषणा SLIST_ENTRY(type)						\
काष्ठा {								\
	काष्ठा type *sle_अग्र;	/* next element */			\
}

/*
 * Singly-linked List access methods.
 */
#घोषणा	SLIST_FIRST(शीर्ष_2)	((शीर्ष_2)->slh_first)
#घोषणा	SLIST_END(शीर्ष_2)		शून्य
#घोषणा	SLIST_EMPTY(शीर्ष_2)	(SLIST_FIRST(शीर्ष_2) == SLIST_END(शीर्ष_2))
#घोषणा	SLIST_NEXT(elm, field)	((elm)->field.sle_अग्र)

#घोषणा	SLIST_FOREACH(var, शीर्ष_2, field)					\
	क्रम((var) = SLIST_FIRST(शीर्ष_2);					\
	    (var) != SLIST_END(शीर्ष_2);					\
	    (var) = SLIST_NEXT(var, field))

#घोषणा	SLIST_FOREACH_SAFE(var, शीर्ष_2, field, tvar)			\
	क्रम ((var) = SLIST_FIRST(शीर्ष_2);				\
	    (var) && ((tvar) = SLIST_NEXT(var, field), 1);		\
	    (var) = (tvar))

/*
 * Singly-linked List functions.
 */
#घोषणा	SLIST_INIT(शीर्ष_2) {						\
	SLIST_FIRST(शीर्ष_2) = SLIST_END(शीर्ष_2);				\
}

#घोषणा	SLIST_INSERT_AFTER(slistelm, elm, field) करो {			\
	(elm)->field.sle_अग्र = (slistelm)->field.sle_अग्र;		\
	(slistelm)->field.sle_अग्र = (elm);				\
} जबतक (0)

#घोषणा	SLIST_INSERT_HEAD(शीर्ष_2, elm, field) करो {			\
	(elm)->field.sle_अग्र = (शीर्ष_2)->slh_first;			\
	(शीर्ष_2)->slh_first = (elm);					\
} जबतक (0)

#घोषणा	SLIST_REMOVE_AFTER(elm, field) करो {				\
	(elm)->field.sle_अग्र = (elm)->field.sle_अग्र->field.sle_अग्र;	\
} जबतक (0)

#घोषणा	SLIST_REMOVE_HEAD(शीर्ष_2, field) करो {				\
	(शीर्ष_2)->slh_first = (शीर्ष_2)->slh_first->field.sle_अग्र;		\
} जबतक (0)

#घोषणा SLIST_REMOVE(शीर्ष_2, elm, type, field) करो {			\
	अगर ((शीर्ष_2)->slh_first == (elm)) {				\
		SLIST_REMOVE_HEAD((शीर्ष_2), field);			\
	} अन्यथा {							\
		काष्ठा type *curelm = (शीर्ष_2)->slh_first;		\
									\
		जबतक (curelm->field.sle_अग्र != (elm))			\
			curelm = curelm->field.sle_अग्र;		\
		curelm->field.sle_अग्र =				\
		    curelm->field.sle_अग्र->field.sle_अग्र;		\
	}								\
	_Q_INVALIDATE((elm)->field.sle_अग्र);				\
} जबतक (0)

/*
 * List definitions.
 */
#घोषणा LIST_HEAD(name, type)						\
काष्ठा name {								\
	काष्ठा type *lh_first;	/* first element */			\
}

#घोषणा LIST_HEAD_INITIALIZER(शीर्ष_2)					\
	{ शून्य }

#घोषणा LIST_ENTRY(type)						\
काष्ठा {								\
	काष्ठा type *le_अग्र;	/* next element */			\
	काष्ठा type **le_पूर्व;	/* address of previous next element */	\
}

/*
 * List access methods.
 */
#घोषणा	LIST_FIRST(शीर्ष_2)		((शीर्ष_2)->lh_first)
#घोषणा	LIST_END(शीर्ष_2)			शून्य
#घोषणा	LIST_EMPTY(शीर्ष_2)		(LIST_FIRST(शीर्ष_2) == LIST_END(शीर्ष_2))
#घोषणा	LIST_NEXT(elm, field)		((elm)->field.le_अग्र)

#घोषणा LIST_FOREACH(var, शीर्ष_2, field)					\
	क्रम((var) = LIST_FIRST(शीर्ष_2);					\
	    (var)!= LIST_END(शीर्ष_2);					\
	    (var) = LIST_NEXT(var, field))

#घोषणा	LIST_FOREACH_SAFE(var, शीर्ष_2, field, tvar)			\
	क्रम ((var) = LIST_FIRST(शीर्ष_2);				\
	    (var) && ((tvar) = LIST_NEXT(var, field), 1);		\
	    (var) = (tvar))

/*
 * List functions.
 */
#घोषणा	LIST_INIT(शीर्ष_2) करो {						\
	LIST_FIRST(शीर्ष_2) = LIST_END(शीर्ष_2);				\
} जबतक (0)

#घोषणा LIST_INSERT_AFTER(listelm, elm, field) करो {			\
	अगर (((elm)->field.le_अग्र = (listelm)->field.le_अग्र) != शून्य)	\
		(listelm)->field.le_अग्र->field.le_पूर्व =		\
		    &(elm)->field.le_अग्र;				\
	(listelm)->field.le_अग्र = (elm);				\
	(elm)->field.le_पूर्व = &(listelm)->field.le_अग्र;		\
} जबतक (0)

#घोषणा	LIST_INSERT_BEFORE(listelm, elm, field) करो {			\
	(elm)->field.le_पूर्व = (listelm)->field.le_पूर्व;		\
	(elm)->field.le_अग्र = (listelm);				\
	*(listelm)->field.le_पूर्व = (elm);				\
	(listelm)->field.le_पूर्व = &(elm)->field.le_अग्र;		\
} जबतक (0)

#घोषणा LIST_INSERT_HEAD(शीर्ष_2, elm, field) करो {				\
	अगर (((elm)->field.le_अग्र = (शीर्ष_2)->lh_first) != शून्य)		\
		(शीर्ष_2)->lh_first->field.le_पूर्व = &(elm)->field.le_अग्र;\
	(शीर्ष_2)->lh_first = (elm);					\
	(elm)->field.le_पूर्व = &(शीर्ष_2)->lh_first;			\
} जबतक (0)

#घोषणा LIST_REMOVE(elm, field) करो {					\
	अगर ((elm)->field.le_अग्र != शून्य)				\
		(elm)->field.le_अग्र->field.le_पूर्व =			\
		    (elm)->field.le_पूर्व;				\
	*(elm)->field.le_पूर्व = (elm)->field.le_अग्र;			\
	_Q_INVALIDATE((elm)->field.le_पूर्व);				\
	_Q_INVALIDATE((elm)->field.le_अग्र);				\
} जबतक (0)

#घोषणा LIST_REPLACE(elm, elm2, field) करो {				\
	अगर (((elm2)->field.le_अग्र = (elm)->field.le_अग्र) != शून्य)	\
		(elm2)->field.le_अग्र->field.le_पूर्व =			\
		    &(elm2)->field.le_अग्र;				\
	(elm2)->field.le_पूर्व = (elm)->field.le_पूर्व;			\
	*(elm2)->field.le_पूर्व = (elm2);				\
	_Q_INVALIDATE((elm)->field.le_पूर्व);				\
	_Q_INVALIDATE((elm)->field.le_अग्र);				\
} जबतक (0)

/*
 * Simple queue definitions.
 */
#घोषणा SIMPLEQ_HEAD(name, type)					\
काष्ठा name {								\
	काष्ठा type *sqh_first;	/* first element */			\
	काष्ठा type **sqh_last;	/* addr of last next element */		\
}

#घोषणा SIMPLEQ_HEAD_INITIALIZER(शीर्ष_2)					\
	{ शून्य, &(शीर्ष_2).sqh_first }

#घोषणा SIMPLEQ_ENTRY(type)						\
काष्ठा {								\
	काष्ठा type *sqe_अग्र;	/* next element */			\
}

/*
 * Simple queue access methods.
 */
#घोषणा	SIMPLEQ_FIRST(शीर्ष_2)	    ((शीर्ष_2)->sqh_first)
#घोषणा	SIMPLEQ_END(शीर्ष_2)	    शून्य
#घोषणा	SIMPLEQ_EMPTY(शीर्ष_2)	    (SIMPLEQ_FIRST(शीर्ष_2) == SIMPLEQ_END(शीर्ष_2))
#घोषणा	SIMPLEQ_NEXT(elm, field)    ((elm)->field.sqe_अग्र)

#घोषणा SIMPLEQ_FOREACH(var, शीर्ष_2, field)				\
	क्रम((var) = SIMPLEQ_FIRST(शीर्ष_2);				\
	    (var) != SIMPLEQ_END(शीर्ष_2);					\
	    (var) = SIMPLEQ_NEXT(var, field))

#घोषणा	SIMPLEQ_FOREACH_SAFE(var, शीर्ष_2, field, tvar)			\
	क्रम ((var) = SIMPLEQ_FIRST(शीर्ष_2);				\
	    (var) && ((tvar) = SIMPLEQ_NEXT(var, field), 1);		\
	    (var) = (tvar))

/*
 * Simple queue functions.
 */
#घोषणा	SIMPLEQ_INIT(शीर्ष_2) करो {						\
	(शीर्ष_2)->sqh_first = शून्य;					\
	(शीर्ष_2)->sqh_last = &(शीर्ष_2)->sqh_first;				\
} जबतक (0)

#घोषणा SIMPLEQ_INSERT_HEAD(शीर्ष_2, elm, field) करो {			\
	अगर (((elm)->field.sqe_अग्र = (शीर्ष_2)->sqh_first) == शून्य)	\
		(शीर्ष_2)->sqh_last = &(elm)->field.sqe_अग्र;		\
	(शीर्ष_2)->sqh_first = (elm);					\
} जबतक (0)

#घोषणा SIMPLEQ_INSERT_TAIL(शीर्ष_2, elm, field) करो {			\
	(elm)->field.sqe_अग्र = शून्य;					\
	*(शीर्ष_2)->sqh_last = (elm);					\
	(शीर्ष_2)->sqh_last = &(elm)->field.sqe_अग्र;			\
} जबतक (0)

#घोषणा SIMPLEQ_INSERT_AFTER(शीर्ष_2, listelm, elm, field) करो {		\
	अगर (((elm)->field.sqe_अग्र = (listelm)->field.sqe_अग्र) == शून्य)\
		(शीर्ष_2)->sqh_last = &(elm)->field.sqe_अग्र;		\
	(listelm)->field.sqe_अग्र = (elm);				\
} जबतक (0)

#घोषणा SIMPLEQ_REMOVE_HEAD(शीर्ष_2, field) करो {			\
	अगर (((शीर्ष_2)->sqh_first = (शीर्ष_2)->sqh_first->field.sqe_अग्र) == शून्य) \
		(शीर्ष_2)->sqh_last = &(शीर्ष_2)->sqh_first;			\
} जबतक (0)

#घोषणा SIMPLEQ_REMOVE_AFTER(शीर्ष_2, elm, field) करो {			\
	अगर (((elm)->field.sqe_अग्र = (elm)->field.sqe_अग्र->field.sqe_अग्र) \
	    == शून्य)							\
		(शीर्ष_2)->sqh_last = &(elm)->field.sqe_अग्र;		\
} जबतक (0)

#घोषणा SIMPLEQ_CONCAT(head1, head2) करो {				\
	अगर (!SIMPLEQ_EMPTY((head2))) {					\
		*(head1)->sqh_last = (head2)->sqh_first;		\
		(head1)->sqh_last = (head2)->sqh_last;			\
		SIMPLEQ_INIT((head2));					\
	}								\
} जबतक (0)

/*
 * XOR Simple queue definitions.
 */
#घोषणा XSIMPLEQ_शीर्ष(name, type)					\
काष्ठा name {								\
	काष्ठा type *sqx_first;	/* first element */			\
	काष्ठा type **sqx_last;	/* addr of last next element */		\
	अचिन्हित दीर्घ sqx_cookie;					\
}

#घोषणा XSIMPLEQ_ENTRY(type)						\
काष्ठा {								\
	काष्ठा type *sqx_अग्र;	/* next element */			\
}

/*
 * XOR Simple queue access methods.
 */
#घोषणा XSIMPLEQ_XOR(शीर्ष_2, ptr)	    ((__typeof(ptr))((शीर्ष_2)->sqx_cookie ^ \
					(अचिन्हित दीर्घ)(ptr)))
#घोषणा	XSIMPLEQ_FIRST(शीर्ष_2)	    XSIMPLEQ_XOR(शीर्ष_2, ((शीर्ष_2)->sqx_first))
#घोषणा	XSIMPLEQ_END(शीर्ष_2)	    शून्य
#घोषणा	XSIMPLEQ_EMPTY(शीर्ष_2)	    (XSIMPLEQ_FIRST(शीर्ष_2) == XSIMPLEQ_END(शीर्ष_2))
#घोषणा	XSIMPLEQ_अग्र(शीर्ष_2, elm, field)    XSIMPLEQ_XOR(शीर्ष_2, ((elm)->field.sqx_अग्र))


#घोषणा XSIMPLEQ_FOREACH(var, शीर्ष_2, field)				\
	क्रम ((var) = XSIMPLEQ_FIRST(शीर्ष_2);				\
	    (var) != XSIMPLEQ_END(शीर्ष_2);				\
	    (var) = XSIMPLEQ_अग्र(शीर्ष_2, var, field))

#घोषणा	XSIMPLEQ_FOREACH_SAFE(var, शीर्ष_2, field, tvar)			\
	क्रम ((var) = XSIMPLEQ_FIRST(शीर्ष_2);				\
	    (var) && ((tvar) = XSIMPLEQ_अग्र(शीर्ष_2, var, field), 1);	\
	    (var) = (tvar))

/*
 * XOR Simple queue functions.
 */
#घोषणा	XSIMPLEQ_INIT(शीर्ष_2) करो {					\
	arc4random_buf(&(शीर्ष_2)->sqx_cookie, माप((शीर्ष_2)->sqx_cookie)); \
	(शीर्ष_2)->sqx_first = XSIMPLEQ_XOR(शीर्ष_2, शून्य);			\
	(शीर्ष_2)->sqx_last = XSIMPLEQ_XOR(शीर्ष_2, &(शीर्ष_2)->sqx_first);	\
} जबतक (0)

#घोषणा XSIMPLEQ_जोड़ो_शीर्ष(शीर्ष_2, elm, field) करो {			\
	अगर (((elm)->field.sqx_अग्र = (शीर्ष_2)->sqx_first) ==		\
	    XSIMPLEQ_XOR(शीर्ष_2, शून्य))					\
		(शीर्ष_2)->sqx_last = XSIMPLEQ_XOR(शीर्ष_2, &(elm)->field.sqx_अग्र); \
	(शीर्ष_2)->sqx_first = XSIMPLEQ_XOR(शीर्ष_2, (elm));			\
} जबतक (0)

#घोषणा XSIMPLEQ_जोड़ो_पुच्छ(शीर्ष_2, elm, field) करो {			\
	(elm)->field.sqx_अग्र = XSIMPLEQ_XOR(शीर्ष_2, शून्य);		\
	*(XSIMPLEQ_XOR(शीर्ष_2, (शीर्ष_2)->sqx_last)) = XSIMPLEQ_XOR(शीर्ष_2, (elm)); \
	(शीर्ष_2)->sqx_last = XSIMPLEQ_XOR(शीर्ष_2, &(elm)->field.sqx_अग्र);	\
} जबतक (0)

#घोषणा XSIMPLEQ_जोड़ो_AFTER(शीर्ष_2, listelm, elm, field) करो {		\
	अगर (((elm)->field.sqx_अग्र = (listelm)->field.sqx_अग्र) ==	\
	    XSIMPLEQ_XOR(शीर्ष_2, शून्य))					\
		(शीर्ष_2)->sqx_last = XSIMPLEQ_XOR(शीर्ष_2, &(elm)->field.sqx_अग्र); \
	(listelm)->field.sqx_अग्र = XSIMPLEQ_XOR(शीर्ष_2, (elm));		\
} जबतक (0)

#घोषणा XSIMPLEQ_REMOVE_शीर्ष(शीर्ष_2, field) करो {				\
	अगर (((शीर्ष_2)->sqx_first = XSIMPLEQ_XOR(शीर्ष_2,			\
	    (शीर्ष_2)->sqx_first)->field.sqx_अग्र) == XSIMPLEQ_XOR(शीर्ष_2, शून्य)) \
		(शीर्ष_2)->sqx_last = XSIMPLEQ_XOR(शीर्ष_2, &(शीर्ष_2)->sqx_first); \
} जबतक (0)

#घोषणा XSIMPLEQ_REMOVE_AFTER(शीर्ष_2, elm, field) करो {			\
	अगर (((elm)->field.sqx_अग्र = XSIMPLEQ_XOR(शीर्ष_2,			\
	    (elm)->field.sqx_अग्र)->field.sqx_अग्र)			\
	    == XSIMPLEQ_XOR(शीर्ष_2, शून्य))				\
		(शीर्ष_2)->sqx_last = 					\
		    XSIMPLEQ_XOR(शीर्ष_2, &(elm)->field.sqx_अग्र);		\
} जबतक (0)


/*
 * Tail queue definitions.
 */
#घोषणा TAILQ_HEAD(name, type)						\
काष्ठा name {								\
	काष्ठा type *tqh_first;	/* first element */			\
	काष्ठा type **tqh_last;	/* addr of last next element */		\
}

#घोषणा TAILQ_HEAD_INITIALIZER(शीर्ष_2)					\
	{ शून्य, &(शीर्ष_2).tqh_first }

#घोषणा TAILQ_ENTRY(type)						\
काष्ठा {								\
	काष्ठा type *tqe_next;	/* next element */			\
	काष्ठा type **tqe_prev;	/* address of previous next element */	\
}

/*
 * Tail queue access methods.
 */
#घोषणा	TAILQ_FIRST(शीर्ष_2)		((शीर्ष_2)->tqh_first)
#घोषणा	TAILQ_END(शीर्ष_2)			शून्य
#घोषणा	TAILQ_NEXT(elm, field)		((elm)->field.tqe_next)
#घोषणा TAILQ_LAST(शीर्ष_2, headname)					\
	(*(((काष्ठा headname *)((शीर्ष_2)->tqh_last))->tqh_last))
/* XXX */
#घोषणा TAILQ_PREV(elm, headname, field)				\
	(*(((काष्ठा headname *)((elm)->field.tqe_prev))->tqh_last))
#घोषणा	TAILQ_EMPTY(शीर्ष_2)						\
	(TAILQ_FIRST(शीर्ष_2) == TAILQ_END(शीर्ष_2))

#घोषणा TAILQ_FOREACH(var, शीर्ष_2, field)					\
	क्रम((var) = TAILQ_FIRST(शीर्ष_2);					\
	    (var) != TAILQ_END(शीर्ष_2);					\
	    (var) = TAILQ_NEXT(var, field))

#घोषणा	TAILQ_FOREACH_SAFE(var, शीर्ष_2, field, tvar)			\
	क्रम ((var) = TAILQ_FIRST(शीर्ष_2);					\
	    (var) != TAILQ_END(शीर्ष_2) &&					\
	    ((tvar) = TAILQ_NEXT(var, field), 1);			\
	    (var) = (tvar))


#घोषणा TAILQ_FOREACH_REVERSE(var, शीर्ष_2, headname, field)		\
	क्रम((var) = TAILQ_LAST(शीर्ष_2, headname);				\
	    (var) != TAILQ_END(शीर्ष_2);					\
	    (var) = TAILQ_PREV(var, headname, field))

#घोषणा	TAILQ_FOREACH_REVERSE_SAFE(var, शीर्ष_2, headname, field, tvar)	\
	क्रम ((var) = TAILQ_LAST(शीर्ष_2, headname);			\
	    (var) != TAILQ_END(शीर्ष_2) &&					\
	    ((tvar) = TAILQ_PREV(var, headname, field), 1);		\
	    (var) = (tvar))

/*
 * Tail queue functions.
 */
#घोषणा	TAILQ_INIT(शीर्ष_2) करो {						\
	(शीर्ष_2)->tqh_first = शून्य;					\
	(शीर्ष_2)->tqh_last = &(शीर्ष_2)->tqh_first;				\
} जबतक (0)

#घोषणा TAILQ_INSERT_HEAD(शीर्ष_2, elm, field) करो {			\
	अगर (((elm)->field.tqe_next = (शीर्ष_2)->tqh_first) != शून्य)	\
		(शीर्ष_2)->tqh_first->field.tqe_prev =			\
		    &(elm)->field.tqe_next;				\
	अन्यथा								\
		(शीर्ष_2)->tqh_last = &(elm)->field.tqe_next;		\
	(शीर्ष_2)->tqh_first = (elm);					\
	(elm)->field.tqe_prev = &(शीर्ष_2)->tqh_first;			\
} जबतक (0)

#घोषणा TAILQ_INSERT_TAIL(शीर्ष_2, elm, field) करो {			\
	(elm)->field.tqe_next = शून्य;					\
	(elm)->field.tqe_prev = (शीर्ष_2)->tqh_last;			\
	*(शीर्ष_2)->tqh_last = (elm);					\
	(शीर्ष_2)->tqh_last = &(elm)->field.tqe_next;			\
} जबतक (0)

#घोषणा TAILQ_INSERT_AFTER(शीर्ष_2, listelm, elm, field) करो {		\
	अगर (((elm)->field.tqe_next = (listelm)->field.tqe_next) != शून्य)\
		(elm)->field.tqe_next->field.tqe_prev =			\
		    &(elm)->field.tqe_next;				\
	अन्यथा								\
		(शीर्ष_2)->tqh_last = &(elm)->field.tqe_next;		\
	(listelm)->field.tqe_next = (elm);				\
	(elm)->field.tqe_prev = &(listelm)->field.tqe_next;		\
} जबतक (0)

#घोषणा	TAILQ_INSERT_BEFORE(listelm, elm, field) करो {			\
	(elm)->field.tqe_prev = (listelm)->field.tqe_prev;		\
	(elm)->field.tqe_next = (listelm);				\
	*(listelm)->field.tqe_prev = (elm);				\
	(listelm)->field.tqe_prev = &(elm)->field.tqe_next;		\
} जबतक (0)

#घोषणा TAILQ_REMOVE(शीर्ष_2, elm, field) करो {				\
	अगर (((elm)->field.tqe_next) != शून्य)				\
		(elm)->field.tqe_next->field.tqe_prev =			\
		    (elm)->field.tqe_prev;				\
	अन्यथा								\
		(शीर्ष_2)->tqh_last = (elm)->field.tqe_prev;		\
	*(elm)->field.tqe_prev = (elm)->field.tqe_next;			\
	_Q_INVALIDATE((elm)->field.tqe_prev);				\
	_Q_INVALIDATE((elm)->field.tqe_next);				\
} जबतक (0)

#घोषणा TAILQ_REPLACE(शीर्ष_2, elm, elm2, field) करो {			\
	अगर (((elm2)->field.tqe_next = (elm)->field.tqe_next) != शून्य)	\
		(elm2)->field.tqe_next->field.tqe_prev =		\
		    &(elm2)->field.tqe_next;				\
	अन्यथा								\
		(शीर्ष_2)->tqh_last = &(elm2)->field.tqe_next;		\
	(elm2)->field.tqe_prev = (elm)->field.tqe_prev;			\
	*(elm2)->field.tqe_prev = (elm2);				\
	_Q_INVALIDATE((elm)->field.tqe_prev);				\
	_Q_INVALIDATE((elm)->field.tqe_next);				\
} जबतक (0)

#घोषणा TAILQ_CONCAT(head1, head2, field) करो {				\
	अगर (!TAILQ_EMPTY(head2)) {					\
		*(head1)->tqh_last = (head2)->tqh_first;		\
		(head2)->tqh_first->field.tqe_prev = (head1)->tqh_last;	\
		(head1)->tqh_last = (head2)->tqh_last;			\
		TAILQ_INIT((head2));					\
	}								\
} जबतक (0)

#पूर्ण_अगर	/* !_SYS_QUEUE_H_ */
