/*
 *	Process synchronisation
 *
 * Copyright 1996, 1997, 1998 Marcus Meissner
 * Copyright 1997, 1998, 1999 Alexandre Julliard
 * Copyright 1999, 2000 Juergen Schmied
 * Copyright 2003 Eric Pouech
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <limits.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#define NONAMELESSUNION
#include "windef.h"
#include "winternl.h"
#include "wine/debug.h"
<<<<<<< HEAD

=======
#include "wine/list.h"
>>>>>>> github-desktop-wine-mirror/master
#include "ntdll_misc.h"
#include "esync.h"

WINE_DEFAULT_DEBUG_CHANNEL(sync);
WINE_DECLARE_DEBUG_CHANNEL(relay);

static const char *debugstr_timeout( const LARGE_INTEGER *timeout )
{
<<<<<<< HEAD
    return syscall( __NR_futex, addr, FUTEX_WAIT | futex_private, val, timeout, 0, 0 );
}

static inline int futex_wake( const int *addr, int val )
{
    return syscall( __NR_futex, addr, FUTEX_WAKE | futex_private, val, NULL, 0, 0 );
}

static inline int futex_wait_bitset( const int *addr, int val, struct timespec *timeout, int mask )
{
    return syscall( __NR_futex, addr, FUTEX_WAIT_BITSET | futex_private, val, timeout, 0, mask );
}

static inline int futex_wake_bitset( const int *addr, int val, int mask )
{
    return syscall( __NR_futex, addr, FUTEX_WAKE_BITSET | futex_private, val, NULL, 0, mask );
}

static inline int use_futexes(void)
{
    static int supported = -1;

    if (supported == -1)
    {
        futex_wait( &supported, 10, NULL );
        if (errno == ENOSYS)
        {
            futex_private = 0;
            futex_wait( &supported, 10, NULL );
        }
        supported = (errno != ENOSYS);
    }
    return supported;
}

static int *get_futex(void **ptr)
{
    if (sizeof(void *) == 8)
        return (int *)((((ULONG_PTR)ptr) + 3) & ~3);
    else if (!(((ULONG_PTR)ptr) & 3))
        return (int *)ptr;
    else
        return NULL;
}

static void timespec_from_timeout( struct timespec *timespec, const LARGE_INTEGER *timeout )
{
    LARGE_INTEGER now;
    timeout_t diff;

    if (timeout->QuadPart > 0)
    {
        NtQuerySystemTime( &now );
        diff = timeout->QuadPart - now.QuadPart;
    }
    else
        diff = -timeout->QuadPart;

    timespec->tv_sec  = diff / TICKSPERSEC;
    timespec->tv_nsec = (diff % TICKSPERSEC) * 100;
}
#endif

/* creates a struct security_descriptor and contained information in one contiguous piece of memory */
NTSTATUS alloc_object_attributes( const OBJECT_ATTRIBUTES *attr, struct object_attributes **ret,
                                  data_size_t *ret_len )
{
    unsigned int len = sizeof(**ret);
    PSID owner = NULL, group = NULL;
    ACL *dacl, *sacl;
    BOOLEAN dacl_present, sacl_present, defaulted;
    PSECURITY_DESCRIPTOR sd;
    NTSTATUS status;

    *ret = NULL;
    *ret_len = 0;

    if (!attr) return STATUS_SUCCESS;

    if (attr->Length != sizeof(*attr)) return STATUS_INVALID_PARAMETER;

    if ((sd = attr->SecurityDescriptor))
    {
        len += sizeof(struct security_descriptor);

        if ((status = RtlGetOwnerSecurityDescriptor( sd, &owner, &defaulted ))) return status;
        if ((status = RtlGetGroupSecurityDescriptor( sd, &group, &defaulted ))) return status;
        if ((status = RtlGetSaclSecurityDescriptor( sd, &sacl_present, &sacl, &defaulted ))) return status;
        if ((status = RtlGetDaclSecurityDescriptor( sd, &dacl_present, &dacl, &defaulted ))) return status;
        if (owner) len += RtlLengthSid( owner );
        if (group) len += RtlLengthSid( group );
        if (sacl_present && sacl) len += sacl->AclSize;
        if (dacl_present && dacl) len += dacl->AclSize;

        /* fix alignment for the Unicode name that follows the structure */
        len = (len + sizeof(WCHAR) - 1) & ~(sizeof(WCHAR) - 1);
    }

    if (attr->ObjectName)
    {
        if (attr->ObjectName->Length & (sizeof(WCHAR) - 1)) return STATUS_OBJECT_NAME_INVALID;
        len += attr->ObjectName->Length;
    }
    else if (attr->RootDirectory) return STATUS_OBJECT_NAME_INVALID;

    len = (len + 3) & ~3;  /* DWORD-align the entire structure */

    *ret = RtlAllocateHeap( GetProcessHeap(), HEAP_ZERO_MEMORY, len );
    if (!*ret) return STATUS_NO_MEMORY;

    (*ret)->rootdir = wine_server_obj_handle( attr->RootDirectory );
    (*ret)->attributes = attr->Attributes;

    if (attr->SecurityDescriptor)
    {
        struct security_descriptor *descr = (struct security_descriptor *)(*ret + 1);
        unsigned char *ptr = (unsigned char *)(descr + 1);

        descr->control = ((SECURITY_DESCRIPTOR *)sd)->Control & ~SE_SELF_RELATIVE;
        if (owner) descr->owner_len = RtlLengthSid( owner );
        if (group) descr->group_len = RtlLengthSid( group );
        if (sacl_present && sacl) descr->sacl_len = sacl->AclSize;
        if (dacl_present && dacl) descr->dacl_len = dacl->AclSize;

        memcpy( ptr, owner, descr->owner_len );
        ptr += descr->owner_len;
        memcpy( ptr, group, descr->group_len );
        ptr += descr->group_len;
        memcpy( ptr, sacl, descr->sacl_len );
        ptr += descr->sacl_len;
        memcpy( ptr, dacl, descr->dacl_len );
        (*ret)->sd_len = (sizeof(*descr) + descr->owner_len + descr->group_len + descr->sacl_len +
                          descr->dacl_len + sizeof(WCHAR) - 1) & ~(sizeof(WCHAR) - 1);
    }

    if (attr->ObjectName)
    {
        unsigned char *ptr = (unsigned char *)(*ret + 1) + (*ret)->sd_len;
        (*ret)->name_len = attr->ObjectName->Length;
        memcpy( ptr, attr->ObjectName->Buffer, (*ret)->name_len );
    }

    *ret_len = len;
    return STATUS_SUCCESS;
}

NTSTATUS validate_open_object_attributes( const OBJECT_ATTRIBUTES *attr )
{
    if (!attr || attr->Length != sizeof(*attr)) return STATUS_INVALID_PARAMETER;

    if (attr->ObjectName)
    {
        if (attr->ObjectName->Length & (sizeof(WCHAR) - 1)) return STATUS_OBJECT_NAME_INVALID;
    }
    else if (attr->RootDirectory) return STATUS_OBJECT_NAME_INVALID;

    return STATUS_SUCCESS;
}

/*
 *	Semaphores
 */

/******************************************************************************
 *  NtCreateSemaphore (NTDLL.@)
 */
NTSTATUS WINAPI NtCreateSemaphore( OUT PHANDLE SemaphoreHandle,
                                   IN ACCESS_MASK access,
                                   IN const OBJECT_ATTRIBUTES *attr OPTIONAL,
                                   IN LONG InitialCount,
                                   IN LONG MaximumCount )
{
    NTSTATUS ret;
    data_size_t len;
    struct object_attributes *objattr;

    if (MaximumCount <= 0 || InitialCount < 0 || InitialCount > MaximumCount)
        return STATUS_INVALID_PARAMETER;

    if (do_esync())
        return esync_create_semaphore( SemaphoreHandle, access, attr, InitialCount, MaximumCount );

    if ((ret = alloc_object_attributes( attr, &objattr, &len ))) return ret;

    SERVER_START_REQ( create_semaphore )
    {
        req->access  = access;
        req->initial = InitialCount;
        req->max     = MaximumCount;
        wine_server_add_data( req, objattr, len );
        ret = wine_server_call( req );
        *SemaphoreHandle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;

    RtlFreeHeap( GetProcessHeap(), 0, objattr );
    return ret;
}

/******************************************************************************
 *  NtOpenSemaphore (NTDLL.@)
 */
NTSTATUS WINAPI NtOpenSemaphore( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    NTSTATUS ret;

    if ((ret = validate_open_object_attributes( attr ))) return ret;

    if (do_esync())
        return esync_open_semaphore( handle, access, attr );

    SERVER_START_REQ( open_semaphore )
    {
        req->access     = access;
        req->attributes = attr->Attributes;
        req->rootdir    = wine_server_obj_handle( attr->RootDirectory );
        if (attr->ObjectName)
            wine_server_add_data( req, attr->ObjectName->Buffer, attr->ObjectName->Length );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    return ret;
}

/******************************************************************************
 *  NtQuerySemaphore (NTDLL.@)
 */
NTSTATUS WINAPI NtQuerySemaphore( HANDLE handle, SEMAPHORE_INFORMATION_CLASS class,
                                  void *info, ULONG len, ULONG *ret_len )
{
    NTSTATUS ret;
    SEMAPHORE_BASIC_INFORMATION *out = info;

    if (do_esync())
        return esync_query_semaphore( handle, class, info, len, ret_len );

    TRACE("(%p, %u, %p, %u, %p)\n", handle, class, info, len, ret_len);

    if (class != SemaphoreBasicInformation)
    {
        FIXME("(%p,%d,%u) Unknown class\n", handle, class, len);
        return STATUS_INVALID_INFO_CLASS;
    }

    if (len != sizeof(SEMAPHORE_BASIC_INFORMATION)) return STATUS_INFO_LENGTH_MISMATCH;

    SERVER_START_REQ( query_semaphore )
    {
        req->handle = wine_server_obj_handle( handle );
        if (!(ret = wine_server_call( req )))
        {
            out->CurrentCount = reply->current;
            out->MaximumCount = reply->max;
            if (ret_len) *ret_len = sizeof(SEMAPHORE_BASIC_INFORMATION);
        }
    }
    SERVER_END_REQ;

    return ret;
}

/******************************************************************************
 *  NtReleaseSemaphore (NTDLL.@)
 */
NTSTATUS WINAPI NtReleaseSemaphore( HANDLE handle, ULONG count, PULONG previous )
{
    NTSTATUS ret;

    if (do_esync())
        return esync_release_semaphore( handle, count, previous );

    SERVER_START_REQ( release_semaphore )
    {
        req->handle = wine_server_obj_handle( handle );
        req->count  = count;
        if (!(ret = wine_server_call( req )))
        {
            if (previous) *previous = reply->prev_count;
        }
    }
    SERVER_END_REQ;
    return ret;
}

/*
 *	Events
 */

/**************************************************************************
 * NtCreateEvent (NTDLL.@)
 * ZwCreateEvent (NTDLL.@)
 */
NTSTATUS WINAPI NtCreateEvent( PHANDLE EventHandle, ACCESS_MASK DesiredAccess,
                               const OBJECT_ATTRIBUTES *attr, EVENT_TYPE type, BOOLEAN InitialState)
{
    NTSTATUS ret;
    data_size_t len;
    struct object_attributes *objattr;

    if (do_esync())
        return esync_create_event( EventHandle, DesiredAccess, attr, type, InitialState );

    if ((ret = alloc_object_attributes( attr, &objattr, &len ))) return ret;

    SERVER_START_REQ( create_event )
    {
        req->access = DesiredAccess;
        req->manual_reset = (type == NotificationEvent);
        req->initial_state = InitialState;
        wine_server_add_data( req, objattr, len );
        ret = wine_server_call( req );
        *EventHandle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;

    RtlFreeHeap( GetProcessHeap(), 0, objattr );
    return ret;
}

/******************************************************************************
 *  NtOpenEvent (NTDLL.@)
 *  ZwOpenEvent (NTDLL.@)
 */
NTSTATUS WINAPI NtOpenEvent( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    NTSTATUS ret;

    if ((ret = validate_open_object_attributes( attr ))) return ret;

    if (do_esync())
        return esync_open_event( handle, access, attr );

    SERVER_START_REQ( open_event )
    {
        req->access     = access;
        req->attributes = attr->Attributes;
        req->rootdir    = wine_server_obj_handle( attr->RootDirectory );
        if (attr->ObjectName)
            wine_server_add_data( req, attr->ObjectName->Buffer, attr->ObjectName->Length );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    return ret;
}


/******************************************************************************
 *  NtSetEvent (NTDLL.@)
 *  ZwSetEvent (NTDLL.@)
 */
NTSTATUS WINAPI NtSetEvent( HANDLE handle, LONG *prev_state )
{
    NTSTATUS ret;

    if (do_esync())
        return esync_set_event( handle, prev_state );

    SERVER_START_REQ( event_op )
    {
        req->handle = wine_server_obj_handle( handle );
        req->op     = SET_EVENT;
        ret = wine_server_call( req );
        if (!ret && prev_state) *prev_state = reply->state;
    }
    SERVER_END_REQ;
    return ret;
}

/******************************************************************************
 *  NtResetEvent (NTDLL.@)
 */
NTSTATUS WINAPI NtResetEvent( HANDLE handle, LONG *prev_state )
{
    NTSTATUS ret;

    if (do_esync())
        return esync_reset_event( handle, prev_state );

    SERVER_START_REQ( event_op )
    {
        req->handle = wine_server_obj_handle( handle );
        req->op     = RESET_EVENT;
        ret = wine_server_call( req );
        if (!ret && prev_state) *prev_state = reply->state;
    }
    SERVER_END_REQ;
    return ret;
}

/******************************************************************************
 *  NtClearEvent (NTDLL.@)
 *
 * FIXME
 *   same as NtResetEvent ???
 */
NTSTATUS WINAPI NtClearEvent ( HANDLE handle )
{
    return NtResetEvent( handle, NULL );
}

/******************************************************************************
 *  NtPulseEvent (NTDLL.@)
 *
 * FIXME
 *   PulseCount
 */
NTSTATUS WINAPI NtPulseEvent( HANDLE handle, LONG *prev_state )
{
    NTSTATUS ret;

    if (do_esync())
        return esync_pulse_event( handle, prev_state );

    SERVER_START_REQ( event_op )
    {
        req->handle = wine_server_obj_handle( handle );
        req->op     = PULSE_EVENT;
        ret = wine_server_call( req );
        if (!ret && prev_state) *prev_state = reply->state;
    }
    SERVER_END_REQ;
    return ret;
}

/******************************************************************************
 *  NtQueryEvent (NTDLL.@)
 */
NTSTATUS WINAPI NtQueryEvent( HANDLE handle, EVENT_INFORMATION_CLASS class,
                              void *info, ULONG len, ULONG *ret_len )
{
    NTSTATUS ret;
    EVENT_BASIC_INFORMATION *out = info;

    if (do_esync())
        return esync_query_event( handle, class, info, len, ret_len );

    TRACE("(%p, %u, %p, %u, %p)\n", handle, class, info, len, ret_len);

    if (class != EventBasicInformation)
    {
        FIXME("(%p, %d, %d) Unknown class\n",
              handle, class, len);
        return STATUS_INVALID_INFO_CLASS;
    }

    if (len != sizeof(EVENT_BASIC_INFORMATION)) return STATUS_INFO_LENGTH_MISMATCH;

    SERVER_START_REQ( query_event )
    {
        req->handle = wine_server_obj_handle( handle );
        if (!(ret = wine_server_call( req )))
        {
            out->EventType  = reply->manual_reset ? NotificationEvent : SynchronizationEvent;
            out->EventState = reply->state;
            if (ret_len) *ret_len = sizeof(EVENT_BASIC_INFORMATION);
        }
    }
    SERVER_END_REQ;

    return ret;
}

/*
 *	Mutants (known as Mutexes in Kernel32)
 */

/******************************************************************************
 *              NtCreateMutant                          [NTDLL.@]
 *              ZwCreateMutant                          [NTDLL.@]
 */
NTSTATUS WINAPI NtCreateMutant(OUT HANDLE* MutantHandle,
                               IN ACCESS_MASK access,
                               IN const OBJECT_ATTRIBUTES* attr OPTIONAL,
                               IN BOOLEAN InitialOwner)
{
    NTSTATUS status;
    data_size_t len;
    struct object_attributes *objattr;

    if (do_esync())
        return esync_create_mutex( MutantHandle, access, attr, InitialOwner );

    if ((status = alloc_object_attributes( attr, &objattr, &len ))) return status;

    SERVER_START_REQ( create_mutex )
    {
        req->access  = access;
        req->owned   = InitialOwner;
        wine_server_add_data( req, objattr, len );
        status = wine_server_call( req );
        *MutantHandle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;

    RtlFreeHeap( GetProcessHeap(), 0, objattr );
    return status;
}

/**************************************************************************
 *		NtOpenMutant				[NTDLL.@]
 *		ZwOpenMutant				[NTDLL.@]
 */
NTSTATUS WINAPI NtOpenMutant( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    NTSTATUS    status;

    if ((status = validate_open_object_attributes( attr ))) return status;

    if (do_esync())
        return esync_open_mutex( handle, access, attr );

    SERVER_START_REQ( open_mutex )
    {
        req->access  = access;
        req->attributes = attr->Attributes;
        req->rootdir = wine_server_obj_handle( attr->RootDirectory );
        if (attr->ObjectName)
            wine_server_add_data( req, attr->ObjectName->Buffer, attr->ObjectName->Length );
        status = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    return status;
}

/**************************************************************************
 *		NtReleaseMutant				[NTDLL.@]
 *		ZwReleaseMutant				[NTDLL.@]
 */
NTSTATUS WINAPI NtReleaseMutant( IN HANDLE handle, OUT PLONG prev_count OPTIONAL)
{
    NTSTATUS    status;

    if (do_esync())
        return esync_release_mutex( handle, prev_count );

    SERVER_START_REQ( release_mutex )
    {
        req->handle = wine_server_obj_handle( handle );
        status = wine_server_call( req );
        if (prev_count) *prev_count = 1 - reply->prev_count;
    }
    SERVER_END_REQ;
    return status;
}

/******************************************************************
 *		NtQueryMutant                   [NTDLL.@]
 *		ZwQueryMutant                   [NTDLL.@]
 */
NTSTATUS WINAPI NtQueryMutant( HANDLE handle, MUTANT_INFORMATION_CLASS class,
                               void *info, ULONG len, ULONG *ret_len )
{
    NTSTATUS ret;
    MUTANT_BASIC_INFORMATION *out = info;

    if (do_esync())
        return esync_query_mutex( handle, class, info, len, ret_len );

    TRACE("(%p, %u, %p, %u, %p)\n", handle, class, info, len, ret_len);

    if (class != MutantBasicInformation)
    {
        FIXME("(%p, %d, %d) Unknown class\n",
              handle, class, len);
        return STATUS_INVALID_INFO_CLASS;
    }

    if (len != sizeof(MUTANT_BASIC_INFORMATION)) return STATUS_INFO_LENGTH_MISMATCH;

    SERVER_START_REQ( query_mutex )
    {
        req->handle = wine_server_obj_handle( handle );
        if (!(ret = wine_server_call( req )))
        {
            out->CurrentCount   = 1 - reply->count;
            out->OwnedByCaller  = reply->owned;
            out->AbandonedState = reply->abandoned;
            if (ret_len) *ret_len = sizeof(MUTANT_BASIC_INFORMATION);
        }
    }
    SERVER_END_REQ;

    return ret;
}

/*
 *	Jobs
 */

/******************************************************************************
 *              NtCreateJobObject   [NTDLL.@]
 *              ZwCreateJobObject   [NTDLL.@]
 */
NTSTATUS WINAPI NtCreateJobObject( PHANDLE handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    NTSTATUS ret;
    data_size_t len;
    struct object_attributes *objattr;

    if ((ret = alloc_object_attributes( attr, &objattr, &len ))) return ret;

    SERVER_START_REQ( create_job )
    {
        req->access = access;
        wine_server_add_data( req, objattr, len );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;

    RtlFreeHeap( GetProcessHeap(), 0, objattr );
    return ret;
}

/******************************************************************************
 *              NtOpenJobObject   [NTDLL.@]
 *              ZwOpenJobObject   [NTDLL.@]
 */
NTSTATUS WINAPI NtOpenJobObject( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    NTSTATUS ret;

    if ((ret = validate_open_object_attributes( attr ))) return ret;

    SERVER_START_REQ( open_job )
    {
        req->access     = access;
        req->attributes = attr->Attributes;
        req->rootdir    = wine_server_obj_handle( attr->RootDirectory );
        if (attr->ObjectName)
            wine_server_add_data( req, attr->ObjectName->Buffer, attr->ObjectName->Length );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    return ret;
}

/******************************************************************************
 *              NtTerminateJobObject   [NTDLL.@]
 *              ZwTerminateJobObject   [NTDLL.@]
 */
NTSTATUS WINAPI NtTerminateJobObject( HANDLE handle, NTSTATUS status )
{
    NTSTATUS ret;

    TRACE( "(%p, %d)\n", handle, status );

    SERVER_START_REQ( terminate_job )
    {
        req->handle = wine_server_obj_handle( handle );
        req->status = status;
        ret = wine_server_call( req );
    }
    SERVER_END_REQ;

    return ret;
}

/******************************************************************************
 *              NtQueryInformationJobObject   [NTDLL.@]
 *              ZwQueryInformationJobObject   [NTDLL.@]
 */
NTSTATUS WINAPI NtQueryInformationJobObject( HANDLE handle, JOBOBJECTINFOCLASS class, PVOID info,
                                             ULONG len, PULONG ret_len )
{
    FIXME( "stub: %p %u %p %u %p\n", handle, class, info, len, ret_len );

    if (class >= MaxJobObjectInfoClass)
        return STATUS_INVALID_PARAMETER;

    switch (class)
    {
    case JobObjectBasicAccountingInformation:
        {
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION *accounting;
            if (len < sizeof(*accounting))
                return STATUS_INFO_LENGTH_MISMATCH;

            accounting = (JOBOBJECT_BASIC_ACCOUNTING_INFORMATION *)info;
            memset(accounting, 0, sizeof(*accounting));
            if (ret_len) *ret_len = sizeof(*accounting);
            return STATUS_SUCCESS;
        }

    case JobObjectBasicProcessIdList:
        {
            JOBOBJECT_BASIC_PROCESS_ID_LIST *process;
            if (len < sizeof(*process))
                return STATUS_INFO_LENGTH_MISMATCH;

            process = (JOBOBJECT_BASIC_PROCESS_ID_LIST *)info;
            memset(process, 0, sizeof(*process));
            if (ret_len) *ret_len = sizeof(*process);
            return STATUS_SUCCESS;
        }

    case JobObjectExtendedLimitInformation:
        {
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION *extended_limit;
            if (len < sizeof(*extended_limit))
                return STATUS_INFO_LENGTH_MISMATCH;

            extended_limit = (JOBOBJECT_EXTENDED_LIMIT_INFORMATION *)info;
            memset(extended_limit, 0, sizeof(*extended_limit));
            if (ret_len) *ret_len = sizeof(*extended_limit);
            return STATUS_SUCCESS;
        }

    case JobObjectBasicLimitInformation:
        {
            JOBOBJECT_BASIC_LIMIT_INFORMATION *basic_limit;
            if (len < sizeof(*basic_limit))
                return STATUS_INFO_LENGTH_MISMATCH;

            basic_limit = (JOBOBJECT_BASIC_LIMIT_INFORMATION *)info;
            memset(basic_limit, 0, sizeof(*basic_limit));
            if (ret_len) *ret_len = sizeof(*basic_limit);
            return STATUS_SUCCESS;
        }

    default:
        return STATUS_NOT_IMPLEMENTED;
    }
}

/******************************************************************************
 *              NtSetInformationJobObject   [NTDLL.@]
 *              ZwSetInformationJobObject   [NTDLL.@]
 */
NTSTATUS WINAPI NtSetInformationJobObject( HANDLE handle, JOBOBJECTINFOCLASS class, PVOID info, ULONG len )
{
    NTSTATUS status = STATUS_NOT_IMPLEMENTED;
    JOBOBJECT_BASIC_LIMIT_INFORMATION *basic_limit;
    ULONG info_size = sizeof(JOBOBJECT_BASIC_LIMIT_INFORMATION);
    DWORD limit_flags = JOB_OBJECT_BASIC_LIMIT_VALID_FLAGS;

    TRACE( "(%p, %u, %p, %u)\n", handle, class, info, len );

    if (class >= MaxJobObjectInfoClass)
        return STATUS_INVALID_PARAMETER;

    switch (class)
    {

    case JobObjectExtendedLimitInformation:
        info_size = sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION);
        limit_flags = JOB_OBJECT_EXTENDED_LIMIT_VALID_FLAGS;
        /* fallthrough */
    case JobObjectBasicLimitInformation:
        if (len != info_size)
            return STATUS_INVALID_PARAMETER;

        basic_limit = info;
        if (basic_limit->LimitFlags & ~limit_flags)
            return STATUS_INVALID_PARAMETER;

        SERVER_START_REQ( set_job_limits )
        {
            req->handle = wine_server_obj_handle( handle );
            req->limit_flags = basic_limit->LimitFlags;
            status = wine_server_call( req );
        }
        SERVER_END_REQ;
        break;

    case JobObjectAssociateCompletionPortInformation:
        if (len != sizeof(JOBOBJECT_ASSOCIATE_COMPLETION_PORT))
            return STATUS_INVALID_PARAMETER;

        SERVER_START_REQ( set_job_completion_port )
        {
            JOBOBJECT_ASSOCIATE_COMPLETION_PORT *port_info = info;
            req->job = wine_server_obj_handle( handle );
            req->port = wine_server_obj_handle( port_info->CompletionPort );
            req->key = wine_server_client_ptr( port_info->CompletionKey );
            status = wine_server_call(req);
        }
        SERVER_END_REQ;
        break;

    case JobObjectBasicUIRestrictions:
        status = STATUS_SUCCESS;
        /* fallthrough */
    default:
        FIXME( "stub: %p %u %p %u\n", handle, class, info, len );
    }

    return status;
}

/******************************************************************************
 *              NtIsProcessInJob   [NTDLL.@]
 *              ZwIsProcessInJob   [NTDLL.@]
 */
NTSTATUS WINAPI NtIsProcessInJob( HANDLE process, HANDLE job )
{
    NTSTATUS status;

    TRACE( "(%p %p)\n", job, process );

    SERVER_START_REQ( process_in_job )
    {
        req->job     = wine_server_obj_handle( job );
        req->process = wine_server_obj_handle( process );
        status = wine_server_call( req );
    }
    SERVER_END_REQ;

    return status;
}

/******************************************************************************
 *              NtAssignProcessToJobObject   [NTDLL.@]
 *              ZwAssignProcessToJobObject   [NTDLL.@]
 */
NTSTATUS WINAPI NtAssignProcessToJobObject( HANDLE job, HANDLE process )
{
    NTSTATUS status;

    TRACE( "(%p %p)\n", job, process );

    SERVER_START_REQ( assign_job )
    {
        req->job     = wine_server_obj_handle( job );
        req->process = wine_server_obj_handle( process );
        status = wine_server_call( req );
    }
    SERVER_END_REQ;

    return status;
}

/*
 *	Timers
 */

/**************************************************************************
 *		NtCreateTimer				[NTDLL.@]
 *		ZwCreateTimer				[NTDLL.@]
 */
NTSTATUS WINAPI NtCreateTimer(OUT HANDLE *handle,
                              IN ACCESS_MASK access,
                              IN const OBJECT_ATTRIBUTES *attr OPTIONAL,
                              IN TIMER_TYPE timer_type)
{
    NTSTATUS status;
    data_size_t len;
    struct object_attributes *objattr;

    if (timer_type != NotificationTimer && timer_type != SynchronizationTimer)
        return STATUS_INVALID_PARAMETER;

    if ((status = alloc_object_attributes( attr, &objattr, &len ))) return status;

    SERVER_START_REQ( create_timer )
    {
        req->access  = access;
        req->manual  = (timer_type == NotificationTimer);
        wine_server_add_data( req, objattr, len );
        status = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;

    RtlFreeHeap( GetProcessHeap(), 0, objattr );
    return status;

}

/**************************************************************************
 *		NtOpenTimer				[NTDLL.@]
 *		ZwOpenTimer				[NTDLL.@]
 */
NTSTATUS WINAPI NtOpenTimer( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    NTSTATUS status;

    if ((status = validate_open_object_attributes( attr ))) return status;

    SERVER_START_REQ( open_timer )
    {
        req->access     = access;
        req->attributes = attr->Attributes;
        req->rootdir    = wine_server_obj_handle( attr->RootDirectory );
        if (attr->ObjectName)
            wine_server_add_data( req, attr->ObjectName->Buffer, attr->ObjectName->Length );
        status = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    return status;
}

/**************************************************************************
 *		NtSetTimer				[NTDLL.@]
 *		ZwSetTimer				[NTDLL.@]
 */
NTSTATUS WINAPI NtSetTimer(IN HANDLE handle,
                           IN const LARGE_INTEGER* when,
                           IN PTIMER_APC_ROUTINE callback,
                           IN PVOID callback_arg,
                           IN BOOLEAN resume,
                           IN ULONG period OPTIONAL,
                           OUT PBOOLEAN state OPTIONAL)
{
    NTSTATUS    status = STATUS_SUCCESS;

    TRACE("(%p,%p,%p,%p,%08x,0x%08x,%p)\n",
          handle, when, callback, callback_arg, resume, period, state);

    SERVER_START_REQ( set_timer )
    {
        req->handle   = wine_server_obj_handle( handle );
        req->period   = period;
        req->expire   = when->QuadPart;
        req->callback = wine_server_client_ptr( callback );
        req->arg      = wine_server_client_ptr( callback_arg );
        status = wine_server_call( req );
        if (state) *state = reply->signaled;
    }
    SERVER_END_REQ;

    /* set error but can still succeed */
    if (resume && status == STATUS_SUCCESS) return STATUS_TIMER_RESUME_IGNORED;
    return status;
}

/**************************************************************************
 *		NtCancelTimer				[NTDLL.@]
 *		ZwCancelTimer				[NTDLL.@]
 */
NTSTATUS WINAPI NtCancelTimer(IN HANDLE handle, OUT BOOLEAN* state)
{
    NTSTATUS    status;

    SERVER_START_REQ( cancel_timer )
    {
        req->handle = wine_server_obj_handle( handle );
        status = wine_server_call( req );
        if (state) *state = reply->signaled;
    }
    SERVER_END_REQ;
    return status;
}

/******************************************************************************
 *  NtQueryTimer (NTDLL.@)
 *
 * Retrieves information about a timer.
 *
 * PARAMS
 *  TimerHandle           [I] The timer to retrieve information about.
 *  TimerInformationClass [I] The type of information to retrieve.
 *  TimerInformation      [O] Pointer to buffer to store information in.
 *  Length                [I] The length of the buffer pointed to by TimerInformation.
 *  ReturnLength          [O] Optional. The size of buffer actually used.
 *
 * RETURNS
 *  Success: STATUS_SUCCESS
 *  Failure: STATUS_INFO_LENGTH_MISMATCH, if Length doesn't match the required data
 *           size for the class specified.
 *           STATUS_INVALID_INFO_CLASS, if an invalid TimerInformationClass was specified.
 *           STATUS_ACCESS_DENIED, if TimerHandle does not have TIMER_QUERY_STATE access
 *           to the timer.
 */
NTSTATUS WINAPI NtQueryTimer(
    HANDLE TimerHandle,
    TIMER_INFORMATION_CLASS TimerInformationClass,
    PVOID TimerInformation,
    ULONG Length,
    PULONG ReturnLength)
{
    TIMER_BASIC_INFORMATION * basic_info = TimerInformation;
    NTSTATUS status;
    LARGE_INTEGER now;

    TRACE("(%p,%d,%p,0x%08x,%p)\n", TimerHandle, TimerInformationClass,
       TimerInformation, Length, ReturnLength);

    switch (TimerInformationClass)
    {
    case TimerBasicInformation:
        if (Length < sizeof(TIMER_BASIC_INFORMATION))
            return STATUS_INFO_LENGTH_MISMATCH;

        SERVER_START_REQ(get_timer_info)
        {
            req->handle = wine_server_obj_handle( TimerHandle );
            status = wine_server_call(req);

            /* convert server time to absolute NTDLL time */
            basic_info->RemainingTime.QuadPart = reply->when;
            basic_info->TimerState = reply->signaled;
        }
        SERVER_END_REQ;

        /* convert from absolute into relative time */
        NtQuerySystemTime(&now);
        if (now.QuadPart > basic_info->RemainingTime.QuadPart)
            basic_info->RemainingTime.QuadPart = 0;
        else
            basic_info->RemainingTime.QuadPart -= now.QuadPart;

        if (ReturnLength) *ReturnLength = sizeof(TIMER_BASIC_INFORMATION);

        return status;
    }

    FIXME("Unhandled class %d\n", TimerInformationClass);
    return STATUS_INVALID_INFO_CLASS;
}


/******************************************************************************
 * NtQueryTimerResolution [NTDLL.@]
 */
NTSTATUS WINAPI NtQueryTimerResolution(OUT ULONG* min_resolution,
                                       OUT ULONG* max_resolution,
                                       OUT ULONG* current_resolution)
{
    FIXME("(%p,%p,%p), stub!\n",
          min_resolution, max_resolution, current_resolution);

    return STATUS_NOT_IMPLEMENTED;
}

/******************************************************************************
 * NtSetTimerResolution [NTDLL.@]
 */
NTSTATUS WINAPI NtSetTimerResolution(IN ULONG resolution,
                                     IN BOOLEAN set_resolution,
                                     OUT ULONG* current_resolution )
{
    FIXME("(%u,%u,%p), stub!\n",
          resolution, set_resolution, current_resolution);

    return STATUS_NOT_IMPLEMENTED;
}



/* wait operations */

static NTSTATUS wait_objects( DWORD count, const HANDLE *handles,
                              BOOLEAN wait_any, BOOLEAN alertable,
                              const LARGE_INTEGER *timeout )
{
    select_op_t select_op;
    UINT i, flags = SELECT_INTERRUPTIBLE;

    if (!count || count > MAXIMUM_WAIT_OBJECTS) return STATUS_INVALID_PARAMETER_1;

    if (do_esync())
    {
        NTSTATUS ret = esync_wait_objects( count, handles, wait_any, alertable, timeout );
        if (ret != STATUS_NOT_IMPLEMENTED)
            return ret;
    }

    if (alertable) flags |= SELECT_ALERTABLE;
    select_op.wait.op = wait_any ? SELECT_WAIT : SELECT_WAIT_ALL;
    for (i = 0; i < count; i++) select_op.wait.handles[i] = wine_server_obj_handle( handles[i] );
    return server_select( &select_op, offsetof( select_op_t, wait.handles[count] ), flags, timeout );
}


/******************************************************************
 *		NtWaitForMultipleObjects (NTDLL.@)
 */
NTSTATUS WINAPI NtWaitForMultipleObjects( DWORD count, const HANDLE *handles,
                                          BOOLEAN wait_any, BOOLEAN alertable,
                                          const LARGE_INTEGER *timeout )
{
    return wait_objects( count, handles, wait_any, alertable, timeout );
}


/******************************************************************
 *		NtWaitForSingleObject (NTDLL.@)
 */
NTSTATUS WINAPI NtWaitForSingleObject(HANDLE handle, BOOLEAN alertable, const LARGE_INTEGER *timeout )
{
    return wait_objects( 1, &handle, FALSE, alertable, timeout );
}


/******************************************************************
 *		NtSignalAndWaitForSingleObject (NTDLL.@)
 */
NTSTATUS WINAPI NtSignalAndWaitForSingleObject( HANDLE hSignalObject, HANDLE hWaitObject,
                                                BOOLEAN alertable, const LARGE_INTEGER *timeout )
{
    select_op_t select_op;
    UINT flags = SELECT_INTERRUPTIBLE;

    if (do_esync())
        return esync_signal_and_wait( hSignalObject, hWaitObject, alertable, timeout );

    if (!hSignalObject) return STATUS_INVALID_HANDLE;

    if (alertable) flags |= SELECT_ALERTABLE;
    select_op.signal_and_wait.op = SELECT_SIGNAL_AND_WAIT;
    select_op.signal_and_wait.wait = wine_server_obj_handle( hWaitObject );
    select_op.signal_and_wait.signal = wine_server_obj_handle( hSignalObject );
    return server_select( &select_op, sizeof(select_op.signal_and_wait), flags, timeout );
}


/******************************************************************
 *		NtYieldExecution (NTDLL.@)
 */
NTSTATUS WINAPI NtYieldExecution(void)
{
#ifdef HAVE_SCHED_YIELD
    sched_yield();
    return STATUS_SUCCESS;
#else
    return STATUS_NO_YIELD_PERFORMED;
#endif
}


/******************************************************************
 *		NtDelayExecution (NTDLL.@)
 */
NTSTATUS WINAPI NtDelayExecution( BOOLEAN alertable, const LARGE_INTEGER *timeout )
{
    /* if alertable, we need to query the server */
    if (alertable)
        return server_select( NULL, 0, SELECT_INTERRUPTIBLE | SELECT_ALERTABLE, timeout );

    if (!timeout || timeout->QuadPart == TIMEOUT_INFINITE)  /* sleep forever */
    {
        for (;;) select( 0, NULL, NULL, NULL, NULL );
    }
    else
    {
        LARGE_INTEGER now;
        timeout_t when, diff;

        if ((when = timeout->QuadPart) < 0)
        {
            NtQuerySystemTime( &now );
            when = now.QuadPart - when;
        }

        /* Note that we yield after establishing the desired timeout */
        NtYieldExecution();
        if (!when) return STATUS_SUCCESS;

        for (;;)
        {
            struct timeval tv;
            NtQuerySystemTime( &now );
            diff = (when - now.QuadPart + 9) / 10;
            if (diff <= 0) break;
            tv.tv_sec  = diff / 1000000;
            tv.tv_usec = diff % 1000000;
            if (select( 0, NULL, NULL, NULL, &tv ) != -1) break;
        }
    }
    return STATUS_SUCCESS;
}


/******************************************************************************
 *              NtCreateKeyedEvent (NTDLL.@)
 */
NTSTATUS WINAPI NtCreateKeyedEvent( HANDLE *handle, ACCESS_MASK access,
                                    const OBJECT_ATTRIBUTES *attr, ULONG flags )
{
    NTSTATUS ret;
    data_size_t len;
    struct object_attributes *objattr;

    if ((ret = alloc_object_attributes( attr, &objattr, &len ))) return ret;

    SERVER_START_REQ( create_keyed_event )
    {
        req->access = access;
        wine_server_add_data( req, objattr, len );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;

    RtlFreeHeap( GetProcessHeap(), 0, objattr );
    return ret;
}

/******************************************************************************
 *              NtOpenKeyedEvent (NTDLL.@)
 */
NTSTATUS WINAPI NtOpenKeyedEvent( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    NTSTATUS ret;

    if ((ret = validate_open_object_attributes( attr ))) return ret;

    SERVER_START_REQ( open_keyed_event )
    {
        req->access     = access;
        req->attributes = attr->Attributes;
        req->rootdir    = wine_server_obj_handle( attr->RootDirectory );
        if (attr->ObjectName)
            wine_server_add_data( req, attr->ObjectName->Buffer, attr->ObjectName->Length );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    return ret;
}

/******************************************************************************
 *              NtWaitForKeyedEvent (NTDLL.@)
 */
NTSTATUS WINAPI NtWaitForKeyedEvent( HANDLE handle, const void *key,
                                     BOOLEAN alertable, const LARGE_INTEGER *timeout )
{
    select_op_t select_op;
    UINT flags = SELECT_INTERRUPTIBLE;

    if (!handle) handle = keyed_event;
    if ((ULONG_PTR)key & 1) return STATUS_INVALID_PARAMETER_1;
    if (alertable) flags |= SELECT_ALERTABLE;
    select_op.keyed_event.op     = SELECT_KEYED_EVENT_WAIT;
    select_op.keyed_event.handle = wine_server_obj_handle( handle );
    select_op.keyed_event.key    = wine_server_client_ptr( key );
    return server_select( &select_op, sizeof(select_op.keyed_event), flags, timeout );
}

/******************************************************************************
 *              NtReleaseKeyedEvent (NTDLL.@)
 */
NTSTATUS WINAPI NtReleaseKeyedEvent( HANDLE handle, const void *key,
                                     BOOLEAN alertable, const LARGE_INTEGER *timeout )
{
    select_op_t select_op;
    UINT flags = SELECT_INTERRUPTIBLE;

    if (!handle) handle = keyed_event;
    if ((ULONG_PTR)key & 1) return STATUS_INVALID_PARAMETER_1;
    if (alertable) flags |= SELECT_ALERTABLE;
    select_op.keyed_event.op     = SELECT_KEYED_EVENT_RELEASE;
    select_op.keyed_event.handle = wine_server_obj_handle( handle );
    select_op.keyed_event.key    = wine_server_client_ptr( key );
    return server_select( &select_op, sizeof(select_op.keyed_event), flags, timeout );
}

/******************************************************************
 *              NtCreateIoCompletion (NTDLL.@)
 *              ZwCreateIoCompletion (NTDLL.@)
 *
 * Creates I/O completion object.
 *
 * PARAMS
 *      CompletionPort            [O] created completion object handle will be placed there
 *      DesiredAccess             [I] desired access to a handle (combination of IO_COMPLETION_*)
 *      ObjectAttributes          [I] completion object attributes
 *      NumberOfConcurrentThreads [I] desired number of concurrent active worker threads
 *
 */
NTSTATUS WINAPI NtCreateIoCompletion( PHANDLE CompletionPort, ACCESS_MASK DesiredAccess,
                                      POBJECT_ATTRIBUTES attr, ULONG NumberOfConcurrentThreads )
{
    NTSTATUS status;
    data_size_t len;
    struct object_attributes *objattr;

    TRACE("(%p, %x, %p, %d)\n", CompletionPort, DesiredAccess, attr, NumberOfConcurrentThreads);

    if (!CompletionPort)
        return STATUS_INVALID_PARAMETER;

    if ((status = alloc_object_attributes( attr, &objattr, &len ))) return status;

    SERVER_START_REQ( create_completion )
    {
        req->access     = DesiredAccess;
        req->concurrent = NumberOfConcurrentThreads;
        wine_server_add_data( req, objattr, len );
        if (!(status = wine_server_call( req )))
            *CompletionPort = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;

    RtlFreeHeap( GetProcessHeap(), 0, objattr );
    return status;
}

/******************************************************************
 *              NtSetIoCompletion (NTDLL.@)
 *              ZwSetIoCompletion (NTDLL.@)
 *
 * Inserts completion message into queue
 *
 * PARAMS
 *      CompletionPort           [I] HANDLE to completion object
 *      CompletionKey            [I] completion key
 *      CompletionValue          [I] completion value (usually pointer to OVERLAPPED)
 *      Status                   [I] operation status
 *      NumberOfBytesTransferred [I] number of bytes transferred
 */
NTSTATUS WINAPI NtSetIoCompletion( HANDLE CompletionPort, ULONG_PTR CompletionKey,
                                   ULONG_PTR CompletionValue, NTSTATUS Status,
                                   SIZE_T NumberOfBytesTransferred )
{
    NTSTATUS status;

    TRACE("(%p, %lx, %lx, %x, %lx)\n", CompletionPort, CompletionKey,
          CompletionValue, Status, NumberOfBytesTransferred);

    SERVER_START_REQ( add_completion )
    {
        req->handle      = wine_server_obj_handle( CompletionPort );
        req->ckey        = CompletionKey;
        req->cvalue      = CompletionValue;
        req->status      = Status;
        req->information = NumberOfBytesTransferred;
        status = wine_server_call( req );
    }
    SERVER_END_REQ;
    return status;
}

/******************************************************************
 *              NtRemoveIoCompletion (NTDLL.@)
 *              ZwRemoveIoCompletion (NTDLL.@)
 *
 * (Wait for and) retrieve first completion message from completion object's queue
 *
 * PARAMS
 *      CompletionPort  [I] HANDLE to I/O completion object
 *      CompletionKey   [O] completion key
 *      CompletionValue [O] Completion value given in NtSetIoCompletion or in async operation
 *      iosb            [O] IO_STATUS_BLOCK of completed asynchronous operation
 *      WaitTime        [I] optional wait time in NTDLL format
 *
 */
NTSTATUS WINAPI NtRemoveIoCompletion( HANDLE CompletionPort, PULONG_PTR CompletionKey,
                                      PULONG_PTR CompletionValue, PIO_STATUS_BLOCK iosb,
                                      PLARGE_INTEGER WaitTime )
{
    NTSTATUS status;

    TRACE("(%p, %p, %p, %p, %p)\n", CompletionPort, CompletionKey,
          CompletionValue, iosb, WaitTime);

    for(;;)
    {
        SERVER_START_REQ( remove_completion )
        {
            req->handle = wine_server_obj_handle( CompletionPort );
            if (!(status = wine_server_call( req )))
            {
                *CompletionKey    = reply->ckey;
                *CompletionValue  = reply->cvalue;
                iosb->Information = reply->information;
                iosb->u.Status    = reply->status;
            }
        }
        SERVER_END_REQ;
        if (status != STATUS_PENDING) break;

        status = NtWaitForSingleObject( CompletionPort, FALSE, WaitTime );
        if (status != WAIT_OBJECT_0) break;
    }
    return status;
}

/******************************************************************
 *              NtRemoveIoCompletionEx (NTDLL.@)
 *              ZwRemoveIoCompletionEx (NTDLL.@)
 */
NTSTATUS WINAPI NtRemoveIoCompletionEx( HANDLE port, FILE_IO_COMPLETION_INFORMATION *info, ULONG count,
                                        ULONG *written, LARGE_INTEGER *timeout, BOOLEAN alertable )
{
    NTSTATUS ret;
    ULONG i = 0;

    TRACE("%p %p %u %p %p %u\n", port, info, count, written, timeout, alertable);

    for (;;)
    {
        while (i < count)
        {
            SERVER_START_REQ( remove_completion )
            {
                req->handle = wine_server_obj_handle( port );
                if (!(ret = wine_server_call( req )))
                {
                    info[i].CompletionKey             = reply->ckey;
                    info[i].CompletionValue           = reply->cvalue;
                    info[i].IoStatusBlock.Information = reply->information;
                    info[i].IoStatusBlock.u.Status    = reply->status;
                }
            }
            SERVER_END_REQ;

            if (ret != STATUS_SUCCESS) break;

            ++i;
        }

        if (i || ret != STATUS_PENDING)
        {
            if (ret == STATUS_PENDING)
                ret = STATUS_SUCCESS;
            break;
        }

        ret = NtWaitForSingleObject( port, alertable, timeout );
        if (ret != WAIT_OBJECT_0) break;
    }

    *written = i ? i : 1;
    return ret;
}

/******************************************************************
 *              NtOpenIoCompletion (NTDLL.@)
 *              ZwOpenIoCompletion (NTDLL.@)
 *
 * Opens I/O completion object
 *
 * PARAMS
 *      CompletionPort     [O] completion object handle will be placed there
 *      DesiredAccess      [I] desired access to a handle (combination of IO_COMPLETION_*)
 *      ObjectAttributes   [I] completion object name
 *
 */
NTSTATUS WINAPI NtOpenIoCompletion( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    NTSTATUS status;

    if (!handle) return STATUS_INVALID_PARAMETER;
    if ((status = validate_open_object_attributes( attr ))) return status;

    SERVER_START_REQ( open_completion )
    {
        req->access     = access;
        req->attributes = attr->Attributes;
        req->rootdir    = wine_server_obj_handle( attr->RootDirectory );
        if (attr->ObjectName)
            wine_server_add_data( req, attr->ObjectName->Buffer, attr->ObjectName->Length );
        status = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    return status;
}

/******************************************************************
 *              NtQueryIoCompletion (NTDLL.@)
 *              ZwQueryIoCompletion (NTDLL.@)
 *
 * Requests information about given I/O completion object
 *
 * PARAMS
 *      CompletionPort        [I] HANDLE to completion port to request
 *      InformationClass      [I] information class
 *      CompletionInformation [O] user-provided buffer for data
 *      BufferLength          [I] buffer length
 *      RequiredLength        [O] required buffer length
 *
 */
NTSTATUS WINAPI NtQueryIoCompletion( HANDLE CompletionPort, IO_COMPLETION_INFORMATION_CLASS InformationClass,
                                     PVOID CompletionInformation, ULONG BufferLength, PULONG RequiredLength )
{
    NTSTATUS status;

    TRACE("(%p, %d, %p, 0x%x, %p)\n", CompletionPort, InformationClass, CompletionInformation,
          BufferLength, RequiredLength);

    if (!CompletionInformation) return STATUS_INVALID_PARAMETER;
    switch( InformationClass )
    {
        case IoCompletionBasicInformation:
            {
                ULONG *info = CompletionInformation;

                if (RequiredLength) *RequiredLength = sizeof(*info);
                if (BufferLength != sizeof(*info))
                    status = STATUS_INFO_LENGTH_MISMATCH;
                else
                {
                    SERVER_START_REQ( query_completion )
                    {
                        req->handle = wine_server_obj_handle( CompletionPort );
                        if (!(status = wine_server_call( req )))
                            *info = reply->depth;
                    }
                    SERVER_END_REQ;
                }
            }
            break;
        default:
            status = STATUS_INVALID_PARAMETER;
            break;
    }
    return status;
}

NTSTATUS NTDLL_AddCompletion( HANDLE hFile, ULONG_PTR CompletionValue,
                              NTSTATUS CompletionStatus, ULONG Information, BOOL async )
{
    NTSTATUS status;

    SERVER_START_REQ( add_fd_completion )
    {
        req->handle      = wine_server_obj_handle( hFile );
        req->cvalue      = CompletionValue;
        req->status      = CompletionStatus;
        req->information = Information;
        req->async       = async;
        status = wine_server_call( req );
    }
    SERVER_END_REQ;
    return status;
=======
    if (!timeout) return "(infinite)";
    return wine_dbgstr_longlong( timeout->QuadPart );
>>>>>>> github-desktop-wine-mirror/master
}

/******************************************************************
 *              RtlRunOnceInitialize (NTDLL.@)
 */
void WINAPI RtlRunOnceInitialize( RTL_RUN_ONCE *once )
{
    once->Ptr = NULL;
}

/******************************************************************
 *              RtlRunOnceBeginInitialize (NTDLL.@)
 */
DWORD WINAPI RtlRunOnceBeginInitialize( RTL_RUN_ONCE *once, ULONG flags, void **context )
{
    if (flags & RTL_RUN_ONCE_CHECK_ONLY)
    {
        ULONG_PTR val = (ULONG_PTR)once->Ptr;

        if (flags & RTL_RUN_ONCE_ASYNC) return STATUS_INVALID_PARAMETER;
        if ((val & 3) != 2) return STATUS_UNSUCCESSFUL;
        if (context) *context = (void *)(val & ~3);
        return STATUS_SUCCESS;
    }

    for (;;)
    {
        ULONG_PTR next, val = (ULONG_PTR)once->Ptr;

        switch (val & 3)
        {
        case 0:  /* first time */
            if (!InterlockedCompareExchangePointer( &once->Ptr,
                                                    (flags & RTL_RUN_ONCE_ASYNC) ? (void *)3 : (void *)1, 0 ))
                return STATUS_PENDING;
            break;

        case 1:  /* in progress, wait */
            if (flags & RTL_RUN_ONCE_ASYNC) return STATUS_INVALID_PARAMETER;
            next = val & ~3;
            if (InterlockedCompareExchangePointer( &once->Ptr, (void *)((ULONG_PTR)&next | 1),
                                                   (void *)val ) == (void *)val)
                NtWaitForKeyedEvent( 0, &next, FALSE, NULL );
            break;

        case 2:  /* done */
            if (context) *context = (void *)(val & ~3);
            return STATUS_SUCCESS;

        case 3:  /* in progress, async */
            if (!(flags & RTL_RUN_ONCE_ASYNC)) return STATUS_INVALID_PARAMETER;
            return STATUS_PENDING;
        }
    }
}

/******************************************************************
 *              RtlRunOnceComplete (NTDLL.@)
 */
DWORD WINAPI RtlRunOnceComplete( RTL_RUN_ONCE *once, ULONG flags, void *context )
{
    if ((ULONG_PTR)context & 3) return STATUS_INVALID_PARAMETER;

    if (flags & RTL_RUN_ONCE_INIT_FAILED)
    {
        if (context) return STATUS_INVALID_PARAMETER;
        if (flags & RTL_RUN_ONCE_ASYNC) return STATUS_INVALID_PARAMETER;
    }
    else context = (void *)((ULONG_PTR)context | 2);

    for (;;)
    {
        ULONG_PTR val = (ULONG_PTR)once->Ptr;

        switch (val & 3)
        {
        case 1:  /* in progress */
            if (InterlockedCompareExchangePointer( &once->Ptr, context, (void *)val ) != (void *)val) break;
            val &= ~3;
            while (val)
            {
                ULONG_PTR next = *(ULONG_PTR *)val;
                NtReleaseKeyedEvent( 0, (void *)val, FALSE, NULL );
                val = next;
            }
            return STATUS_SUCCESS;

        case 3:  /* in progress, async */
            if (!(flags & RTL_RUN_ONCE_ASYNC)) return STATUS_INVALID_PARAMETER;
            if (InterlockedCompareExchangePointer( &once->Ptr, context, (void *)val ) != (void *)val) break;
            return STATUS_SUCCESS;

        default:
            return STATUS_UNSUCCESSFUL;
        }
    }
}


/***********************************************************************
 * Critical sections
 ***********************************************************************/


static void *no_debug_info_marker = (void *)(ULONG_PTR)-1;

static BOOL crit_section_has_debuginfo( const RTL_CRITICAL_SECTION *crit )
{
    return crit->DebugInfo != NULL && crit->DebugInfo != no_debug_info_marker;
}

static inline HANDLE get_semaphore( RTL_CRITICAL_SECTION *crit )
{
    HANDLE ret = crit->LockSemaphore;
    if (!ret)
    {
        HANDLE sem;
        if (NtCreateSemaphore( &sem, SEMAPHORE_ALL_ACCESS, NULL, 0, 1 )) return 0;
        if (!(ret = InterlockedCompareExchangePointer( &crit->LockSemaphore, sem, 0 )))
            ret = sem;
        else
            NtClose(sem);  /* somebody beat us to it */
    }
    return ret;
}

static inline NTSTATUS wait_semaphore( RTL_CRITICAL_SECTION *crit, int timeout )
{
    LARGE_INTEGER time = {.QuadPart = timeout * (LONGLONG)-10000000};

    /* debug info is cleared by MakeCriticalSectionGlobal */
    if (!crit_section_has_debuginfo( crit ))
    {
        HANDLE sem = get_semaphore( crit );
        return NtWaitForSingleObject( sem, FALSE, &time );
    }
    else
    {
        LONG *lock = (LONG *)&crit->LockSemaphore;
        while (!InterlockedCompareExchange( lock, 0, 1 ))
        {
            static const LONG zero;
            /* this may wait longer than specified in case of multiple wake-ups */
            if (RtlWaitOnAddress( lock, &zero, sizeof(LONG), &time ) == STATUS_TIMEOUT)
                return STATUS_TIMEOUT;
        }
        return STATUS_WAIT_0;
    }
}

/******************************************************************************
 *      RtlInitializeCriticalSection   (NTDLL.@)
 */
NTSTATUS WINAPI RtlInitializeCriticalSection( RTL_CRITICAL_SECTION *crit )
{
    return RtlInitializeCriticalSectionEx( crit, 0, 0 );
}


/******************************************************************************
 *      RtlInitializeCriticalSectionAndSpinCount   (NTDLL.@)
 */
NTSTATUS WINAPI RtlInitializeCriticalSectionAndSpinCount( RTL_CRITICAL_SECTION *crit, ULONG spincount )
{
    return RtlInitializeCriticalSectionEx( crit, spincount, 0 );
}


/******************************************************************************
 *      RtlInitializeCriticalSectionEx   (NTDLL.@)
 */
NTSTATUS WINAPI RtlInitializeCriticalSectionEx( RTL_CRITICAL_SECTION *crit, ULONG spincount, ULONG flags )
{
    if (flags & (RTL_CRITICAL_SECTION_FLAG_DYNAMIC_SPIN|RTL_CRITICAL_SECTION_FLAG_STATIC_INIT))
        FIXME("(%p,%u,0x%08x) semi-stub\n", crit, spincount, flags);

    /* FIXME: if RTL_CRITICAL_SECTION_FLAG_STATIC_INIT is given, we should use
     * memory from a static pool to hold the debug info. Then heap.c could pass
     * this flag rather than initialising the process heap CS by hand. If this
     * is done, then debug info should be managed through Rtlp[Allocate|Free]DebugInfo
     * so (e.g.) MakeCriticalSectionGlobal() doesn't free it using HeapFree().
     */
    if (flags & RTL_CRITICAL_SECTION_FLAG_NO_DEBUG_INFO)
        crit->DebugInfo = no_debug_info_marker;
    else
    {
        crit->DebugInfo = RtlAllocateHeap( GetProcessHeap(), 0, sizeof(RTL_CRITICAL_SECTION_DEBUG ));
        if (crit->DebugInfo)
        {
            crit->DebugInfo->Type = 0;
            crit->DebugInfo->CreatorBackTraceIndex = 0;
            crit->DebugInfo->CriticalSection = crit;
            crit->DebugInfo->ProcessLocksList.Blink = &crit->DebugInfo->ProcessLocksList;
            crit->DebugInfo->ProcessLocksList.Flink = &crit->DebugInfo->ProcessLocksList;
            crit->DebugInfo->EntryCount = 0;
            crit->DebugInfo->ContentionCount = 0;
            memset( crit->DebugInfo->Spare, 0, sizeof(crit->DebugInfo->Spare) );
        }
    }
    crit->LockCount      = -1;
    crit->RecursionCount = 0;
    crit->OwningThread   = 0;
    crit->LockSemaphore  = 0;
    if (NtCurrentTeb()->Peb->NumberOfProcessors <= 1) spincount = 0;
    crit->SpinCount = spincount & ~0x80000000;
    return STATUS_SUCCESS;
}


/******************************************************************************
 *      RtlSetCriticalSectionSpinCount   (NTDLL.@)
 */
ULONG WINAPI RtlSetCriticalSectionSpinCount( RTL_CRITICAL_SECTION *crit, ULONG spincount )
{
    ULONG oldspincount = crit->SpinCount;
    if (NtCurrentTeb()->Peb->NumberOfProcessors <= 1) spincount = 0;
    crit->SpinCount = spincount;
    return oldspincount;
}


/******************************************************************************
 *      RtlDeleteCriticalSection   (NTDLL.@)
 */
NTSTATUS WINAPI RtlDeleteCriticalSection( RTL_CRITICAL_SECTION *crit )
{
    crit->LockCount      = -1;
    crit->RecursionCount = 0;
    crit->OwningThread   = 0;
    if (crit_section_has_debuginfo( crit ))
    {
        /* only free the ones we made in here */
        if (!crit->DebugInfo->Spare[0])
        {
            RtlFreeHeap( GetProcessHeap(), 0, crit->DebugInfo );
            crit->DebugInfo = NULL;
        }
    }
    else NtClose( crit->LockSemaphore );
    crit->LockSemaphore = 0;
    return STATUS_SUCCESS;
}


/******************************************************************************
 *      RtlpWaitForCriticalSection   (NTDLL.@)
 */
NTSTATUS WINAPI RtlpWaitForCriticalSection( RTL_CRITICAL_SECTION *crit )
{
    LONGLONG timeout = NtCurrentTeb()->Peb->CriticalSectionTimeout.QuadPart / -10000000;

    /* Don't allow blocking on a critical section during process termination */
    if (RtlDllShutdownInProgress())
    {
        WARN( "process %s is shutting down, returning STATUS_SUCCESS\n",
              debugstr_w(NtCurrentTeb()->Peb->ProcessParameters->ImagePathName.Buffer) );
        return STATUS_SUCCESS;
    }

    for (;;)
    {
        EXCEPTION_RECORD rec;
        NTSTATUS status = wait_semaphore( crit, 5 );
        timeout -= 5;

        if ( status == STATUS_TIMEOUT )
        {
            const char *name = NULL;
            if (crit_section_has_debuginfo( crit )) name = (char *)crit->DebugInfo->Spare[0];
            if (!name) name = "?";
            ERR( "section %p %s wait timed out in thread %04x, blocked by %04x, retrying (60 sec)\n",
                 crit, debugstr_a(name), GetCurrentThreadId(), HandleToULong(crit->OwningThread) );
            status = wait_semaphore( crit, 60 );
            timeout -= 60;

            if ( status == STATUS_TIMEOUT && TRACE_ON(relay) )
            {
                ERR( "section %p %s wait timed out in thread %04x, blocked by %04x, retrying (5 min)\n",
                     crit, debugstr_a(name), GetCurrentThreadId(), HandleToULong(crit->OwningThread) );
                status = wait_semaphore( crit, 300 );
                timeout -= 300;
            }
        }
        if (status == STATUS_WAIT_0) break;

        /* Throw exception only for Wine internal locks */
        if (!crit_section_has_debuginfo( crit ) || !crit->DebugInfo->Spare[0]) continue;

        /* only throw deadlock exception if configured timeout is reached */
        if (timeout > 0) continue;

        rec.ExceptionCode    = STATUS_POSSIBLE_DEADLOCK;
        rec.ExceptionFlags   = 0;
        rec.ExceptionRecord  = NULL;
        rec.ExceptionAddress = RtlRaiseException;  /* sic */
        rec.NumberParameters = 1;
        rec.ExceptionInformation[0] = (ULONG_PTR)crit;
        RtlRaiseException( &rec );
    }
    if (crit_section_has_debuginfo( crit )) crit->DebugInfo->ContentionCount++;
    return STATUS_SUCCESS;
}


/******************************************************************************
 *      RtlpUnWaitCriticalSection   (NTDLL.@)
 */
NTSTATUS WINAPI RtlpUnWaitCriticalSection( RTL_CRITICAL_SECTION *crit )
{
    NTSTATUS ret;

    /* debug info is cleared by MakeCriticalSectionGlobal */
    if (!crit_section_has_debuginfo( crit ))
    {
        HANDLE sem = get_semaphore( crit );
        ret = NtReleaseSemaphore( sem, 1, NULL );
    }
    else
    {
        LONG *lock = (LONG *)&crit->LockSemaphore;
        InterlockedExchange( lock, 1 );
        RtlWakeAddressSingle( lock );
        ret = STATUS_SUCCESS;
    }
    if (ret) RtlRaiseStatus( ret );
    return ret;
}


/******************************************************************************
 *      RtlEnterCriticalSection   (NTDLL.@)
 */
NTSTATUS WINAPI RtlEnterCriticalSection( RTL_CRITICAL_SECTION *crit )
{
    if (crit->SpinCount)
    {
        ULONG count;

        if (RtlTryEnterCriticalSection( crit )) return STATUS_SUCCESS;
        for (count = crit->SpinCount; count > 0; count--)
        {
            if (crit->LockCount > 0) break;  /* more than one waiter, don't bother spinning */
            if (crit->LockCount == -1)       /* try again */
            {
                if (InterlockedCompareExchange( &crit->LockCount, 0, -1 ) == -1) goto done;
            }
            YieldProcessor();
        }
    }

    if (InterlockedIncrement( &crit->LockCount ))
    {
        if (crit->OwningThread == ULongToHandle(GetCurrentThreadId()))
        {
            crit->RecursionCount++;
            return STATUS_SUCCESS;
        }

        /* Now wait for it */
        RtlpWaitForCriticalSection( crit );
    }
done:
    crit->OwningThread   = ULongToHandle(GetCurrentThreadId());
    crit->RecursionCount = 1;
    return STATUS_SUCCESS;
}


/******************************************************************************
 *      RtlTryEnterCriticalSection   (NTDLL.@)
 */
BOOL WINAPI RtlTryEnterCriticalSection( RTL_CRITICAL_SECTION *crit )
{
    BOOL ret = FALSE;
    if (InterlockedCompareExchange( &crit->LockCount, 0, -1 ) == -1)
    {
        crit->OwningThread   = ULongToHandle(GetCurrentThreadId());
        crit->RecursionCount = 1;
        ret = TRUE;
    }
    else if (crit->OwningThread == ULongToHandle(GetCurrentThreadId()))
    {
        InterlockedIncrement( &crit->LockCount );
        crit->RecursionCount++;
        ret = TRUE;
    }
    return ret;
}


/******************************************************************************
 *      RtlIsCriticalSectionLocked   (NTDLL.@)
 */
BOOL WINAPI RtlIsCriticalSectionLocked( RTL_CRITICAL_SECTION *crit )
{
    return crit->RecursionCount != 0;
}


/******************************************************************************
 *      RtlIsCriticalSectionLockedByThread   (NTDLL.@)
 */
BOOL WINAPI RtlIsCriticalSectionLockedByThread( RTL_CRITICAL_SECTION *crit )
{
    return crit->OwningThread == ULongToHandle(GetCurrentThreadId()) &&
           crit->RecursionCount;
}


/******************************************************************************
 *      RtlLeaveCriticalSection   (NTDLL.@)
 */
NTSTATUS WINAPI RtlLeaveCriticalSection( RTL_CRITICAL_SECTION *crit )
{
    if (--crit->RecursionCount)
    {
        if (crit->RecursionCount > 0) InterlockedDecrement( &crit->LockCount );
        else ERR( "section %p is not acquired\n", crit );
    }
    else
    {
        crit->OwningThread = 0;
        if (InterlockedDecrement( &crit->LockCount ) >= 0)
        {
            /* someone is waiting */
            RtlpUnWaitCriticalSection( crit );
        }
    }
    return STATUS_SUCCESS;
}

/******************************************************************
 *              RtlRunOnceExecuteOnce (NTDLL.@)
 */
DWORD WINAPI RtlRunOnceExecuteOnce( RTL_RUN_ONCE *once, PRTL_RUN_ONCE_INIT_FN func,
                                    void *param, void **context )
{
    DWORD ret = RtlRunOnceBeginInitialize( once, 0, context );

    if (ret != STATUS_PENDING) return ret;

    if (!func( once, param, context ))
    {
        RtlRunOnceComplete( once, RTL_RUN_ONCE_INIT_FAILED, NULL );
        return STATUS_UNSUCCESSFUL;
    }

    return RtlRunOnceComplete( once, 0, context ? *context : NULL );
}

struct srw_lock
{
<<<<<<< HEAD
    int old, new, *futex;
    NTSTATUS ret;

    if (!use_futexes()) return STATUS_NOT_IMPLEMENTED;

    if (!(futex = get_futex( &lock->Ptr )))
        return STATUS_NOT_IMPLEMENTED;

    do
    {
        old = *futex;

        if (!(old & SRWLOCK_FUTEX_EXCLUSIVE_LOCK_BIT)
                && !(old & SRWLOCK_FUTEX_SHARED_OWNERS_MASK))
        {
            /* Not locked exclusive or shared. We can try to grab it. */
            new = old | SRWLOCK_FUTEX_EXCLUSIVE_LOCK_BIT;
            ret = STATUS_SUCCESS;
        }
        else
        {
            new = old;
            ret = STATUS_TIMEOUT;
        }
    } while (interlocked_cmpxchg( futex, new, old ) != old);

    return ret;
}

static NTSTATUS fast_acquire_srw_exclusive( RTL_SRWLOCK *lock )
{
    int old, new, *futex;
    BOOLEAN wait;

    if (!use_futexes()) return STATUS_NOT_IMPLEMENTED;

    if (!(futex = get_futex( &lock->Ptr )))
        return STATUS_NOT_IMPLEMENTED;

    /* Atomically increment the exclusive waiter count. */
    do
    {
        old = *futex;
        new = old + SRWLOCK_FUTEX_EXCLUSIVE_WAITERS_INC;
        assert(new & SRWLOCK_FUTEX_EXCLUSIVE_WAITERS_MASK);
    } while (interlocked_cmpxchg( futex, new, old ) != old);

    for (;;)
    {
        do
        {
            old = *futex;

            if (!(old & SRWLOCK_FUTEX_EXCLUSIVE_LOCK_BIT)
                    && !(old & SRWLOCK_FUTEX_SHARED_OWNERS_MASK))
            {
                /* Not locked exclusive or shared. We can try to grab it. */
                new = old | SRWLOCK_FUTEX_EXCLUSIVE_LOCK_BIT;
                assert(old & SRWLOCK_FUTEX_EXCLUSIVE_WAITERS_MASK);
                new -= SRWLOCK_FUTEX_EXCLUSIVE_WAITERS_INC;
                wait = FALSE;
            }
            else
            {
                new = old;
                wait = TRUE;
            }
        } while (interlocked_cmpxchg( futex, new, old ) != old);

        if (!wait)
            return STATUS_SUCCESS;

        futex_wait_bitset( futex, new, NULL, SRWLOCK_FUTEX_BITSET_EXCLUSIVE );
    }

    return STATUS_SUCCESS;
}

static NTSTATUS fast_try_acquire_srw_shared( RTL_SRWLOCK *lock )
{
    int new, old, *futex;
    NTSTATUS ret;

    if (!use_futexes()) return STATUS_NOT_IMPLEMENTED;

    if (!(futex = get_futex( &lock->Ptr )))
        return STATUS_NOT_IMPLEMENTED;

    do
    {
        old = *futex;

        if (!(old & SRWLOCK_FUTEX_EXCLUSIVE_LOCK_BIT)
                && !(old & SRWLOCK_FUTEX_EXCLUSIVE_WAITERS_MASK))
        {
            /* Not locked exclusive, and no exclusive waiters. We can try to
             * grab it. */
            new = old + SRWLOCK_FUTEX_SHARED_OWNERS_INC;
            assert(new & SRWLOCK_FUTEX_SHARED_OWNERS_MASK);
            ret = STATUS_SUCCESS;
        }
        else
        {
            new = old;
            ret = STATUS_TIMEOUT;
        }
    } while (interlocked_cmpxchg( futex, new, old ) != old);

    return ret;
}

static NTSTATUS fast_acquire_srw_shared( RTL_SRWLOCK *lock )
{
    int old, new, *futex;
    BOOLEAN wait;

    if (!use_futexes()) return STATUS_NOT_IMPLEMENTED;

    if (!(futex = get_futex( &lock->Ptr )))
        return STATUS_NOT_IMPLEMENTED;

    for (;;)
    {
        do
        {
            old = *futex;

            if (!(old & SRWLOCK_FUTEX_EXCLUSIVE_LOCK_BIT)
                    && !(old & SRWLOCK_FUTEX_EXCLUSIVE_WAITERS_MASK))
            {
                /* Not locked exclusive, and no exclusive waiters. We can try
                 * to grab it. */
                new = old + SRWLOCK_FUTEX_SHARED_OWNERS_INC;
                assert(new & SRWLOCK_FUTEX_SHARED_OWNERS_MASK);
                wait = FALSE;
            }
            else
            {
                new = old | SRWLOCK_FUTEX_SHARED_WAITERS_BIT;
                wait = TRUE;
            }
        } while (interlocked_cmpxchg( futex, new, old ) != old);

        if (!wait)
            return STATUS_SUCCESS;

        futex_wait_bitset( futex, new, NULL, SRWLOCK_FUTEX_BITSET_SHARED );
    }

    return STATUS_SUCCESS;
}

static NTSTATUS fast_release_srw_exclusive( RTL_SRWLOCK *lock )
{
    int old, new, *futex;

    if (!use_futexes()) return STATUS_NOT_IMPLEMENTED;

    if (!(futex = get_futex( &lock->Ptr )))
        return STATUS_NOT_IMPLEMENTED;

    do
    {
        old = *futex;

        if (!(old & SRWLOCK_FUTEX_EXCLUSIVE_LOCK_BIT))
        {
            ERR("Lock %p is not owned exclusive! (%#x)\n", lock, *futex);
            return STATUS_RESOURCE_NOT_OWNED;
        }

        new = old & ~SRWLOCK_FUTEX_EXCLUSIVE_LOCK_BIT;

        if (!(new & SRWLOCK_FUTEX_EXCLUSIVE_WAITERS_MASK))
            new &= ~SRWLOCK_FUTEX_SHARED_WAITERS_BIT;
    } while (interlocked_cmpxchg( futex, new, old ) != old);

    if (new & SRWLOCK_FUTEX_EXCLUSIVE_WAITERS_MASK)
        futex_wake_bitset( futex, 1, SRWLOCK_FUTEX_BITSET_EXCLUSIVE );
    else if (old & SRWLOCK_FUTEX_SHARED_WAITERS_BIT)
        futex_wake_bitset( futex, INT_MAX, SRWLOCK_FUTEX_BITSET_SHARED );

    return STATUS_SUCCESS;
}

static NTSTATUS fast_release_srw_shared( RTL_SRWLOCK *lock )
{
    int old, new, *futex;

    if (!use_futexes()) return STATUS_NOT_IMPLEMENTED;

    if (!(futex = get_futex( &lock->Ptr )))
        return STATUS_NOT_IMPLEMENTED;

    do
    {
        old = *futex;

        if (old & SRWLOCK_FUTEX_EXCLUSIVE_LOCK_BIT)
        {
            ERR("Lock %p is owned exclusive! (%#x)\n", lock, *futex);
            return STATUS_RESOURCE_NOT_OWNED;
        }
        else if (!(old & SRWLOCK_FUTEX_SHARED_OWNERS_MASK))
        {
            ERR("Lock %p is not owned shared! (%#x)\n", lock, *futex);
            return STATUS_RESOURCE_NOT_OWNED;
        }

        new = old - SRWLOCK_FUTEX_SHARED_OWNERS_INC;
    } while (interlocked_cmpxchg( futex, new, old ) != old);

    /* Optimization: only bother waking if there are actually exclusive waiters. */
    if (!(new & SRWLOCK_FUTEX_SHARED_OWNERS_MASK) && (new & SRWLOCK_FUTEX_EXCLUSIVE_WAITERS_MASK))
        futex_wake_bitset( futex, 1, SRWLOCK_FUTEX_BITSET_EXCLUSIVE );

    return STATUS_SUCCESS;
}

#else

static NTSTATUS fast_try_acquire_srw_exclusive( RTL_SRWLOCK *lock )
{
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS fast_acquire_srw_exclusive( RTL_SRWLOCK *lock )
{
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS fast_try_acquire_srw_shared( RTL_SRWLOCK *lock )
{
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS fast_acquire_srw_shared( RTL_SRWLOCK *lock )
{
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS fast_release_srw_exclusive( RTL_SRWLOCK *lock )
{
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS fast_release_srw_shared( RTL_SRWLOCK *lock )
{
    return STATUS_NOT_IMPLEMENTED;
}

#endif

/* SRW locks implementation
 *
 * The memory layout used by the lock is:
 *
 * 32 31            16               0
 *  ________________ ________________
 * | X| #exclusive  |    #shared     |
 *  ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
 * Since there is no space left for a separate counter of shared access
 * threads inside the locked section the #shared field is used for multiple
 * purposes. The following table lists all possible states the lock can be
 * in, notation: [X, #exclusive, #shared]:
 *
 * [0,   0,   N] -> locked by N shared access threads, if N=0 it's unlocked
 * [0, >=1, >=1] -> threads are requesting exclusive locks, but there are
 * still shared access threads inside. #shared should not be incremented
 * anymore!
 * [1, >=1, >=0] -> lock is owned by an exclusive thread and the #shared
 * counter can be used again to count the number of threads waiting in the
 * queue for shared access.
 *
 * the following states are invalid and will never occur:
 * [0, >=1,   0], [1,   0, >=0]
 *
 * The main problem arising from the fact that we have no separate counter
 * of shared access threads inside the locked section is that in the state
 * [0, >=1, >=1] above we cannot add additional waiting threads to the
 * shared access queue - it wouldn't be possible to distinguish waiting
 * threads and those that are still inside. To solve this problem the lock
 * uses the following approach: a thread that isn't able to allocate a
 * shared lock just uses the exclusive queue instead. As soon as the thread
 * is woken up it is in the state [1, >=1, >=0]. In this state it's again
 * possible to use the shared access queue. The thread atomically moves
 * itself to the shared access queue and releases the exclusive lock, so
 * that the "real" exclusive access threads have a chance. As soon as they
 * are all ready the shared access threads are processed.
 */

#define SRWLOCK_MASK_IN_EXCLUSIVE     0x80000000
#define SRWLOCK_MASK_EXCLUSIVE_QUEUE  0x7fff0000
#define SRWLOCK_MASK_SHARED_QUEUE     0x0000ffff
#define SRWLOCK_RES_EXCLUSIVE         0x00010000
#define SRWLOCK_RES_SHARED            0x00000001

#ifdef WORDS_BIGENDIAN
#define srwlock_key_exclusive(lock)   ((void *)(((ULONG_PTR)&lock->Ptr + 1) & ~1))
#define srwlock_key_shared(lock)      ((void *)(((ULONG_PTR)&lock->Ptr + 3) & ~1))
#else
#define srwlock_key_exclusive(lock)   ((void *)(((ULONG_PTR)&lock->Ptr + 3) & ~1))
#define srwlock_key_shared(lock)      ((void *)(((ULONG_PTR)&lock->Ptr + 1) & ~1))
#endif

static inline void srwlock_check_invalid( unsigned int val )
{
    /* Throw exception if it's impossible to acquire/release this lock. */
    if ((val & SRWLOCK_MASK_EXCLUSIVE_QUEUE) == SRWLOCK_MASK_EXCLUSIVE_QUEUE ||
            (val & SRWLOCK_MASK_SHARED_QUEUE) == SRWLOCK_MASK_SHARED_QUEUE)
        RtlRaiseStatus(STATUS_RESOURCE_NOT_OWNED);
}

static inline unsigned int srwlock_lock_exclusive( unsigned int *dest, int incr )
{
    unsigned int val, tmp;
    /* Atomically modifies the value of *dest by adding incr. If the shared
     * queue is empty and there are threads waiting for exclusive access, then
     * sets the mark SRWLOCK_MASK_IN_EXCLUSIVE to signal other threads that
     * they are allowed again to use the shared queue counter. */
    for (val = *dest;; val = tmp)
    {
        tmp = val + incr;
        srwlock_check_invalid( tmp );
        if ((tmp & SRWLOCK_MASK_EXCLUSIVE_QUEUE) && !(tmp & SRWLOCK_MASK_SHARED_QUEUE))
            tmp |= SRWLOCK_MASK_IN_EXCLUSIVE;
        if ((tmp = interlocked_cmpxchg( (int *)dest, tmp, val )) == val)
            break;
    }
    return val;
}

static inline unsigned int srwlock_unlock_exclusive( unsigned int *dest, int incr )
{
    unsigned int val, tmp;
    /* Atomically modifies the value of *dest by adding incr. If the queue of
     * threads waiting for exclusive access is empty, then remove the
     * SRWLOCK_MASK_IN_EXCLUSIVE flag (only the shared queue counter will
     * remain). */
    for (val = *dest;; val = tmp)
    {
        tmp = val + incr;
        srwlock_check_invalid( tmp );
        if (!(tmp & SRWLOCK_MASK_EXCLUSIVE_QUEUE))
            tmp &= SRWLOCK_MASK_SHARED_QUEUE;
        if ((tmp = interlocked_cmpxchg( (int *)dest, tmp, val )) == val)
            break;
    }
    return val;
}

static inline void srwlock_leave_exclusive( RTL_SRWLOCK *lock, unsigned int val )
{
    /* Used when a thread leaves an exclusive section. If there are other
     * exclusive access threads they are processed first, followed by
     * the shared waiters. */
    if (val & SRWLOCK_MASK_EXCLUSIVE_QUEUE)
        NtReleaseKeyedEvent( 0, srwlock_key_exclusive(lock), FALSE, NULL );
    else
    {
        val &= SRWLOCK_MASK_SHARED_QUEUE; /* remove SRWLOCK_MASK_IN_EXCLUSIVE */
        while (val--)
            NtReleaseKeyedEvent( 0, srwlock_key_shared(lock), FALSE, NULL );
    }
}

static inline void srwlock_leave_shared( RTL_SRWLOCK *lock, unsigned int val )
{
    /* Wake up one exclusive thread as soon as the last shared access thread
     * has left. */
    if ((val & SRWLOCK_MASK_EXCLUSIVE_QUEUE) && !(val & SRWLOCK_MASK_SHARED_QUEUE))
        NtReleaseKeyedEvent( 0, srwlock_key_exclusive(lock), FALSE, NULL );
}
=======
    short exclusive_waiters;

    /* Number of shared owners, or -1 if owned exclusive.
     *
     * Sadly Windows has no equivalent to FUTEX_WAIT_BITSET, so in order to wake
     * up *only* exclusive or *only* shared waiters (and thus avoid spurious
     * wakeups), we need to wait on two different addresses.
     * RtlAcquireSRWLockShared() needs to know the values of "exclusive_waiters"
     * and "owners", but RtlAcquireSRWLockExclusive() only needs to know the
     * value of "owners", so the former can wait on the entire structure, and
     * the latter waits only on the "owners" member. Note then that "owners"
     * must not be the first element in the structure.
     */
    short owners;
};
C_ASSERT( sizeof(struct srw_lock) == 4 );
>>>>>>> github-desktop-wine-mirror/master

/***********************************************************************
 *              RtlInitializeSRWLock (NTDLL.@)
 *
 * NOTES
 *  Please note that SRWLocks do not keep track of the owner of a lock.
 *  It doesn't make any difference which thread for example unlocks an
 *  SRWLock (see corresponding tests). This implementation uses two
 *  keyed events (one for the exclusive waiters and one for the shared
 *  waiters) and is limited to 2^15-1 waiting threads.
 */
void WINAPI RtlInitializeSRWLock( RTL_SRWLOCK *lock )
{
    lock->Ptr = NULL;
}

/***********************************************************************
 *              RtlAcquireSRWLockExclusive (NTDLL.@)
 *
 * NOTES
 *  Unlike RtlAcquireResourceExclusive this function doesn't allow
 *  nested calls from the same thread. "Upgrading" a shared access lock
 *  to an exclusive access lock also doesn't seem to be supported.
 */
void WINAPI RtlAcquireSRWLockExclusive( RTL_SRWLOCK *lock )
{
    union { RTL_SRWLOCK *rtl; struct srw_lock *s; LONG *l; } u = { lock };

    InterlockedIncrement16( &u.s->exclusive_waiters );

    for (;;)
    {
        union { struct srw_lock s; LONG l; } old, new;
        BOOL wait;

        do
        {
            old.s = *u.s;
            new.s = old.s;

            if (!old.s.owners)
            {
                /* Not locked exclusive or shared. We can try to grab it. */
                new.s.owners = -1;
                --new.s.exclusive_waiters;
                wait = FALSE;
            }
            else
            {
                wait = TRUE;
            }
        } while (InterlockedCompareExchange( u.l, new.l, old.l ) != old.l);

        if (!wait) return;
        RtlWaitOnAddress( &u.s->owners, &new.s.owners, sizeof(short), NULL );
    }
}

/***********************************************************************
 *              RtlAcquireSRWLockShared (NTDLL.@)
 *
 * NOTES
 *   Do not call this function recursively - it will only succeed when
 *   there are no threads waiting for an exclusive lock!
 */
void WINAPI RtlAcquireSRWLockShared( RTL_SRWLOCK *lock )
{
    union { RTL_SRWLOCK *rtl; struct srw_lock *s; LONG *l; } u = { lock };

    for (;;)
    {
        union { struct srw_lock s; LONG l; } old, new;
        BOOL wait;

        do
        {
            old.s = *u.s;
            new = old;

            if (old.s.owners != -1 && !old.s.exclusive_waiters)
            {
                /* Not locked exclusive, and no exclusive waiters.
                 * We can try to grab it. */
                ++new.s.owners;
                wait = FALSE;
            }
            else
            {
                wait = TRUE;
            }
        } while (InterlockedCompareExchange( u.l, new.l, old.l ) != old.l);

        if (!wait) return;
        RtlWaitOnAddress( u.s, &new.s, sizeof(struct srw_lock), NULL );
    }
}

/***********************************************************************
 *              RtlReleaseSRWLockExclusive (NTDLL.@)
 */
void WINAPI RtlReleaseSRWLockExclusive( RTL_SRWLOCK *lock )
{
    union { RTL_SRWLOCK *rtl; struct srw_lock *s; LONG *l; } u = { lock };
    union { struct srw_lock s; LONG l; } old, new;

    do
    {
        old.s = *u.s;
        new = old;

        if (old.s.owners != -1) ERR("Lock %p is not owned exclusive!\n", lock);

        new.s.owners = 0;
    } while (InterlockedCompareExchange( u.l, new.l, old.l ) != old.l);

    if (new.s.exclusive_waiters)
        RtlWakeAddressSingle( &u.s->owners );
    else
        RtlWakeAddressAll( u.s );
}

/***********************************************************************
 *              RtlReleaseSRWLockShared (NTDLL.@)
 */
void WINAPI RtlReleaseSRWLockShared( RTL_SRWLOCK *lock )
{
    union { RTL_SRWLOCK *rtl; struct srw_lock *s; LONG *l; } u = { lock };
    union { struct srw_lock s; LONG l; } old, new;

    do
    {
        old.s = *u.s;
        new = old;

        if (old.s.owners == -1) ERR("Lock %p is owned exclusive!\n", lock);
        else if (!old.s.owners) ERR("Lock %p is not owned shared!\n", lock);

        --new.s.owners;
    } while (InterlockedCompareExchange( u.l, new.l, old.l ) != old.l);

    if (!new.s.owners)
        RtlWakeAddressSingle( &u.s->owners );
}

/***********************************************************************
 *              RtlTryAcquireSRWLockExclusive (NTDLL.@)
 *
 * NOTES
 *  Similarly to AcquireSRWLockExclusive, recursive calls are not allowed
 *  and will fail with a FALSE return value.
 */
BOOLEAN WINAPI RtlTryAcquireSRWLockExclusive( RTL_SRWLOCK *lock )
{
    union { RTL_SRWLOCK *rtl; struct srw_lock *s; LONG *l; } u = { lock };
    union { struct srw_lock s; LONG l; } old, new;
    BOOLEAN ret;

    do
    {
        old.s = *u.s;
        new.s = old.s;

        if (!old.s.owners)
        {
            /* Not locked exclusive or shared. We can try to grab it. */
            new.s.owners = -1;
            ret = TRUE;
        }
        else
        {
            ret = FALSE;
        }
    } while (InterlockedCompareExchange( u.l, new.l, old.l ) != old.l);

    return ret;
}

/***********************************************************************
 *              RtlTryAcquireSRWLockShared (NTDLL.@)
 */
BOOLEAN WINAPI RtlTryAcquireSRWLockShared( RTL_SRWLOCK *lock )
{
    union { RTL_SRWLOCK *rtl; struct srw_lock *s; LONG *l; } u = { lock };
    union { struct srw_lock s; LONG l; } old, new;
    BOOLEAN ret;

    do
    {
        old.s = *u.s;
        new.s = old.s;

        if (old.s.owners != -1 && !old.s.exclusive_waiters)
        {
            /* Not locked exclusive, and no exclusive waiters.
             * We can try to grab it. */
            ++new.s.owners;
            ret = TRUE;
        }
        else
        {
            ret = FALSE;
        }
    } while (InterlockedCompareExchange( u.l, new.l, old.l ) != old.l);

    return ret;
}

<<<<<<< HEAD
#ifdef __linux__
static NTSTATUS fast_wait_cv( int *futex, int val, const LARGE_INTEGER *timeout )
{
    struct timespec timespec;
    int ret;

    if (timeout && timeout->QuadPart != TIMEOUT_INFINITE)
    {
        timespec_from_timeout( &timespec, timeout );
        ret = futex_wait( futex, val, &timespec );
    }
    else
        ret = futex_wait( futex, val, NULL );

    if (ret == -1 && errno == ETIMEDOUT)
        return STATUS_TIMEOUT;
    return STATUS_WAIT_0;
}

static NTSTATUS fast_sleep_cs_cv( RTL_CONDITION_VARIABLE *variable,
        RTL_CRITICAL_SECTION *cs, const LARGE_INTEGER *timeout )
{
    NTSTATUS status;
    int val, *futex;

    if (!use_futexes())
        return STATUS_NOT_IMPLEMENTED;

    if (!(futex = get_futex( &variable->Ptr )))
        return STATUS_NOT_IMPLEMENTED;

    val = *futex;

    RtlLeaveCriticalSection( cs );
    status = fast_wait_cv( futex, val, timeout );
    RtlEnterCriticalSection( cs );
    return status;
}

static NTSTATUS fast_sleep_srw_cv( RTL_CONDITION_VARIABLE *variable,
        RTL_SRWLOCK *lock, const LARGE_INTEGER *timeout, ULONG flags )
{
    NTSTATUS status;
    int val, *futex;

    if (!use_futexes())
        return STATUS_NOT_IMPLEMENTED;

    if (!(futex = get_futex( &variable->Ptr )))
        return STATUS_NOT_IMPLEMENTED;

    val = *futex;

    if (flags & RTL_CONDITION_VARIABLE_LOCKMODE_SHARED)
        RtlReleaseSRWLockShared( lock );
    else
        RtlReleaseSRWLockExclusive( lock );

    status = fast_wait_cv( futex, val, timeout );

    if (flags & RTL_CONDITION_VARIABLE_LOCKMODE_SHARED)
        RtlAcquireSRWLockShared( lock );
    else
        RtlAcquireSRWLockExclusive( lock );
    return status;
}

static NTSTATUS fast_wake_cv( RTL_CONDITION_VARIABLE *variable, int count )
{
    int *futex;

    if (!use_futexes()) return STATUS_NOT_IMPLEMENTED;

    if (!(futex = get_futex( &variable->Ptr )))
        return STATUS_NOT_IMPLEMENTED;

    interlocked_xchg_add( futex, 1 );
    futex_wake( futex, count );
    return STATUS_SUCCESS;
}
#else
static NTSTATUS fast_sleep_srw_cv( RTL_CONDITION_VARIABLE *variable,
        RTL_SRWLOCK *lock, const LARGE_INTEGER *timeout, ULONG flags )
{
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS fast_sleep_cs_cv( RTL_CONDITION_VARIABLE *variable,
        RTL_CRITICAL_SECTION *cs, const LARGE_INTEGER *timeout )
{
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS fast_wait_cv( RTL_CONDITION_VARIABLE *variable, int val, const LARGE_INTEGER *timeout )
{
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS fast_wake_cv( RTL_CONDITION_VARIABLE *variable, int count )
{
    return STATUS_NOT_IMPLEMENTED;
}
#endif

=======
>>>>>>> github-desktop-wine-mirror/master
/***********************************************************************
 *           RtlInitializeConditionVariable   (NTDLL.@)
 *
 * Initializes the condition variable with NULL.
 *
 * PARAMS
 *  variable [O] condition variable
 *
 * RETURNS
 *  Nothing.
 */
void WINAPI RtlInitializeConditionVariable( RTL_CONDITION_VARIABLE *variable )
{
    variable->Ptr = NULL;
}

/***********************************************************************
 *           RtlWakeConditionVariable   (NTDLL.@)
 *
 * Wakes up one thread waiting on the condition variable.
 *
 * PARAMS
 *  variable [I/O] condition variable to wake up.
 *
 * RETURNS
 *  Nothing.
 *
 * NOTES
 *  The calling thread does not have to own any lock in order to call
 *  this function.
 */
void WINAPI RtlWakeConditionVariable( RTL_CONDITION_VARIABLE *variable )
{
<<<<<<< HEAD
    if (fast_wake_cv( variable, 1 ) == STATUS_NOT_IMPLEMENTED)
    {
        interlocked_xchg_add( (int *)&variable->Ptr, 1 );
        RtlWakeAddressSingle( variable );
    }
=======
    InterlockedIncrement( (LONG *)&variable->Ptr );
    RtlWakeAddressSingle( variable );
>>>>>>> github-desktop-wine-mirror/master
}

/***********************************************************************
 *           RtlWakeAllConditionVariable   (NTDLL.@)
 *
 * See WakeConditionVariable, wakes up all waiting threads.
 */
void WINAPI RtlWakeAllConditionVariable( RTL_CONDITION_VARIABLE *variable )
{
<<<<<<< HEAD
    if (fast_wake_cv( variable, INT_MAX ) == STATUS_NOT_IMPLEMENTED)
    {
        interlocked_xchg_add( (int *)&variable->Ptr, 1 );
        RtlWakeAddressAll( variable );
    }
=======
    InterlockedIncrement( (LONG *)&variable->Ptr );
    RtlWakeAddressAll( variable );
>>>>>>> github-desktop-wine-mirror/master
}

/***********************************************************************
 *           RtlSleepConditionVariableCS   (NTDLL.@)
 *
 * Atomically releases the critical section and suspends the thread,
 * waiting for a Wake(All)ConditionVariable event. Afterwards it enters
 * the critical section again and returns.
 *
 * PARAMS
 *  variable  [I/O] condition variable
 *  crit      [I/O] critical section to leave temporarily
 *  timeout   [I]   timeout
 *
 * RETURNS
 *  see NtWaitForKeyedEvent for all possible return values.
 */
NTSTATUS WINAPI RtlSleepConditionVariableCS( RTL_CONDITION_VARIABLE *variable, RTL_CRITICAL_SECTION *crit,
                                             const LARGE_INTEGER *timeout )
{
    int value = *(int *)&variable->Ptr;
    NTSTATUS status;
<<<<<<< HEAD
    int val;
=======
>>>>>>> github-desktop-wine-mirror/master

    if ((status = fast_sleep_cs_cv( variable, crit, timeout )) != STATUS_NOT_IMPLEMENTED)
        return status;

    val = *(int *)&variable->Ptr;
    RtlLeaveCriticalSection( crit );
<<<<<<< HEAD
    status = RtlWaitOnAddress( &variable->Ptr, &val, sizeof(int), timeout );
=======
    status = RtlWaitOnAddress( &variable->Ptr, &value, sizeof(value), timeout );
>>>>>>> github-desktop-wine-mirror/master
    RtlEnterCriticalSection( crit );
    return status;
}

/***********************************************************************
 *           RtlSleepConditionVariableSRW   (NTDLL.@)
 *
 * Atomically releases the SRWLock and suspends the thread,
 * waiting for a Wake(All)ConditionVariable event. Afterwards it enters
 * the SRWLock again with the same access rights and returns.
 *
 * PARAMS
 *  variable  [I/O] condition variable
 *  lock      [I/O] SRWLock to leave temporarily
 *  timeout   [I]   timeout
 *  flags     [I]   type of the current lock (exclusive / shared)
 *
 * RETURNS
 *  see NtWaitForKeyedEvent for all possible return values.
 *
 * NOTES
 *  the behaviour is undefined if the thread doesn't own the lock.
 */
NTSTATUS WINAPI RtlSleepConditionVariableSRW( RTL_CONDITION_VARIABLE *variable, RTL_SRWLOCK *lock,
                                              const LARGE_INTEGER *timeout, ULONG flags )
{
    int value = *(int *)&variable->Ptr;
    NTSTATUS status;
<<<<<<< HEAD
    int val;

    if ((status = fast_sleep_srw_cv( variable, lock, timeout, flags )) != STATUS_NOT_IMPLEMENTED)
        return status;

    val = *(int *)&variable->Ptr;
=======
>>>>>>> github-desktop-wine-mirror/master

    if (flags & RTL_CONDITION_VARIABLE_LOCKMODE_SHARED)
        RtlReleaseSRWLockShared( lock );
    else
        RtlReleaseSRWLockExclusive( lock );

<<<<<<< HEAD
    status = RtlWaitOnAddress( &variable->Ptr, &val, sizeof(int), timeout );
=======
    status = RtlWaitOnAddress( &variable->Ptr, &value, sizeof(value), timeout );
>>>>>>> github-desktop-wine-mirror/master

    if (flags & RTL_CONDITION_VARIABLE_LOCKMODE_SHARED)
        RtlAcquireSRWLockShared( lock );
    else
        RtlAcquireSRWLockExclusive( lock );
    return status;
}

/* RtlWaitOnAddress() and RtlWakeAddress*(), hereafter referred to as "Win32
 * futexes", offer futex-like semantics with a variable set of address sizes,
 * but are limited to a single process. They are also fair—the documentation
 * specifies this, and tests bear it out.
 *
 * On Windows they are implemented using NtAlertThreadByThreadId and
 * NtWaitForAlertByThreadId, which manipulate a single flag (similar to an
 * auto-reset event) per thread. This can be tested by attempting to wake a
 * thread waiting in RtlWaitOnAddress() via NtAlertThreadByThreadId.
 */

struct futex_entry
{
    struct list entry;
    const void *addr;
    DWORD tid;
};

struct futex_queue
{
    struct list queue;
    LONG lock;
};

static struct futex_queue futex_queues[256];

static struct futex_queue *get_futex_queue( const void *addr )
{
    ULONG_PTR val = (ULONG_PTR)addr;

    return &futex_queues[(val >> 4) % ARRAY_SIZE(futex_queues)];
}

static void spin_lock( LONG *lock )
{
    while (InterlockedCompareExchange( lock, -1, 0 ))
        YieldProcessor();
}

static void spin_unlock( LONG *lock )
{
    InterlockedExchange( lock, 0 );
}

static BOOL compare_addr( const void *addr, const void *cmp, SIZE_T size )
{
    switch (size)
    {
        case 1:
            return (*(const UCHAR *)addr == *(const UCHAR *)cmp);
        case 2:
            return (*(const USHORT *)addr == *(const USHORT *)cmp);
        case 4:
            return (*(const ULONG *)addr == *(const ULONG *)cmp);
        case 8:
            return (*(const ULONG64 *)addr == *(const ULONG64 *)cmp);
    }

    return FALSE;
}

/***********************************************************************
 *           RtlWaitOnAddress   (NTDLL.@)
 */
NTSTATUS WINAPI RtlWaitOnAddress( const void *addr, const void *cmp, SIZE_T size,
                                  const LARGE_INTEGER *timeout )
{
    struct futex_queue *queue = get_futex_queue( addr );
    struct futex_entry entry;
    NTSTATUS ret;

    TRACE("addr %p cmp %p size %#Ix timeout %s\n", addr, cmp, size, debugstr_timeout( timeout ));

    if (size != 1 && size != 2 && size != 4 && size != 8)
        return STATUS_INVALID_PARAMETER;

    entry.addr = addr;
    entry.tid = GetCurrentThreadId();

    spin_lock( &queue->lock );

    /* Do the comparison inside of the spinlock, to reduce spurious wakeups. */

    if (!compare_addr( addr, cmp, size ))
    {
        spin_unlock( &queue->lock );
        return STATUS_SUCCESS;
    }

    if (!queue->queue.next)
        list_init( &queue->queue );
    list_add_tail( &queue->queue, &entry.entry );

    spin_unlock( &queue->lock );

    ret = NtWaitForAlertByThreadId( NULL, timeout );

    spin_lock( &queue->lock );
    /* We may have already been removed by a call to RtlWakeAddressSingle(). */
    if (entry.addr)
        list_remove( &entry.entry );
    spin_unlock( &queue->lock );

    TRACE("returning %#x\n", ret);

    if (ret == STATUS_ALERTED) ret = STATUS_SUCCESS;
    return ret;
}

/***********************************************************************
 *           RtlWakeAddressAll    (NTDLL.@)
 */
void WINAPI RtlWakeAddressAll( const void *addr )
{
    struct futex_queue *queue = get_futex_queue( addr );
    unsigned int count = 0, i;
    struct futex_entry *entry;
    DWORD tids[256];

    TRACE("%p\n", addr);

    if (!addr) return;

    spin_lock( &queue->lock );

    if (!queue->queue.next)
        list_init(&queue->queue);

    LIST_FOR_EACH_ENTRY( entry, &queue->queue, struct futex_entry, entry )
    {
        if (entry->addr == addr)
        {
            /* Try to buffer wakes, so that we don't make a system call while
             * holding a spinlock. */
            if (count < ARRAY_SIZE(tids))
                tids[count++] = entry->tid;
            else
                NtAlertThreadByThreadId( (HANDLE)(DWORD_PTR)entry->tid );
        }
    }

    spin_unlock( &queue->lock );

    for (i = 0; i < count; ++i)
        NtAlertThreadByThreadId( (HANDLE)(DWORD_PTR)tids[i] );
}

/***********************************************************************
 *           RtlWakeAddressSingle (NTDLL.@)
 */
void WINAPI RtlWakeAddressSingle( const void *addr )
{
    struct futex_queue *queue = get_futex_queue( addr );
    struct futex_entry *entry;
    DWORD tid = 0;

    TRACE("%p\n", addr);

    if (!addr) return;

    spin_lock( &queue->lock );

    if (!queue->queue.next)
        list_init(&queue->queue);

    LIST_FOR_EACH_ENTRY( entry, &queue->queue, struct futex_entry, entry )
    {
        if (entry->addr == addr)
        {
            /* Try to buffer wakes, so that we don't make a system call while
             * holding a spinlock. */
            tid = entry->tid;

            /* Remove this entry from the queue, so that a simultaneous call to
             * RtlWakeAddressSingle() will not also wake it—two simultaneous
             * calls must wake at least two waiters if they exist. */
            entry->addr = NULL;
            list_remove( &entry->entry );
            break;
        }
    }

    spin_unlock( &queue->lock );

    if (tid) NtAlertThreadByThreadId( (HANDLE)(DWORD_PTR)tid );
}
