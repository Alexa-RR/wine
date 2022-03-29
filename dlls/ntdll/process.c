/*
 * NT process handling
 *
 * Copyright 1996-1998 Marcus Meissner
 * Copyright 2018 Alexandre Julliard
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

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "wine/debug.h"
#include "windef.h"
#include "winternl.h"
#include "ntdll_misc.h"
#include "wine/exception.h"

WINE_DEFAULT_DEBUG_CHANNEL(process);


/******************************************************************************
 *  RtlGetCurrentPeb  [NTDLL.@]
 *
 */
PEB * WINAPI RtlGetCurrentPeb(void)
{
    return NtCurrentTeb()->Peb;
}


/******************************************************************
 *		RtlWow64EnableFsRedirection   (NTDLL.@)
 */
NTSTATUS WINAPI RtlWow64EnableFsRedirection( BOOLEAN enable )
{
<<<<<<< HEAD
    HANDLE ret = 0;
    SERVER_START_REQ( make_process_system )
    {
        if (!wine_server_call( req )) ret = wine_server_ptr_handle( reply->event );
    }
    SERVER_END_REQ;
    return ret;
}

/***********************************************************************
 *           __wine_create_default_token   (NTDLL.@)
 *
 * Creates a default limited or admin token.
 */
HANDLE CDECL __wine_create_default_token( BOOL admin )
{
    HANDLE ret = NULL;
    SERVER_START_REQ( create_token )
    {
        req->admin = admin;
        if (!wine_server_call( req ))
            ret = wine_server_ptr_handle( reply->token );
    }
    SERVER_END_REQ;
    return ret;
}

static UINT process_error_mode;

#define UNIMPLEMENTED_INFO_CLASS(c) \
    case c: \
        FIXME("(process=%p) Unimplemented information class: " #c "\n", ProcessHandle); \
        ret = STATUS_INVALID_INFO_CLASS; \
        break

ULONG_PTR get_system_affinity_mask(void)
{
    ULONG num_cpus = NtCurrentTeb()->Peb->NumberOfProcessors;
    if (num_cpus >= sizeof(ULONG_PTR) * 8) return ~(ULONG_PTR)0;
    return ((ULONG_PTR)1 << num_cpus) - 1;
}

#if defined(HAVE_MACH_MACH_H)

static void fill_VM_COUNTERS(VM_COUNTERS* pvmi)
{
#if defined(MACH_TASK_BASIC_INFO)
    struct mach_task_basic_info info;
    mach_msg_type_number_t infoCount = MACH_TASK_BASIC_INFO_COUNT;
    if(task_info(mach_task_self(), MACH_TASK_BASIC_INFO, (task_info_t)&info, &infoCount) == KERN_SUCCESS)
    {
        pvmi->VirtualSize = info.resident_size + info.virtual_size;
        pvmi->PagefileUsage = info.virtual_size;
        pvmi->WorkingSetSize = info.resident_size;
        pvmi->PeakWorkingSetSize = info.resident_size_max;
    }
#endif
}

#elif defined(linux)

static void fill_VM_COUNTERS(VM_COUNTERS* pvmi)
{
    FILE *f;
    char line[256];
    unsigned long value;

    f = fopen("/proc/self/status", "r");
    if (!f) return;

    while (fgets(line, sizeof(line), f))
    {
        if (sscanf(line, "VmPeak: %lu", &value))
            pvmi->PeakVirtualSize = (ULONG64)value * 1024;
        else if (sscanf(line, "VmSize: %lu", &value))
            pvmi->VirtualSize = (ULONG64)value * 1024;
        else if (sscanf(line, "VmHWM: %lu", &value))
            pvmi->PeakWorkingSetSize = (ULONG64)value * 1024;
        else if (sscanf(line, "VmRSS: %lu", &value))
            pvmi->WorkingSetSize = (ULONG64)value * 1024;
        else if (sscanf(line, "RssAnon: %lu", &value))
            pvmi->PagefileUsage += (ULONG64)value * 1024;
        else if (sscanf(line, "VmSwap: %lu", &value))
            pvmi->PagefileUsage += (ULONG64)value * 1024;
    }
    pvmi->PeakPagefileUsage = pvmi->PagefileUsage;

    fclose(f);
}

#else

static void fill_VM_COUNTERS(VM_COUNTERS* pvmi)
{
    read_process_memory_stats(getpid(), pvmi);
}

#endif

/******************************************************************************
*  NtQueryInformationProcess		[NTDLL.@]
*  ZwQueryInformationProcess		[NTDLL.@]
*
*/
NTSTATUS WINAPI NtQueryInformationProcess(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength)
{
    NTSTATUS ret = STATUS_SUCCESS;
    ULONG len = 0;

    TRACE("(%p,0x%08x,%p,0x%08x,%p)\n",
          ProcessHandle,ProcessInformationClass,
          ProcessInformation,ProcessInformationLength,
          ReturnLength);

    switch (ProcessInformationClass) 
    {
    UNIMPLEMENTED_INFO_CLASS(ProcessBasePriority);
    UNIMPLEMENTED_INFO_CLASS(ProcessRaisePriority);
    UNIMPLEMENTED_INFO_CLASS(ProcessExceptionPort);
    UNIMPLEMENTED_INFO_CLASS(ProcessAccessToken);
    UNIMPLEMENTED_INFO_CLASS(ProcessLdtInformation);
    UNIMPLEMENTED_INFO_CLASS(ProcessLdtSize);
    UNIMPLEMENTED_INFO_CLASS(ProcessIoPortHandlers);
    UNIMPLEMENTED_INFO_CLASS(ProcessPooledUsageAndLimits);
    UNIMPLEMENTED_INFO_CLASS(ProcessWorkingSetWatch);
    UNIMPLEMENTED_INFO_CLASS(ProcessUserModeIOPL);
    UNIMPLEMENTED_INFO_CLASS(ProcessEnableAlignmentFaultFixup);
    UNIMPLEMENTED_INFO_CLASS(ProcessWx86Information);
    UNIMPLEMENTED_INFO_CLASS(ProcessPriorityBoost);
    UNIMPLEMENTED_INFO_CLASS(ProcessDeviceMap);
    UNIMPLEMENTED_INFO_CLASS(ProcessSessionInformation);
    UNIMPLEMENTED_INFO_CLASS(ProcessForegroundInformation);
    UNIMPLEMENTED_INFO_CLASS(ProcessLUIDDeviceMapsEnabled);
    UNIMPLEMENTED_INFO_CLASS(ProcessBreakOnTermination);
    UNIMPLEMENTED_INFO_CLASS(ProcessHandleTracing);

    case ProcessBasicInformation:
        {
            PROCESS_BASIC_INFORMATION pbi;
            const ULONG_PTR affinity_mask = get_system_affinity_mask();

            if (ProcessInformationLength >= sizeof(PROCESS_BASIC_INFORMATION))
            {
                if (!ProcessInformation)
                    ret = STATUS_ACCESS_VIOLATION;
                else if (!ProcessHandle)
                    ret = STATUS_INVALID_HANDLE;
                else
                {
                    SERVER_START_REQ(get_process_info)
                    {
                        req->handle = wine_server_obj_handle( ProcessHandle );
                        if ((ret = wine_server_call( req )) == STATUS_SUCCESS)
                        {
                            pbi.ExitStatus = reply->exit_code;
                            pbi.PebBaseAddress = wine_server_get_ptr( reply->peb );
                            pbi.AffinityMask = reply->affinity & affinity_mask;
                            pbi.BasePriority = reply->priority;
                            pbi.UniqueProcessId = reply->pid;
                            pbi.InheritedFromUniqueProcessId = reply->ppid;
                        }
                    }
                    SERVER_END_REQ;

                    memcpy(ProcessInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION));

                    len = sizeof(PROCESS_BASIC_INFORMATION);
                }

                if (ProcessInformationLength > sizeof(PROCESS_BASIC_INFORMATION))
                    ret = STATUS_INFO_LENGTH_MISMATCH;
            }
            else
            {
                len = sizeof(PROCESS_BASIC_INFORMATION);
                ret = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        break;
    case ProcessQuotaLimits:
        {
            QUOTA_LIMITS pqli;

            if (ProcessInformationLength >= sizeof(QUOTA_LIMITS))
            {
                if (!ProcessInformation)
                    ret = STATUS_ACCESS_VIOLATION;
                else if (!ProcessHandle)
                    ret = STATUS_INVALID_HANDLE;
                else
                {
                    /* FIXME : real data */
                    memset(&pqli, 0, sizeof(QUOTA_LIMITS));

                    memcpy(ProcessInformation, &pqli, sizeof(QUOTA_LIMITS));

                    len = sizeof(QUOTA_LIMITS);
                }

                if (ProcessInformationLength > sizeof(QUOTA_LIMITS))
                    ret = STATUS_INFO_LENGTH_MISMATCH;
            }
            else
            {
                len = sizeof(QUOTA_LIMITS);
                ret = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        break;
    case ProcessIoCounters:
        {
            IO_COUNTERS pii;

            if (ProcessInformationLength >= sizeof(IO_COUNTERS))
            {
                if (!ProcessInformation)
                    ret = STATUS_ACCESS_VIOLATION;
                else if (!ProcessHandle)
                    ret = STATUS_INVALID_HANDLE;
                else
                {
                    /* FIXME : real data */
                    memset(&pii, 0 , sizeof(IO_COUNTERS));

                    memcpy(ProcessInformation, &pii, sizeof(IO_COUNTERS));

                    len = sizeof(IO_COUNTERS);
                }

                if (ProcessInformationLength > sizeof(IO_COUNTERS))
                    ret = STATUS_INFO_LENGTH_MISMATCH;
            }
            else
            {
                len = sizeof(IO_COUNTERS);
                ret = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        break;
    case ProcessVmCounters:
        {
            VM_COUNTERS pvmi;

            /* older Windows versions don't have the PrivatePageCount field */
            if (ProcessInformationLength >= FIELD_OFFSET(VM_COUNTERS,PrivatePageCount))
            {
                if (!ProcessInformation)
                    ret = STATUS_ACCESS_VIOLATION;
                else
                {
                    memset(&pvmi, 0 , sizeof(VM_COUNTERS));
                    if (ProcessHandle == GetCurrentProcess())
                        fill_VM_COUNTERS(&pvmi);
                    else
                    {
                        SERVER_START_REQ(get_process_vm_counters)
                        {
                            req->handle = wine_server_obj_handle( ProcessHandle );
                            if (!(ret = wine_server_call( req )))
                            {
                                pvmi.PeakVirtualSize = reply->peak_virtual_size;
                                pvmi.VirtualSize = reply->virtual_size;
                                pvmi.PeakWorkingSetSize = reply->peak_working_set_size;
                                pvmi.WorkingSetSize = reply->working_set_size;
                                pvmi.PagefileUsage = reply->pagefile_usage;
                                pvmi.PeakPagefileUsage = reply->peak_pagefile_usage;
                            }
                        }
                        SERVER_END_REQ;
                        if (ret) break;
                    }

                    len = ProcessInformationLength;
                    if (len != FIELD_OFFSET(VM_COUNTERS,PrivatePageCount)) len = sizeof(VM_COUNTERS);

                    memcpy(ProcessInformation, &pvmi, min(ProcessInformationLength,sizeof(VM_COUNTERS)));
                }

                if (ProcessInformationLength != FIELD_OFFSET(VM_COUNTERS,PrivatePageCount) &&
                    ProcessInformationLength != sizeof(VM_COUNTERS))
                    ret = STATUS_INFO_LENGTH_MISMATCH;
            }
            else
            {
                len = sizeof(pvmi);
                ret = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        break;
    case ProcessTimes:
        {
            KERNEL_USER_TIMES pti;

            if (ProcessInformationLength >= sizeof(KERNEL_USER_TIMES))
            {
                if (!ProcessInformation)
                    ret = STATUS_ACCESS_VIOLATION;
                else if (!ProcessHandle)
                    ret = STATUS_INVALID_HANDLE;
                else
                {
                    /* FIXME : User- and KernelTime have to be implemented */
                    memset(&pti, 0, sizeof(KERNEL_USER_TIMES));

                    SERVER_START_REQ(get_process_info)
                    {
                      req->handle = wine_server_obj_handle( ProcessHandle );
                      if ((ret = wine_server_call( req )) == STATUS_SUCCESS)
                      {
                          pti.CreateTime.QuadPart = reply->start_time;
                          pti.ExitTime.QuadPart = reply->end_time;
                      }
                    }
                    SERVER_END_REQ;

                    memcpy(ProcessInformation, &pti, sizeof(KERNEL_USER_TIMES));
                    len = sizeof(KERNEL_USER_TIMES);
                }

                if (ProcessInformationLength > sizeof(KERNEL_USER_TIMES))
                    ret = STATUS_INFO_LENGTH_MISMATCH;
            }
            else
            {
                len = sizeof(KERNEL_USER_TIMES);
                ret = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        break;
    case ProcessDebugPort:
        len = sizeof(DWORD_PTR);
        if (ProcessInformationLength == len)
        {
            if (!ProcessInformation)
                ret = STATUS_ACCESS_VIOLATION;
            else if (!ProcessHandle)
                ret = STATUS_INVALID_HANDLE;
            else
            {
                SERVER_START_REQ(get_process_info)
                {
                    req->handle = wine_server_obj_handle( ProcessHandle );
                    if ((ret = wine_server_call( req )) == STATUS_SUCCESS)
                    {
                        *(DWORD_PTR *)ProcessInformation = reply->debugger_present ? ~(DWORD_PTR)0 : 0;
                    }
                }
                SERVER_END_REQ;
            }
        }
        else
            ret = STATUS_INFO_LENGTH_MISMATCH;
        break;
    case ProcessDebugFlags:
        len = sizeof(DWORD);
        if (ProcessInformationLength == len)
        {
            if (!ProcessInformation)
                ret = STATUS_ACCESS_VIOLATION;
            else if (!ProcessHandle)
                ret = STATUS_INVALID_HANDLE;
            else
            {
                SERVER_START_REQ(get_process_info)
                {
                    req->handle = wine_server_obj_handle( ProcessHandle );
                    if ((ret = wine_server_call( req )) == STATUS_SUCCESS)
                    {
                        *(DWORD *)ProcessInformation = reply->debug_children;
                    }
                }
                SERVER_END_REQ;
            }
        }
        else
            ret = STATUS_INFO_LENGTH_MISMATCH;
        break;
    case ProcessDefaultHardErrorMode:
        len = sizeof(process_error_mode);
        if (ProcessInformationLength == len)
            memcpy(ProcessInformation, &process_error_mode, len);
        else
            ret = STATUS_INFO_LENGTH_MISMATCH;
        break;
    case ProcessDebugObjectHandle:
        /* "These are not the debuggers you are looking for." *
         * set it to 0 aka "no debugger" to satisfy copy protections */
        len = sizeof(HANDLE);
        if (ProcessInformationLength == len)
        {
            if (!ProcessInformation)
                ret = STATUS_ACCESS_VIOLATION;
            else if (!ProcessHandle)
                ret = STATUS_INVALID_HANDLE;
            else
            {
                memset(ProcessInformation, 0, ProcessInformationLength);
                ret = STATUS_PORT_NOT_SET;
            }
        }
        else
            ret = STATUS_INFO_LENGTH_MISMATCH;
        break;
    case ProcessHandleCount:
        if (ProcessInformationLength >= 4)
        {
            if (!ProcessInformation)
                ret = STATUS_ACCESS_VIOLATION;
            else if (!ProcessHandle)
                ret = STATUS_INVALID_HANDLE;
            else
            {
                memset(ProcessInformation, 0, 4);
                len = 4;
            }

            if (ProcessInformationLength > 4)
                ret = STATUS_INFO_LENGTH_MISMATCH;
        }
        else
        {
            len = 4;
            ret = STATUS_INFO_LENGTH_MISMATCH;
        }
        break;

    case ProcessAffinityMask:
        len = sizeof(ULONG_PTR);
        if (ProcessInformationLength == len)
        {
            const ULONG_PTR system_mask = get_system_affinity_mask();

            SERVER_START_REQ(get_process_info)
            {
                req->handle = wine_server_obj_handle( ProcessHandle );
                if (!(ret = wine_server_call( req )))
                    *(ULONG_PTR *)ProcessInformation = reply->affinity & system_mask;
            }
            SERVER_END_REQ;
        }
        else ret = STATUS_INFO_LENGTH_MISMATCH;
        break;

    case ProcessWow64Information:
        len = sizeof(ULONG_PTR);
        if (ProcessInformationLength != len) ret = STATUS_INFO_LENGTH_MISMATCH;
        else if (!ProcessInformation) ret = STATUS_ACCESS_VIOLATION;
        else if(!ProcessHandle) ret = STATUS_INVALID_HANDLE;
        else
        {
            ULONG_PTR val = 0;

            if (ProcessHandle == GetCurrentProcess()) val = is_wow64;
            else if (server_cpus & ((1 << CPU_x86_64) | (1 << CPU_ARM64)))
            {
                SERVER_START_REQ( get_process_info )
                {
                    req->handle = wine_server_obj_handle( ProcessHandle );
                    if (!(ret = wine_server_call( req )))
                        val = (reply->cpu != CPU_x86_64 && reply->cpu != CPU_ARM64);
                }
                SERVER_END_REQ;
            }
            *(ULONG_PTR *)ProcessInformation = val;
        }
        break;
    case ProcessImageFileName:
        /* FIXME: Should return a device path */
    case ProcessImageFileNameWin32:
        SERVER_START_REQ(get_dll_info)
        {
            UNICODE_STRING *image_file_name_str = ProcessInformation;

            req->handle = wine_server_obj_handle( ProcessHandle );
            req->base_address = 0; /* main module */
            wine_server_set_reply( req, image_file_name_str ? image_file_name_str + 1 : NULL,
                                   ProcessInformationLength > sizeof(UNICODE_STRING) ? ProcessInformationLength - sizeof(UNICODE_STRING) : 0 );
            ret = wine_server_call( req );
            if (ret == STATUS_BUFFER_TOO_SMALL) ret = STATUS_INFO_LENGTH_MISMATCH;

            len = sizeof(UNICODE_STRING) + reply->filename_len;
            if (ret == STATUS_SUCCESS)
            {
                image_file_name_str->MaximumLength = image_file_name_str->Length = reply->filename_len;
                image_file_name_str->Buffer = (PWSTR)(image_file_name_str + 1);
            }
        }
        SERVER_END_REQ;
        break;
    case ProcessExecuteFlags:
        len = sizeof(ULONG);
        if (ProcessInformationLength == len)
            *(ULONG *)ProcessInformation = execute_flags;
        else
            ret = STATUS_INFO_LENGTH_MISMATCH;
        break;
    case ProcessPriorityClass:
        len = sizeof(PROCESS_PRIORITY_CLASS);
        if (ProcessInformationLength == len)
        {
            if (!ProcessInformation)
                ret = STATUS_ACCESS_VIOLATION;
            else if (!ProcessHandle)
                ret = STATUS_INVALID_HANDLE;
            else
            {
                PROCESS_PRIORITY_CLASS *priority = ProcessInformation;

                SERVER_START_REQ(get_process_info)
                {
                    req->handle = wine_server_obj_handle( ProcessHandle );
                    if ((ret = wine_server_call( req )) == STATUS_SUCCESS)
                    {
                        priority->PriorityClass = reply->priority;
                        /* FIXME: Not yet supported by the wineserver */
                        priority->Foreground = FALSE;
                    }
                }
                SERVER_END_REQ;
            }
        }
        else
            ret = STATUS_INFO_LENGTH_MISMATCH;
        break;
    case ProcessCookie:
        FIXME("ProcessCookie (%p,%p,0x%08x,%p) stub\n",
              ProcessHandle,ProcessInformation,
              ProcessInformationLength,ReturnLength);

        if(ProcessHandle == NtCurrentProcess())
        {
            len = sizeof(ULONG);
            if (ProcessInformationLength == len)
                *(ULONG *)ProcessInformation = 0;
            else
                ret = STATUS_INFO_LENGTH_MISMATCH;
        }
        else
            ret = STATUS_INVALID_PARAMETER;
        break;
    default:
        FIXME("(%p,info_class=%d,%p,0x%08x,%p) Unknown information class\n",
              ProcessHandle,ProcessInformationClass,
              ProcessInformation,ProcessInformationLength,
              ReturnLength);
        ret = STATUS_INVALID_INFO_CLASS;
        break;
    }

    if (ReturnLength) *ReturnLength = len;
    
    return ret;
}

/******************************************************************************
 * NtSetInformationProcess [NTDLL.@]
 * ZwSetInformationProcess [NTDLL.@]
 */
NTSTATUS WINAPI NtSetInformationProcess(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	IN PVOID ProcessInformation,
	IN ULONG ProcessInformationLength)
{
    NTSTATUS ret = STATUS_SUCCESS;

    switch (ProcessInformationClass)
    {
    case ProcessDefaultHardErrorMode:
        if (ProcessInformationLength != sizeof(UINT)) return STATUS_INVALID_PARAMETER;
        process_error_mode = *(UINT *)ProcessInformation;
        break;
    case ProcessAffinityMask:
    {
        const ULONG_PTR system_mask = get_system_affinity_mask();

        if (ProcessInformationLength != sizeof(DWORD_PTR)) return STATUS_INVALID_PARAMETER;
        if (*(PDWORD_PTR)ProcessInformation & ~system_mask)
            return STATUS_INVALID_PARAMETER;
        if (!*(PDWORD_PTR)ProcessInformation)
            return STATUS_INVALID_PARAMETER;
        SERVER_START_REQ( set_process_info )
        {
            req->handle   = wine_server_obj_handle( ProcessHandle );
            req->affinity = *(PDWORD_PTR)ProcessInformation;
            req->mask     = SET_PROCESS_INFO_AFFINITY;
            ret = wine_server_call( req );
        }
        SERVER_END_REQ;
        break;
    }
    case ProcessPriorityClass:
        if (ProcessInformationLength != sizeof(PROCESS_PRIORITY_CLASS))
            return STATUS_INVALID_PARAMETER;
        else
        {
            PROCESS_PRIORITY_CLASS* ppc = ProcessInformation;

            SERVER_START_REQ( set_process_info )
            {
                req->handle   = wine_server_obj_handle( ProcessHandle );
                /* FIXME Foreground isn't used */
                req->priority = ppc->PriorityClass;
                req->mask     = SET_PROCESS_INFO_PRIORITY;
                ret = wine_server_call( req );
            }
            SERVER_END_REQ;
        }
        break;

    case ProcessExecuteFlags:
        if (is_win64 || ProcessInformationLength != sizeof(ULONG))
            return STATUS_INVALID_PARAMETER;
        else if (execute_flags & MEM_EXECUTE_OPTION_PERMANENT)
            return STATUS_ACCESS_DENIED;
        else
        {
            BOOL enable;
            switch (*(ULONG *)ProcessInformation & (MEM_EXECUTE_OPTION_ENABLE|MEM_EXECUTE_OPTION_DISABLE))
            {
            case MEM_EXECUTE_OPTION_ENABLE:
                enable = TRUE;
                break;
            case MEM_EXECUTE_OPTION_DISABLE:
                enable = FALSE;
                break;
            default:
                return STATUS_INVALID_PARAMETER;
            }
            execute_flags = *(ULONG *)ProcessInformation;
            VIRTUAL_SetForceExec( enable );
        }
        break;

    default:
        FIXME("(%p,0x%08x,%p,0x%08x) stub\n",
              ProcessHandle,ProcessInformationClass,ProcessInformation,
              ProcessInformationLength);
        ret = STATUS_NOT_IMPLEMENTED;
        break;
    }
    return ret;
}

/******************************************************************************
 * NtFlushInstructionCache [NTDLL.@]
 * ZwFlushInstructionCache [NTDLL.@]
 */
NTSTATUS WINAPI NtFlushInstructionCache( HANDLE handle, const void *addr, SIZE_T size )
{
#if defined(__x86_64__) || defined(__i386__)
    /* no-op */
#elif defined(HAVE___CLEAR_CACHE)
    if (handle == GetCurrentProcess())
    {
        __clear_cache( (char *)addr, (char *)addr + size );
    }
    else
    {
        static int once;
        if (!once++) FIXME( "%p %p %ld other process not supported\n", handle, addr, size );
    }
#else
    static int once;
    if (!once++) FIXME( "%p %p %ld\n", handle, addr, size );
#endif
=======
    if (!NtCurrentTeb64()) return STATUS_NOT_IMPLEMENTED;
    NtCurrentTeb64()->TlsSlots[WOW64_TLS_FILESYSREDIR] = !enable;
>>>>>>> master
    return STATUS_SUCCESS;
}


/******************************************************************
 *		RtlWow64EnableFsRedirectionEx   (NTDLL.@)
 */
NTSTATUS WINAPI RtlWow64EnableFsRedirectionEx( ULONG disable, ULONG *old_value )
{
    if (!NtCurrentTeb64()) return STATUS_NOT_IMPLEMENTED;

    __TRY
    {
        *old_value = NtCurrentTeb64()->TlsSlots[WOW64_TLS_FILESYSREDIR];
    }
    __EXCEPT_PAGE_FAULT
    {
        return STATUS_ACCESS_VIOLATION;
    }
    __ENDTRY

    NtCurrentTeb64()->TlsSlots[WOW64_TLS_FILESYSREDIR] = disable;
    return STATUS_SUCCESS;
}


/**********************************************************************
 *           RtlWow64GetCurrentMachine  (NTDLL.@)
 */
USHORT WINAPI RtlWow64GetCurrentMachine(void)
{
    USHORT current, native;

    RtlWow64GetProcessMachines( GetCurrentProcess(), &current, &native );
    return current ? current : native;
}


/**********************************************************************
 *           RtlWow64GetProcessMachines  (NTDLL.@)
 */
NTSTATUS WINAPI RtlWow64GetProcessMachines( HANDLE process, USHORT *current_ret, USHORT *native_ret )
{
<<<<<<< HEAD
    NTSTATUS ret;

    SERVER_START_REQ( suspend_process )
    {
        req->handle = wine_server_obj_handle( handle );
        ret = wine_server_call( req );
    }
    SERVER_END_REQ;

    return ret;
}


/***********************************************************************
 *           build_argv
 *
 * Build an argv array from a command-line.
 * 'reserved' is the number of args to reserve before the first one.
 */
static char **build_argv( const UNICODE_STRING *cmdlineW, int reserved )
{
    int argc;
    char **argv;
    char *arg, *s, *d, *cmdline;
    int in_quotes, bcount, len;

    len = cmdlineW->Length / sizeof(WCHAR);
    if (!(cmdline = RtlAllocateHeap( GetProcessHeap(), 0, len * 3 + 1 ))) return NULL;
    len = ntdll_wcstoumbs( cmdlineW->Buffer, len, cmdline, len * 3, FALSE );
    cmdline[len++] = 0;

    argc = reserved + 1;
    bcount = 0;
    in_quotes = 0;
    s = cmdline;
    while (1)
    {
        if (*s == '\0' || ((*s == ' ' || *s == '\t') && !in_quotes))
        {
            /* space */
            argc++;
            /* skip the remaining spaces */
            while (*s == ' ' || *s == '\t') s++;
            if (*s == '\0') break;
            bcount = 0;
            continue;
        }
        else if (*s == '\\') bcount++;  /* '\', count them */
        else if ((*s == '"') && ((bcount & 1) == 0))
        {
            if (in_quotes && s[1] == '"') s++;
            else
            {
                /* unescaped '"' */
                in_quotes = !in_quotes;
                bcount = 0;
            }
        }
        else bcount = 0; /* a regular character */
        s++;
    }
    if (!(argv = RtlAllocateHeap( GetProcessHeap(), 0, argc * sizeof(*argv) + len )))
    {
        RtlFreeHeap( GetProcessHeap(), 0, cmdline );
        return NULL;
    }

    arg = d = s = (char *)(argv + argc);
    memcpy( d, cmdline, len );
    bcount = 0;
    in_quotes = 0;
    argc = reserved;
    while (*s)
    {
        if ((*s == ' ' || *s == '\t') && !in_quotes)
        {
            /* Close the argument and copy it */
            *d = 0;
            argv[argc++] = arg;
            /* skip the remaining spaces */
            do
            {
                s++;
            } while (*s == ' ' || *s == '\t');

            /* Start with a new argument */
            arg = d = s;
            bcount = 0;
        }
        else if (*s == '\\')
        {
            *d++ = *s++;
            bcount++;
        }
        else if (*s == '"')
        {
            if ((bcount & 1) == 0)
            {
                /* Preceded by an even number of '\', this is half that
                 * number of '\', plus a '"' which we discard.
                 */
                d -= bcount/2;
                s++;
                if (in_quotes && *s == '"')
                {
                    *d++ = '"';
                    s++;
                }
                else in_quotes = !in_quotes;
            }
            else
            {
                /* Preceded by an odd number of '\', this is half that
                 * number of '\' followed by a '"'
                 */
                d = d - bcount / 2 - 1;
                *d++ = '"';
                s++;
            }
            bcount = 0;
        }
        else
        {
            /* a regular character */
            *d++ = *s++;
            bcount = 0;
        }
    }
    if (*arg)
    {
        *d = '\0';
        argv[argc++] = arg;
    }
    argv[argc] = NULL;

    RtlFreeHeap( GetProcessHeap(), 0, cmdline );
    return argv;
}


static inline const WCHAR *get_params_string( const RTL_USER_PROCESS_PARAMETERS *params,
                                              const UNICODE_STRING *str )
{
    if (params->Flags & PROCESS_PARAMS_FLAG_NORMALIZED) return str->Buffer;
    return (const WCHAR *)((const char *)params + (UINT_PTR)str->Buffer);
}

static inline DWORD append_string( void **ptr, const RTL_USER_PROCESS_PARAMETERS *params,
                                   const UNICODE_STRING *str )
{
    const WCHAR *buffer = get_params_string( params, str );
    memcpy( *ptr, buffer, str->Length );
    *ptr = (WCHAR *)*ptr + str->Length / sizeof(WCHAR);
    return str->Length;
}

/***********************************************************************
 *           create_startup_info
 */
static startup_info_t *create_startup_info( const RTL_USER_PROCESS_PARAMETERS *params, DWORD *info_size )
{
    startup_info_t *info;
    DWORD size;
    void *ptr;

    size = sizeof(*info);
    size += params->CurrentDirectory.DosPath.Length;
    size += params->DllPath.Length;
    size += params->ImagePathName.Length;
    size += params->CommandLine.Length;
    size += params->WindowTitle.Length;
    size += params->Desktop.Length;
    size += params->ShellInfo.Length;
    size += params->RuntimeInfo.Length;
    size = (size + 1) & ~1;
    *info_size = size;

    if (!(info = RtlAllocateHeap( GetProcessHeap(), HEAP_ZERO_MEMORY, size ))) return NULL;

    info->debug_flags   = params->DebugFlags;
    info->console_flags = params->ConsoleFlags;
    info->console       = wine_server_obj_handle( params->ConsoleHandle );
    info->hstdin        = wine_server_obj_handle( params->hStdInput );
    info->hstdout       = wine_server_obj_handle( params->hStdOutput );
    info->hstderr       = wine_server_obj_handle( params->hStdError );
    info->x             = params->dwX;
    info->y             = params->dwY;
    info->xsize         = params->dwXSize;
    info->ysize         = params->dwYSize;
    info->xchars        = params->dwXCountChars;
    info->ychars        = params->dwYCountChars;
    info->attribute     = params->dwFillAttribute;
    info->flags         = params->dwFlags;
    info->show          = params->wShowWindow;

    ptr = info + 1;
    info->curdir_len = append_string( &ptr, params, &params->CurrentDirectory.DosPath );
    info->dllpath_len = append_string( &ptr, params, &params->DllPath );
    info->imagepath_len = append_string( &ptr, params, &params->ImagePathName );
    info->cmdline_len = append_string( &ptr, params, &params->CommandLine );
    info->title_len = append_string( &ptr, params, &params->WindowTitle );
    info->desktop_len = append_string( &ptr, params, &params->Desktop );
    info->shellinfo_len = append_string( &ptr, params, &params->ShellInfo );
    info->runtime_len = append_string( &ptr, params, &params->RuntimeInfo );
    return info;
}


/***********************************************************************
 *           get_alternate_loader
 *
 * Get the name of the alternate (32 or 64 bit) Wine loader.
 */
static const char *get_alternate_loader( char **ret_env )
{
    char *env;
    const char *loader = NULL;
    const char *loader_env = getenv( "WINELOADER" );

    *ret_env = NULL;

    if (wine_get_build_dir()) loader = is_win64 ? "loader/wine" : "loader/wine64";

    if (loader_env)
    {
        int len = strlen( loader_env );
        if (!is_win64)
        {
            if (!(env = RtlAllocateHeap( GetProcessHeap(), 0, sizeof("WINELOADER=") + len + 2 ))) return NULL;
            strcpy( env, "WINELOADER=" );
            strcat( env, loader_env );
            strcat( env, "64" );
        }
        else
        {
            if (!(env = RtlAllocateHeap( GetProcessHeap(), 0, sizeof("WINELOADER=") + len ))) return NULL;
            strcpy( env, "WINELOADER=" );
            strcat( env, loader_env );
            len += sizeof("WINELOADER=") - 1;
            if (!strcmp( env + len - 2, "64" )) env[len - 2] = 0;
        }
        if (!loader)
        {
            if ((loader = strrchr( env, '/' ))) loader++;
            else loader = env;
        }
        *ret_env = env;
    }
    if (!loader) loader = is_win64 ? "wine" : "wine64";
    return loader;
}


#ifdef __APPLE__
/***********************************************************************
 *           terminate_main_thread
 *
 * On some versions of Mac OS X, the execve system call fails with
 * ENOTSUP if the process has multiple threads.  Wine is always multi-
 * threaded on Mac OS X because it specifically reserves the main thread
 * for use by the system frameworks (see apple_main_thread() in
 * libs/wine/loader.c).  So, when we need to exec without first forking,
 * we need to terminate the main thread first.  We do this by installing
 * a custom run loop source onto the main run loop and signaling it.
 * The source's "perform" callback is pthread_exit and it will be
 * executed on the main thread, terminating it.
 *
 * Returns TRUE if there's still hope the main thread has terminated or
 * will soon.  Return FALSE if we've given up.
 */
static BOOL terminate_main_thread(void)
{
    static int delayms;

    if (!delayms)
    {
        CFRunLoopSourceContext source_context = { 0 };
        CFRunLoopSourceRef source;

        source_context.perform = pthread_exit;
        if (!(source = CFRunLoopSourceCreate( NULL, 0, &source_context )))
            return FALSE;

        CFRunLoopAddSource( CFRunLoopGetMain(), source, kCFRunLoopCommonModes );
        CFRunLoopSourceSignal( source );
        CFRunLoopWakeUp( CFRunLoopGetMain() );
        CFRelease( source );

        delayms = 20;
    }

    if (delayms > 1000)
        return FALSE;

    usleep(delayms * 1000);
    delayms *= 2;

    return TRUE;
}
#endif


/***********************************************************************
 *           set_stdio_fd
 */
static void set_stdio_fd( int stdin_fd, int stdout_fd )
{
    int fd = -1;

    if (stdin_fd == -1 || stdout_fd == -1)
    {
        fd = open( "/dev/null", O_RDWR );
        if (stdin_fd == -1) stdin_fd = fd;
        if (stdout_fd == -1) stdout_fd = fd;
    }

    dup2( stdin_fd, 0 );
    dup2( stdout_fd, 1 );
    if (fd != -1) close( fd );
}


/***********************************************************************
 *           spawn_loader
 */
static NTSTATUS spawn_loader( const RTL_USER_PROCESS_PARAMETERS *params, int socketfd,
                              const char *unixdir, char *winedebug, const pe_image_info_t *pe_info )
{
    pid_t pid;
    int stdin_fd = -1, stdout_fd = -1;
    char *wineloader = NULL;
    const char *loader = NULL;
    char **argv;
    NTSTATUS status = STATUS_SUCCESS;

    argv = build_argv( &params->CommandLine, 1 );

    if (!is_win64 ^ !is_64bit_arch( pe_info->cpu ))
        loader = get_alternate_loader( &wineloader );

    wine_server_handle_to_fd( params->hStdInput, FILE_READ_DATA, &stdin_fd, NULL );
    wine_server_handle_to_fd( params->hStdOutput, FILE_WRITE_DATA, &stdout_fd, NULL );

    if (!(pid = fork()))  /* child */
    {
        if (!(pid = fork()))  /* grandchild */
        {
            char preloader_reserve[64], socket_env[64];
            ULONGLONG res_start = pe_info->base;
            ULONGLONG res_end   = pe_info->base + pe_info->map_size;

            if (params->ConsoleFlags ||
                params->ConsoleHandle == (HANDLE)1 /* KERNEL32_CONSOLE_ALLOC */ ||
                (params->hStdInput == INVALID_HANDLE_VALUE && params->hStdOutput == INVALID_HANDLE_VALUE))
            {
                setsid();
                set_stdio_fd( -1, -1 );  /* close stdin and stdout */
            }
            else set_stdio_fd( stdin_fd, stdout_fd );

            if (stdin_fd != -1) close( stdin_fd );
            if (stdout_fd != -1) close( stdout_fd );

            /* Reset signals that we previously set to SIG_IGN */
            signal( SIGPIPE, SIG_DFL );

            sprintf( socket_env, "WINESERVERSOCKET=%u", socketfd );
            sprintf( preloader_reserve, "WINEPRELOADRESERVE=%x%08x-%x%08x",
                     (ULONG)(res_start >> 32), (ULONG)res_start, (ULONG)(res_end >> 32), (ULONG)res_end );

            putenv( preloader_reserve );
            putenv( socket_env );
            if (winedebug) putenv( winedebug );
            if (wineloader) putenv( wineloader );
            if (unixdir) chdir( unixdir );

            if (argv) wine_exec_wine_binary( loader, argv, getenv("WINELOADER") );
            _exit(1);
        }

        _exit(pid == -1);
    }

    if (pid != -1)
    {
        /* reap child */
        pid_t wret;
        do {
            wret = waitpid(pid, NULL, 0);
        } while (wret < 0 && errno == EINTR);
    }
    else status = FILE_GetNtStatus();

    if (stdin_fd != -1) close( stdin_fd );
    if (stdout_fd != -1) close( stdout_fd );
    RtlFreeHeap( GetProcessHeap(), 0, wineloader );
    RtlFreeHeap( GetProcessHeap(), 0, argv );
    return status;
}


/***********************************************************************
 *           exec_loader
 */
static NTSTATUS exec_loader( const UNICODE_STRING *cmdline, int socketfd, const pe_image_info_t *pe_info )
{
    char *wineloader = NULL;
    const char *loader = NULL;
    char **argv;
    char preloader_reserve[64], socket_env[64];
    ULONGLONG res_start = pe_info->base;
    ULONGLONG res_end   = pe_info->base + pe_info->map_size;

    if (!(argv = build_argv( cmdline, 1 ))) return STATUS_NO_MEMORY;

    if (!is_win64 ^ !is_64bit_arch( pe_info->cpu ))
        loader = get_alternate_loader( &wineloader );

    /* Reset signals that we previously set to SIG_IGN */
    signal( SIGPIPE, SIG_DFL );

    sprintf( socket_env, "WINESERVERSOCKET=%u", socketfd );
    sprintf( preloader_reserve, "WINEPRELOADRESERVE=%x%08x-%x%08x",
             (ULONG)(res_start >> 32), (ULONG)res_start, (ULONG)(res_end >> 32), (ULONG)res_end );

    putenv( preloader_reserve );
    putenv( socket_env );
    if (wineloader) putenv( wineloader );

    do
    {
        wine_exec_wine_binary( loader, argv, getenv("WINELOADER") );
    }
#ifdef __APPLE__
    while (errno == ENOTSUP && terminate_main_thread());
#else
    while (0);
#endif

    RtlFreeHeap( GetProcessHeap(), 0, wineloader );
    RtlFreeHeap( GetProcessHeap(), 0, argv );
    return STATUS_INVALID_IMAGE_FORMAT;
}


/***************************************************************************
 *	is_builtin_path
 */
static BOOL is_builtin_path( UNICODE_STRING *path, BOOL *is_64bit )
{
    static const WCHAR systemW[] = {'\\','?','?','\\','c',':','\\','w','i','n','d','o','w','s','\\',
                                    's','y','s','t','e','m','3','2','\\'};
    static const WCHAR wow64W[] = {'\\','?','?','\\','c',':','\\','w','i','n','d','o','w','s','\\',
                                   's','y','s','w','o','w','6','4'};

    *is_64bit = is_win64;
    if (path->Length > sizeof(systemW) && !wcsnicmp( path->Buffer, systemW, ARRAY_SIZE(systemW) ))
    {
        if (is_wow64 && !ntdll_get_thread_data()->wow64_redir) *is_64bit = TRUE;
        return TRUE;
    }
    if ((is_win64 || is_wow64) && path->Length > sizeof(wow64W) &&
        !wcsnicmp( path->Buffer, wow64W, ARRAY_SIZE(wow64W) ))
    {
        *is_64bit = FALSE;
        return TRUE;
    }
    return FALSE;
}


/***********************************************************************
 *           get_so_file_info
 */
static BOOL get_so_file_info( HANDLE handle, pe_image_info_t *info )
{
    union
    {
        struct
        {
            unsigned char magic[4];
            unsigned char class;
            unsigned char data;
            unsigned char version;
            unsigned char ignored1[9];
            unsigned short type;
            unsigned short machine;
            unsigned char ignored2[8];
            unsigned int phoff;
            unsigned char ignored3[12];
            unsigned short phnum;
        } elf;
        struct
        {
            unsigned char magic[4];
            unsigned char class;
            unsigned char data;
            unsigned char ignored1[10];
            unsigned short type;
            unsigned short machine;
            unsigned char ignored2[12];
            unsigned __int64 phoff;
            unsigned char ignored3[16];
            unsigned short phnum;
        } elf64;
        struct
        {
            unsigned int magic;
            unsigned int cputype;
            unsigned int cpusubtype;
            unsigned int filetype;
        } macho;
        IMAGE_DOS_HEADER mz;
    } header;

    IO_STATUS_BLOCK io;
    LARGE_INTEGER offset;

    offset.QuadPart = 0;
    if (NtReadFile( handle, 0, NULL, NULL, &io, &header, sizeof(header), &offset, 0 )) return FALSE;
    if (io.Information != sizeof(header)) return FALSE;

    if (!memcmp( header.elf.magic, "\177ELF", 4 ))
    {
        unsigned int type;
        unsigned short phnum;

        if (header.elf.version != 1 /* EV_CURRENT */) return FALSE;
#ifdef WORDS_BIGENDIAN
        if (header.elf.data != 2 /* ELFDATA2MSB */) return FALSE;
#else
        if (header.elf.data != 1 /* ELFDATA2LSB */) return FALSE;
#endif
        switch (header.elf.machine)
        {
        case 3:   info->cpu = CPU_x86; break;
        case 20:  info->cpu = CPU_POWERPC; break;
        case 40:  info->cpu = CPU_ARM; break;
        case 62:  info->cpu = CPU_x86_64; break;
        case 183: info->cpu = CPU_ARM64; break;
        }
        if (header.elf.type != 3 /* ET_DYN */) return FALSE;
        if (header.elf.class == 2 /* ELFCLASS64 */)
        {
            offset.QuadPart = header.elf64.phoff;
            phnum = header.elf64.phnum;
        }
        else
        {
            offset.QuadPart = header.elf.phoff;
            phnum = header.elf.phnum;
        }
        while (phnum--)
        {
            if (NtReadFile( handle, 0, NULL, NULL, &io, &type, sizeof(type), &offset, 0 )) return FALSE;
            if (io.Information < sizeof(type)) return FALSE;
            if (type == 3 /* PT_INTERP */) return FALSE;
            offset.QuadPart += (header.elf.class == 2) ? 56 : 32;
        }
        return TRUE;
    }
    else if (header.macho.magic == 0xfeedface || header.macho.magic == 0xfeedfacf)
    {
        switch (header.macho.cputype)
        {
        case 0x00000007: info->cpu = CPU_x86; break;
        case 0x01000007: info->cpu = CPU_x86_64; break;
        case 0x0000000c: info->cpu = CPU_ARM; break;
        case 0x0100000c: info->cpu = CPU_ARM64; break;
        case 0x00000012: info->cpu = CPU_POWERPC; break;
        }
        if (header.macho.filetype == 8) return TRUE;
    }
    return FALSE;
}


/***********************************************************************
 *           get_pe_file_info
 */
static NTSTATUS get_pe_file_info( UNICODE_STRING *path, ULONG attributes,
                                  HANDLE *handle, pe_image_info_t *info )
{
    NTSTATUS status;
    HANDLE mapping;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK io;

    memset( info, 0, sizeof(*info) );
    InitializeObjectAttributes( &attr, path, attributes, 0, 0 );
    if ((status = __syscall_NtOpenFile( handle, GENERIC_READ, &attr, &io,
                              FILE_SHARE_READ | FILE_SHARE_DELETE, FILE_SYNCHRONOUS_IO_NONALERT )))
    {
        BOOL is_64bit;

        if (is_builtin_path( path, &is_64bit ))
        {
            TRACE( "assuming %u-bit builtin for %s\n", is_64bit ? 64 : 32, debugstr_us(path));
            /* assume current arch */
#if defined(__i386__) || defined(__x86_64__)
            info->cpu = is_64bit ? CPU_x86_64 : CPU_x86;
#elif defined(__powerpc__)
            info->cpu = CPU_POWERPC;
#elif defined(__arm__)
            info->cpu = CPU_ARM;
#elif defined(__aarch64__)
            info->cpu = CPU_ARM64;
#endif
            *handle = 0;
            return STATUS_SUCCESS;
        }
        return status;
    }

    if (!(status = NtCreateSection( &mapping, STANDARD_RIGHTS_REQUIRED | SECTION_QUERY |
                                    SECTION_MAP_READ | SECTION_MAP_EXECUTE,
                                    NULL, NULL, PAGE_EXECUTE_READ, SEC_IMAGE, *handle )))
    {
        SERVER_START_REQ( get_mapping_info )
        {
            req->handle = wine_server_obj_handle( mapping );
            req->access = SECTION_QUERY;
            wine_server_set_reply( req, info, sizeof(*info) );
            status = wine_server_call( req );
        }
        SERVER_END_REQ;
        NtClose( mapping );
    }
    else if (status == STATUS_INVALID_IMAGE_NOT_MZ)
    {
        if (get_so_file_info( *handle, info )) return STATUS_SUCCESS;
    }
    return status;
}


/***********************************************************************
 *           get_env_size
 */
static ULONG get_env_size( const RTL_USER_PROCESS_PARAMETERS *params, char **winedebug )
{
    WCHAR *ptr = params->Environment;

    while (*ptr)
    {
        static const WCHAR WINEDEBUG[] = {'W','I','N','E','D','E','B','U','G','=',0};
        if (!*winedebug && !wcsncmp( ptr, WINEDEBUG, ARRAY_SIZE( WINEDEBUG ) - 1 ))
        {
            DWORD len = wcslen(ptr) * 3 + 1;
            if ((*winedebug = RtlAllocateHeap( GetProcessHeap(), 0, len )))
                ntdll_wcstoumbs( ptr, wcslen(ptr) + 1, *winedebug, len, FALSE );
        }
        ptr += wcslen(ptr) + 1;
    }
    ptr++;
    return (ptr - params->Environment) * sizeof(WCHAR);
}


/***********************************************************************
 *           get_unix_curdir
 */
static char *get_unix_curdir( const RTL_USER_PROCESS_PARAMETERS *params )
{
    UNICODE_STRING nt_name;
    ANSI_STRING unix_name;
=======
    ULONG i, machines[8];
    USHORT current = 0, native = 0;
>>>>>>> master
    NTSTATUS status;

    status = NtQuerySystemInformationEx( SystemSupportedProcessorArchitectures, &process, sizeof(process),
                                         machines, sizeof(machines), NULL );
    if (status) return status;
    for (i = 0; machines[i]; i++)
    {
        USHORT flags = HIWORD(machines[i]);
        USHORT machine = LOWORD(machines[i]);
        if (flags & 4 /* native machine */) native = machine;
        else if (flags & 8 /* current machine */) current = machine;
    }
    if (current_ret) *current_ret = current;
    if (native_ret) *native_ret = native;
    return status;
}


/**********************************************************************
 *           RtlWow64IsWowGuestMachineSupported  (NTDLL.@)
 */
NTSTATUS WINAPI RtlWow64IsWowGuestMachineSupported( USHORT machine, BOOLEAN *supported )
{
    ULONG i, machines[8];
    HANDLE process = 0;
    NTSTATUS status;

    status = NtQuerySystemInformationEx( SystemSupportedProcessorArchitectures, &process, sizeof(process),
                                         machines, sizeof(machines), NULL );
    if (status) return status;
    *supported = FALSE;
    for (i = 0; machines[i]; i++)
    {
        if (HIWORD(machines[i]) & 4 /* native machine */) continue;
        if (machine == LOWORD(machines[i])) *supported = TRUE;
    }
    return status;
}


#ifdef _WIN64

/**********************************************************************
 *           RtlWow64GetCpuAreaInfo  (NTDLL.@)
 */
NTSTATUS WINAPI RtlWow64GetCpuAreaInfo( WOW64_CPURESERVED *cpu, ULONG reserved, WOW64_CPU_AREA_INFO *info )
{
    static const struct { ULONG machine, align, size, offset, flag; } data[] =
    {
#define ENTRY(machine,type,flag) { machine, TYPE_ALIGNMENT(type), sizeof(type), offsetof(type,ContextFlags), flag },
        ENTRY( IMAGE_FILE_MACHINE_I386, I386_CONTEXT, CONTEXT_i386 )
        ENTRY( IMAGE_FILE_MACHINE_AMD64, AMD64_CONTEXT, CONTEXT_AMD64 )
        ENTRY( IMAGE_FILE_MACHINE_ARMNT, ARM_CONTEXT, CONTEXT_ARM )
        ENTRY( IMAGE_FILE_MACHINE_ARM64, ARM64_NT_CONTEXT, CONTEXT_ARM64 )
#undef ENTRY
    };
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(data); i++)
    {
#define ALIGN(ptr,align) ((void *)(((ULONG_PTR)(ptr) + (align) - 1) & ~((align) - 1)))
        if (data[i].machine != cpu->Machine) continue;
        info->Context = ALIGN( cpu + 1, data[i].align );
        info->ContextEx = ALIGN( (char *)info->Context + data[i].size, sizeof(void *) );
        info->ContextFlagsLocation = (char *)info->Context + data[i].offset;
        info->ContextFlag = data[i].flag;
        info->CpuReserved = cpu;
        info->Machine = data[i].machine;
        return STATUS_SUCCESS;
#undef ALIGN
    }
    return STATUS_INVALID_PARAMETER;
}


/**********************************************************************
 *           RtlWow64GetCurrentCpuArea  (NTDLL.@)
 */
NTSTATUS WINAPI RtlWow64GetCurrentCpuArea( USHORT *machine, void **context, void **context_ex )
{
    WOW64_CPU_AREA_INFO info;
    NTSTATUS status;

    if (!(status = RtlWow64GetCpuAreaInfo( NtCurrentTeb()->TlsSlots[WOW64_TLS_CPURESERVED], 0, &info )))
    {
        if (machine) *machine = info.Machine;
        if (context) *context = info.Context;
        if (context_ex) *context_ex = *(void **)info.ContextEx;
    }
    return status;
}


/******************************************************************************
 *              RtlWow64GetThreadContext  (NTDLL.@)
 */
NTSTATUS WINAPI RtlWow64GetThreadContext( HANDLE handle, WOW64_CONTEXT *context )
{
    return NtQueryInformationThread( handle, ThreadWow64Context, context, sizeof(*context), NULL );
}


/******************************************************************************
 *              RtlWow64SetThreadContext  (NTDLL.@)
 */
NTSTATUS WINAPI RtlWow64SetThreadContext( HANDLE handle, const WOW64_CONTEXT *context )
{
    return NtSetInformationThread( handle, ThreadWow64Context, context, sizeof(*context) );
}

/******************************************************************************
 *              RtlWow64GetThreadSelectorEntry  (NTDLL.@)
 */
NTSTATUS WINAPI RtlWow64GetThreadSelectorEntry( HANDLE handle, THREAD_DESCRIPTOR_INFORMATION *info,
                                                ULONG size, ULONG *retlen )
{
    DWORD sel;
    WOW64_CONTEXT context = { WOW64_CONTEXT_CONTROL | WOW64_CONTEXT_SEGMENTS };
    LDT_ENTRY entry = { 0 };

    if (size != sizeof(*info)) return STATUS_INFO_LENGTH_MISMATCH;
    if (RtlWow64GetThreadContext( handle, &context ))
    {
        /* hardcoded values */
        context.SegCs = 0x23;
#ifdef __x86_64__
        __asm__( "movw %%fs,%0" : "=m" (context.SegFs) );
        __asm__( "movw %%ss,%0" : "=m" (context.SegSs) );
#else
        context.SegSs = 0x2b;
        context.SegFs = 0x53;
#endif
    }

    sel = info->Selector | 3;
    if (sel == 0x03) goto done; /* null selector */

    /* set common data */
    entry.HighWord.Bits.Dpl = 3;
    entry.HighWord.Bits.Pres = 1;
    entry.HighWord.Bits.Default_Big = 1;
    if (sel == context.SegCs)  /* code selector */
    {
        entry.LimitLow = 0xffff;
        entry.HighWord.Bits.LimitHi = 0xf;
        entry.HighWord.Bits.Type = 0x1b;  /* code */
        entry.HighWord.Bits.Granularity = 1;
    }
    else if (sel == context.SegSs)  /* data selector */
    {
        entry.LimitLow = 0xffff;
        entry.HighWord.Bits.LimitHi = 0xf;
        entry.HighWord.Bits.Type = 0x13;  /* data */
        entry.HighWord.Bits.Granularity = 1;
    }
    else if (sel == context.SegFs)  /* TEB selector */
    {
        THREAD_BASIC_INFORMATION tbi;

        entry.LimitLow = 0xfff;
        entry.HighWord.Bits.Type = 0x13;  /* data */
        if (!NtQueryInformationThread( handle, ThreadBasicInformation, &tbi, sizeof(tbi), NULL ))
        {
            ULONG addr = (ULONG_PTR)tbi.TebBaseAddress + 0x2000;  /* 32-bit teb offset */
            entry.BaseLow = addr;
            entry.HighWord.Bytes.BaseMid = addr >> 16;
            entry.HighWord.Bytes.BaseHi  = addr >> 24;
        }
    }
    else return STATUS_UNSUCCESSFUL;

done:
    info->Entry = entry;
    if (retlen) *retlen = sizeof(entry);
    return STATUS_SUCCESS;
}

#endif

/**********************************************************************
 *           RtlCreateUserProcess  (NTDLL.@)
 */
NTSTATUS WINAPI RtlCreateUserProcess( UNICODE_STRING *path, ULONG attributes,
                                      RTL_USER_PROCESS_PARAMETERS *params,
                                      SECURITY_DESCRIPTOR *process_descr,
                                      SECURITY_DESCRIPTOR *thread_descr,
                                      HANDLE parent, BOOLEAN inherit, HANDLE debug, HANDLE token,
                                      RTL_USER_PROCESS_INFORMATION *info )
{
    OBJECT_ATTRIBUTES process_attr, thread_attr;
    PS_CREATE_INFO create_info;
    ULONG_PTR buffer[offsetof( PS_ATTRIBUTE_LIST, Attributes[6] ) / sizeof(ULONG_PTR)];
    PS_ATTRIBUTE_LIST *attr = (PS_ATTRIBUTE_LIST *)buffer;
    UINT pos = 0;

    RtlNormalizeProcessParams( params );

    attr->Attributes[pos].Attribute    = PS_ATTRIBUTE_IMAGE_NAME;
    attr->Attributes[pos].Size         = path->Length;
    attr->Attributes[pos].ValuePtr     = path->Buffer;
    attr->Attributes[pos].ReturnLength = NULL;
    pos++;
    attr->Attributes[pos].Attribute    = PS_ATTRIBUTE_CLIENT_ID;
    attr->Attributes[pos].Size         = sizeof(info->ClientId);
    attr->Attributes[pos].ValuePtr     = &info->ClientId;
    attr->Attributes[pos].ReturnLength = NULL;
    pos++;
    attr->Attributes[pos].Attribute    = PS_ATTRIBUTE_IMAGE_INFO;
    attr->Attributes[pos].Size         = sizeof(info->ImageInformation);
    attr->Attributes[pos].ValuePtr     = &info->ImageInformation;
    attr->Attributes[pos].ReturnLength = NULL;
    pos++;
    if (parent)
    {
        attr->Attributes[pos].Attribute    = PS_ATTRIBUTE_PARENT_PROCESS;
        attr->Attributes[pos].Size         = sizeof(parent);
        attr->Attributes[pos].ValuePtr     = parent;
        attr->Attributes[pos].ReturnLength = NULL;
        pos++;
    }
    if (debug)
    {
        attr->Attributes[pos].Attribute    = PS_ATTRIBUTE_DEBUG_PORT;
        attr->Attributes[pos].Size         = sizeof(debug);
        attr->Attributes[pos].ValuePtr     = debug;
        attr->Attributes[pos].ReturnLength = NULL;
        pos++;
    }
    if (token)
    {
        attr->Attributes[pos].Attribute    = PS_ATTRIBUTE_TOKEN;
        attr->Attributes[pos].Size         = sizeof(token);
        attr->Attributes[pos].ValuePtr     = token;
        attr->Attributes[pos].ReturnLength = NULL;
        pos++;
    }
    attr->TotalLength = offsetof( PS_ATTRIBUTE_LIST, Attributes[pos] );

    InitializeObjectAttributes( &process_attr, NULL, 0, NULL, process_descr );
    InitializeObjectAttributes( &thread_attr, NULL, 0, NULL, thread_descr );

    return NtCreateUserProcess( &info->Process, &info->Thread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS,
                                &process_attr, &thread_attr,
                                inherit ? PROCESS_CREATE_FLAGS_INHERIT_HANDLES : 0,
                                THREAD_CREATE_FLAGS_CREATE_SUSPENDED, params,
                                &create_info, attr );
}

<<<<<<< HEAD
    SERVER_START_REQ( new_process )
    {
        req->parent_process = wine_server_obj_handle(parent);
        req->inherit_all    = inherit;
        req->create_flags   = params->DebugFlags; /* hack: creation flags stored in DebugFlags for now */
        req->socket_fd      = socketfd[1];
        req->exe_file       = wine_server_obj_handle( file_handle );
        req->access         = PROCESS_ALL_ACCESS;
        req->cpu            = pe_info.cpu;
        req->info_size      = startup_info_size;
        req->token          = wine_server_obj_handle( token );
        wine_server_add_data( req, objattr, attr_len );
        wine_server_add_data( req, startup_info, startup_info_size );
        wine_server_add_data( req, params->Environment, env_size );
        if (!(status = wine_server_call( req )))
        {
            process_id = reply->pid;
            process_handle = wine_server_ptr_handle( reply->handle );
        }
        process_info = wine_server_ptr_handle( reply->info );
    }
    SERVER_END_REQ;
    RtlFreeHeap( GetProcessHeap(), 0, objattr );
=======
/***********************************************************************
 *      DbgUiGetThreadDebugObject (NTDLL.@)
 */
HANDLE WINAPI DbgUiGetThreadDebugObject(void)
{
    return NtCurrentTeb()->DbgSsReserved[1];
}
>>>>>>> master

/***********************************************************************
 *      DbgUiSetThreadDebugObject (NTDLL.@)
 */
void WINAPI DbgUiSetThreadDebugObject( HANDLE handle )
{
    NtCurrentTeb()->DbgSsReserved[1] = handle;
}

/***********************************************************************
 *      DbgUiConnectToDbg (NTDLL.@)
 */
NTSTATUS WINAPI DbgUiConnectToDbg(void)
{
    HANDLE handle;
    NTSTATUS status;
    OBJECT_ATTRIBUTES attr = { sizeof(attr) };

    if (DbgUiGetThreadDebugObject()) return STATUS_SUCCESS;  /* already connected */

    status = NtCreateDebugObject( &handle, DEBUG_ALL_ACCESS, &attr, DEBUG_KILL_ON_CLOSE );
    if (!status) DbgUiSetThreadDebugObject( handle );
    return status;
}

/***********************************************************************
 *      DbgUiDebugActiveProcess (NTDLL.@)
 */
NTSTATUS WINAPI DbgUiDebugActiveProcess( HANDLE process )
{
    NTSTATUS status;

    if ((status = NtDebugActiveProcess( process, DbgUiGetThreadDebugObject() ))) return status;
    if ((status = DbgUiIssueRemoteBreakin( process ))) DbgUiStopDebugging( process );
    return status;
}

/***********************************************************************
 *      DbgUiStopDebugging (NTDLL.@)
 */
NTSTATUS WINAPI DbgUiStopDebugging( HANDLE process )
{
    return NtRemoveProcessDebug( process, DbgUiGetThreadDebugObject() );
}

/***********************************************************************
 *      DbgUiContinue (NTDLL.@)
 */
NTSTATUS WINAPI DbgUiContinue( CLIENT_ID *client, NTSTATUS status )
{
    return NtDebugContinue( DbgUiGetThreadDebugObject(), client, status );
}

/***********************************************************************
 *      DbgUiWaitStateChange (NTDLL.@)
 */
NTSTATUS WINAPI DbgUiWaitStateChange( DBGUI_WAIT_STATE_CHANGE *state, LARGE_INTEGER *timeout )
{
    return NtWaitForDebugEvent( DbgUiGetThreadDebugObject(), TRUE, timeout, state );
}

/* helper for DbgUiConvertStateChangeStructure */
static inline void *get_thread_teb( HANDLE thread )
{
    THREAD_BASIC_INFORMATION info;

    if (NtQueryInformationThread( thread, ThreadBasicInformation, &info, sizeof(info), NULL )) return NULL;
    return info.TebBaseAddress;
}

/***********************************************************************
 *      DbgUiConvertStateChangeStructure (NTDLL.@)
 */
NTSTATUS WINAPI DbgUiConvertStateChangeStructure( DBGUI_WAIT_STATE_CHANGE *state, DEBUG_EVENT *event )
{
    event->dwProcessId = HandleToULong( state->AppClientId.UniqueProcess );
    event->dwThreadId  = HandleToULong( state->AppClientId.UniqueThread );
    switch (state->NewState)
    {
    case DbgCreateThreadStateChange:
    {
        DBGUI_CREATE_THREAD *info = &state->StateInfo.CreateThread;
        event->dwDebugEventCode = CREATE_THREAD_DEBUG_EVENT;
        event->u.CreateThread.hThread           = info->HandleToThread;
        event->u.CreateThread.lpThreadLocalBase = get_thread_teb( info->HandleToThread );
        event->u.CreateThread.lpStartAddress    = info->NewThread.StartAddress;
        break;
    }
    case DbgCreateProcessStateChange:
    {
        DBGUI_CREATE_PROCESS *info = &state->StateInfo.CreateProcessInfo;
        event->dwDebugEventCode = CREATE_PROCESS_DEBUG_EVENT;
        event->u.CreateProcessInfo.hFile                 = info->NewProcess.FileHandle;
        event->u.CreateProcessInfo.hProcess              = info->HandleToProcess;
        event->u.CreateProcessInfo.hThread               = info->HandleToThread;
        event->u.CreateProcessInfo.lpBaseOfImage         = info->NewProcess.BaseOfImage;
        event->u.CreateProcessInfo.dwDebugInfoFileOffset = info->NewProcess.DebugInfoFileOffset;
        event->u.CreateProcessInfo.nDebugInfoSize        = info->NewProcess.DebugInfoSize;
        event->u.CreateProcessInfo.lpThreadLocalBase     = get_thread_teb( info->HandleToThread );
        event->u.CreateProcessInfo.lpStartAddress        = info->NewProcess.InitialThread.StartAddress;
        event->u.CreateProcessInfo.lpImageName           = NULL;
        event->u.CreateProcessInfo.fUnicode              = TRUE;
        break;
    }
    case DbgExitThreadStateChange:
    {
        DBGKM_EXIT_THREAD *info = &state->StateInfo.ExitThread;
        event->dwDebugEventCode = EXIT_THREAD_DEBUG_EVENT;
        event->u.ExitThread.dwExitCode = info->ExitStatus;
        break;
    }
    case DbgExitProcessStateChange:
    {
        DBGKM_EXIT_PROCESS *info = &state->StateInfo.ExitProcess;
        event->dwDebugEventCode = EXIT_PROCESS_DEBUG_EVENT;
        event->u.ExitProcess.dwExitCode = info->ExitStatus;
        break;
    }
    case DbgExceptionStateChange:
    case DbgBreakpointStateChange:
    case DbgSingleStepStateChange:
    {
        DBGKM_EXCEPTION *info = &state->StateInfo.Exception;
        DWORD code = info->ExceptionRecord.ExceptionCode;
        if (code == DBG_PRINTEXCEPTION_C && info->ExceptionRecord.NumberParameters >= 2)
        {
            event->dwDebugEventCode = OUTPUT_DEBUG_STRING_EVENT;
            event->u.DebugString.lpDebugStringData  = (void *)info->ExceptionRecord.ExceptionInformation[1];
            event->u.DebugString.fUnicode           = FALSE;
            event->u.DebugString.nDebugStringLength = info->ExceptionRecord.ExceptionInformation[0];
        }
        else if (code == DBG_RIPEXCEPTION && info->ExceptionRecord.NumberParameters >= 2)
        {
            event->dwDebugEventCode = RIP_EVENT;
            event->u.RipInfo.dwError = info->ExceptionRecord.ExceptionInformation[0];
            event->u.RipInfo.dwType  = info->ExceptionRecord.ExceptionInformation[1];
        }
        else
        {
            event->dwDebugEventCode = EXCEPTION_DEBUG_EVENT;
            event->u.Exception.ExceptionRecord = info->ExceptionRecord;
            event->u.Exception.dwFirstChance   = info->FirstChance;
        }
        break;
    }
    case DbgLoadDllStateChange:
    {
        DBGKM_LOAD_DLL *info = &state->StateInfo.LoadDll;
        event->dwDebugEventCode = LOAD_DLL_DEBUG_EVENT;
        event->u.LoadDll.hFile                 = info->FileHandle;
        event->u.LoadDll.lpBaseOfDll           = info->BaseOfDll;
        event->u.LoadDll.dwDebugInfoFileOffset = info->DebugInfoFileOffset;
        event->u.LoadDll.nDebugInfoSize        = info->DebugInfoSize;
        event->u.LoadDll.lpImageName           = info->NamePointer;
        event->u.LoadDll.fUnicode              = TRUE;
        break;
    }
    case DbgUnloadDllStateChange:
    {
        DBGKM_UNLOAD_DLL *info = &state->StateInfo.UnloadDll;
        event->dwDebugEventCode = UNLOAD_DLL_DEBUG_EVENT;
        event->u.UnloadDll.lpBaseOfDll = info->BaseAddress;
        break;
    }
    default:
        return STATUS_UNSUCCESSFUL;
    }
    return STATUS_SUCCESS;
}

/***********************************************************************
 *      DbgUiRemoteBreakin (NTDLL.@)
 */
void WINAPI DbgUiRemoteBreakin( void *arg )
{
    TRACE( "\n" );
    if (NtCurrentTeb()->Peb->BeingDebugged)
    {
        __TRY
        {
            DbgBreakPoint();
        }
        __EXCEPT_ALL
        {
            /* do nothing */
        }
        __ENDTRY
    }
    RtlExitUserThread( STATUS_SUCCESS );
}

/***********************************************************************
 *      DbgUiIssueRemoteBreakin (NTDLL.@)
 */
NTSTATUS WINAPI DbgUiIssueRemoteBreakin( HANDLE process )
{
    HANDLE handle;
    NTSTATUS status;
    OBJECT_ATTRIBUTES attr = { sizeof(attr) };

    status = NtCreateThreadEx( &handle, THREAD_ALL_ACCESS, &attr, process,
                               DbgUiRemoteBreakin, NULL, 0, 0, 0, 0, NULL );
#ifdef _WIN64
    /* FIXME: hack for debugging 32-bit wow64 process without a 64-bit ntdll */
    if (status == STATUS_INVALID_PARAMETER)
    {
        ULONG_PTR wow;
        if (!NtQueryInformationProcess( process, ProcessWow64Information, &wow, sizeof(wow), NULL ) && wow)
            status = NtCreateThreadEx( &handle, THREAD_ALL_ACCESS, &attr, process,
                                       (void *)0x7ffe1000, NULL, 0, 0, 0, 0, NULL );
    }
#endif
    if (!status) NtClose( handle );
    return status;
}
