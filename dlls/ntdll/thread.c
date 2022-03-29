/*
 * NT threads support
 *
 * Copyright 1996, 2003 Alexandre Julliard
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

#include <assert.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <sys/types.h>

#define NONAMELESSUNION
#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "winternl.h"
#include "wine/debug.h"
#include "winbase.h"
#include "ntdll_misc.h"
#include "ddk/wdm.h"
#include "wine/exception.h"

WINE_DEFAULT_DEBUG_CHANNEL(thread);
WINE_DECLARE_DEBUG_CHANNEL(relay);
WINE_DECLARE_DEBUG_CHANNEL(pid);
WINE_DECLARE_DEBUG_CHANNEL(timestamp);

struct _KUSER_SHARED_DATA *user_shared_data = (void *)0x7ffe0000;

<<<<<<< HEAD
static struct _KUSER_SHARED_DATA user_shared_data_internal;
struct _KUSER_SHARED_DATA *user_shared_data_external;
struct _KUSER_SHARED_DATA *user_shared_data = &user_shared_data_internal;
static const WCHAR default_windirW[] = {'C',':','\\','w','i','n','d','o','w','s',0};

extern void DECLSPEC_NORETURN __wine_syscall_dispatcher( void );

void (WINAPI *kernel32_start_process)(LPTHREAD_START_ROUTINE,void*) = NULL;

/* info passed to a starting thread */
struct startup_info
=======
struct debug_info
>>>>>>> github-desktop-wine-mirror/master
{
    unsigned int str_pos;       /* current position in strings buffer */
    unsigned int out_pos;       /* current position in output buffer */
    char         strings[1020]; /* buffer for temporary strings */
    char         output[1020];  /* current output line */
};

<<<<<<< HEAD
static PEB *peb;
static PEB_LDR_DATA ldr;
static RTL_BITMAP tls_bitmap;
static RTL_BITMAP tls_expansion_bitmap;
static RTL_BITMAP fls_bitmap;
static API_SET_NAMESPACE_ARRAY apiset_map;
static int nb_threads = 1;
=======
C_ASSERT( sizeof(struct debug_info) == 0x800 );
>>>>>>> github-desktop-wine-mirror/master

static int nb_debug_options;
static struct __wine_debug_channel *debug_options;

static inline struct debug_info *get_info(void)
{
#ifdef _WIN64
    return (struct debug_info *)((TEB32 *)((char *)NtCurrentTeb() + 0x2000) + 1);
#else
    return (struct debug_info *)(NtCurrentTeb() + 1);
#endif
}

static void init_options(void)
{
    unsigned int offset = page_size * (sizeof(void *) / 4);

    debug_options = (struct __wine_debug_channel *)((char *)NtCurrentTeb()->Peb + offset);
    while (debug_options[nb_debug_options].name[0]) nb_debug_options++;
}

/* add a string to the output buffer */
static int append_output( struct debug_info *info, const char *str, size_t len )
{
    if (len >= sizeof(info->output) - info->out_pos)
    {
        __wine_dbg_write( info->output, info->out_pos );
        info->out_pos = 0;
        ERR_(thread)( "debug buffer overflow:\n" );
        __wine_dbg_write( str, len );
        RtlRaiseStatus( STATUS_BUFFER_OVERFLOW );
    }
    memcpy( info->output + info->out_pos, str, len );
    info->out_pos += len;
    return len;
}

/***********************************************************************
 *		__wine_dbg_get_channel_flags  (NTDLL.@)
 *
 * Get the flags to use for a given channel, possibly setting them too in case of lazy init
 */
unsigned char __cdecl __wine_dbg_get_channel_flags( struct __wine_debug_channel *channel )
{
    int min, max, pos, res;
    unsigned char default_flags;

    if (!debug_options) init_options();

    min = 0;
    max = nb_debug_options - 1;
    while (min <= max)
    {
        pos = (min + max) / 2;
        res = strcmp( channel->name, debug_options[pos].name );
        if (!res) return debug_options[pos].flags;
        if (res < 0) max = pos - 1;
        else min = pos + 1;
    }
    /* no option for this channel */
    default_flags = debug_options[nb_debug_options].flags;
    if (channel->flags & (1 << __WINE_DBCL_INIT)) channel->flags = default_flags;
    return default_flags;
}

/***********************************************************************
 *		__wine_dbg_strdup  (NTDLL.@)
 */
const char * __cdecl __wine_dbg_strdup( const char *str )
{
    struct debug_info *info = get_info();
    unsigned int pos = info->str_pos;
    size_t n = strlen( str ) + 1;

    assert( n <= sizeof(info->strings) );
    if (pos + n > sizeof(info->strings)) pos = 0;
    info->str_pos = pos + n;
    return memcpy( info->strings + pos, str, n );
}

/***********************************************************************
 *		__wine_dbg_header  (NTDLL.@)
 */
int __cdecl __wine_dbg_header( enum __wine_debug_class cls, struct __wine_debug_channel *channel,
                               const char *function )
{
    static const char * const classes[] = { "fixme", "err", "warn", "trace" };
    struct debug_info *info = get_info();
    char *pos = info->output;

    if (!(__wine_dbg_get_channel_flags( channel ) & (1 << cls))) return -1;

    /* only print header if we are at the beginning of the line */
    if (info->out_pos) return 0;

    if (TRACE_ON(timestamp))
    {
        ULONG ticks = NtGetTickCount();
        pos += sprintf( pos, "%3u.%03u:", ticks / 1000, ticks % 1000 );
    }
    if (TRACE_ON(pid)) pos += sprintf( pos, "%04x:", GetCurrentProcessId() );
    pos += sprintf( pos, "%04x:", GetCurrentThreadId() );
    if (function && cls < ARRAY_SIZE( classes ))
        pos += snprintf( pos, sizeof(info->output) - (pos - info->output), "%s:%s:%s ",
                         classes[cls], channel->name, function );
    info->out_pos = pos - info->output;
    return info->out_pos;
}

/***********************************************************************
 *		__wine_dbg_output  (NTDLL.@)
 */
int __cdecl __wine_dbg_output( const char *str )
{
    struct debug_info *info = get_info();
    const char *end = strrchr( str, '\n' );
    int ret = 0;

    if (end)
    {
        ret += append_output( info, str, end + 1 - str );
        __wine_dbg_write( info->output, info->out_pos );
        info->out_pos = 0;
        str = end + 1;
    }
    if (*str) ret += append_output( info, str, strlen( str ));
    return ret;
}

<<<<<<< HEAD
#else
static ULONG_PTR get_image_addr(void)
{
    return 0;
}
#endif



BOOL read_process_time(int unix_pid, int unix_tid, unsigned long clk_tck,
                       LARGE_INTEGER *kernel, LARGE_INTEGER *user)
{
#ifdef __linux__
    unsigned long usr, sys;
    char buf[512], *pos;
    FILE *fp;
    int i;

    /* based on https://github.com/torvalds/linux/blob/master/fs/proc/array.c */
    if (unix_tid != -1)
        sprintf( buf, "/proc/%u/task/%u/stat", unix_pid, unix_tid );
    else
        sprintf( buf, "/proc/%u/stat", unix_pid );
    if ((fp = fopen( buf, "r" )))
    {
        pos = fgets( buf, sizeof(buf), fp );
        fclose( fp );

        /* format of first chunk is "%d (%s) %c" - we have to skip to the last ')'
         * to avoid misinterpreting the string. */
        if (pos) pos = strrchr( pos, ')' );
        if (pos) pos = strchr( pos + 1, ' ' );
        if (pos) pos++;

        /* skip over the following fields: state, ppid, pgid, sid, tty_nr, tty_pgrp,
         * task->flags, min_flt, cmin_flt, maj_flt, cmaj_flt */
        for (i = 0; (i < 11) && pos; i++)
        {
            pos = strchr( pos + 1, ' ' );
            if (pos) pos++;
        }

        /* the next two values are user and system time */
        if (pos && (sscanf( pos, "%lu %lu", &usr, &sys ) == 2))
        {
            kernel->QuadPart = (ULONGLONG)sys * 10000000 / clk_tck;
            user->QuadPart   = (ULONGLONG)usr * 10000000 / clk_tck;
            return TRUE;
        }
    }
#endif
    return FALSE;
}


/***********************************************************************
 *           set_process_name
 *
 * Change the process name in the ps output.
 */
static void set_process_name( int argc, char *argv[] )
{
    BOOL shift_strings;
    char *p, *name;
    int i;

#ifdef HAVE_SETPROCTITLE
    setproctitle("-%s", argv[1]);
    shift_strings = FALSE;
#else
    p = argv[0];

    shift_strings = (argc >= 2);
    for (i = 1; i < argc; i++)
    {
        p += strlen(p) + 1;
        if (p != argv[i])
        {
            shift_strings = FALSE;
            break;
        }
    }
#endif

    if (shift_strings)
    {
        int offset = argv[1] - argv[0];
        char *end = argv[argc-1] + strlen(argv[argc-1]) + 1;
        memmove( argv[0], argv[1], end - argv[1] );
        memset( end - offset, 0, offset );
        for (i = 1; i < argc; i++)
            argv[i-1] = argv[i] - offset;
        argv[i-1] = NULL;
    }
    else
    {
        /* remove argv[0] */
        memmove( argv, argv + 1, argc * sizeof(argv[0]) );
    }

    name = argv[0];
    if ((p = strrchr( name, '\\' ))) name = p + 1;
    if ((p = strrchr( name, '/' ))) name = p + 1;

#if defined(HAVE_SETPROGNAME)
    setprogname( name );
#endif

#ifdef HAVE_PRCTL
#ifndef PR_SET_NAME
# define PR_SET_NAME 15
#endif
    prctl( PR_SET_NAME, name );
#endif  /* HAVE_PRCTL */
}


/***********************************************************************
 *           thread_init
 *
 * Setup the initial thread.
 *
 * NOTES: The first allocated TEB on NT is at 0x7ffde000.
 */
TEB *thread_init(void)
{
    SYSTEM_BASIC_INFORMATION sbi;
    TEB *teb;
    void *addr;
    SIZE_T size;
    NTSTATUS status;
    struct ntdll_thread_data *thread_data;

    virtual_init();
    signal_init_early();

    /* reserve space for shared user data */

    addr = (void *)0x7ffe0000;
    size = 0x10000;
    status = NtAllocateVirtualMemory( NtCurrentProcess(), &addr, 0, &size,
                                      MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE );
    if (status)
    {
        MESSAGE( "wine: failed to map the shared user data: %08x\n", status );
        exit(1);
    }
	user_shared_data_external = addr;
    memcpy( user_shared_data->NtSystemRoot, default_windirW, sizeof(default_windirW) );

    /* allocate and initialize the PEB */

    addr = NULL;
    size = sizeof(*peb);
    virtual_alloc_aligned( &addr, 0, &size, MEM_COMMIT | MEM_TOP_DOWN, PAGE_READWRITE, 1 );
    peb = addr;

    peb->FastPebLock        = &peb_lock;
    peb->ApiSetMap          = &apiset_map;
    peb->TlsBitmap          = &tls_bitmap;
    peb->TlsExpansionBitmap = &tls_expansion_bitmap;
    peb->FlsBitmap          = &fls_bitmap;
    peb->LdrData            = &ldr;
    peb->OSMajorVersion     = 5;
    peb->OSMinorVersion     = 1;
    peb->OSBuildNumber      = 0xA28;
    peb->OSPlatformId       = VER_PLATFORM_WIN32_NT;
    ldr.Length = sizeof(ldr);
    ldr.Initialized = TRUE;
    RtlInitializeBitMap( &tls_bitmap, peb->TlsBitmapBits, sizeof(peb->TlsBitmapBits) * 8 );
    RtlInitializeBitMap( &tls_expansion_bitmap, peb->TlsExpansionBitmapBits,
                         sizeof(peb->TlsExpansionBitmapBits) * 8 );
    RtlInitializeBitMap( &fls_bitmap, peb->FlsBitmapBits, sizeof(peb->FlsBitmapBits) * 8 );
    RtlSetBits( peb->TlsBitmap, 0, 1 ); /* TLS index 0 is reserved and should be initialized to NULL. */
    RtlSetBits( peb->FlsBitmap, 0, 1 );
    InitializeListHead( &peb->FlsListHead );
    InitializeListHead( &ldr.InLoadOrderModuleList );
    InitializeListHead( &ldr.InMemoryOrderModuleList );
    InitializeListHead( &ldr.InInitializationOrderModuleList );
    *(ULONG_PTR *)peb->Reserved = get_image_addr();

#if defined(__APPLE__) && defined(__x86_64__)
    *((DWORD*)((char*)user_shared_data_external + 0x1000)) = __wine_syscall_dispatcher;
#endif
    /* Pretend we don't support the SYSCALL instruction on x86-64. Needed for
     * Chromium; see output_syscall_thunks_x64() in winebuild. */
    user_shared_data->SystemCallPad[0] = 1;
    user_shared_data_external->SystemCallPad[0] = 1;

    /*
     * Starting with Vista, the first user to log on has session id 1.
     * Session id 0 is for processes that don't interact with the user (like services).
     */
    peb->SessionId = 1;

    /* allocate and initialize the initial TEB */

    signal_alloc_thread( &teb );
    teb->Peb = peb;
    teb->Tib.StackBase = (void *)~0UL;
    teb->StaticUnicodeString.Buffer = teb->StaticUnicodeBuffer;
    teb->StaticUnicodeString.MaximumLength = sizeof(teb->StaticUnicodeBuffer);

    thread_data = (struct ntdll_thread_data *)&teb->GdiTebBatch;
    thread_data->request_fd = -1;
    thread_data->reply_fd   = -1;
    thread_data->wait_fd[0] = -1;
    thread_data->wait_fd[1] = -1;
    thread_data->esync_queue_fd = -1;
    thread_data->esync_apc_fd = -1;

    signal_init_thread( teb );
    virtual_init_threading();
    debug_init();
    set_process_name( __wine_main_argc, __wine_main_argv );

	/* initialize user_shared_data */
    __wine_user_shared_data();
    fill_cpu_info();

    virtual_get_system_info( &sbi );
    user_shared_data->NumberOfPhysicalPages = sbi.MmNumberOfPhysicalPages;

    return teb;
}



/**************************************************************************
 *  __wine_user_shared_data   (NTDLL.@)
 *
 * Update user shared data and return the address of the structure.
 */
BYTE* CDECL __wine_user_shared_data(void)
{
    static int spinlock;
    ULARGE_INTEGER interrupt;
     LARGE_INTEGER now;

    while (interlocked_cmpxchg( &spinlock, 1, 0 ) != 0);

    NtQuerySystemTime( &now );
    user_shared_data->SystemTime.High2Time = now.u.HighPart;
    user_shared_data->SystemTime.LowPart   = now.u.LowPart;
    user_shared_data->SystemTime.High1Time = now.u.HighPart;

    RtlQueryUnbiasedInterruptTime( &interrupt.QuadPart );
    user_shared_data->InterruptTime.High2Time = interrupt.HighPart;
    user_shared_data->InterruptTime.LowPart   = interrupt.LowPart;
    user_shared_data->InterruptTime.High1Time = interrupt.HighPart;

    interrupt.QuadPart /= 10000;
    user_shared_data->u.TickCount.High2Time  = interrupt.HighPart;
    user_shared_data->u.TickCount.LowPart    = interrupt.LowPart;
    user_shared_data->u.TickCount.High1Time  = interrupt.HighPart;
    user_shared_data->TickCountLowDeprecated = interrupt.LowPart;
    user_shared_data->TickCountMultiplier = 1 << 24;

    spinlock = 0;
    return (BYTE *)user_shared_data;
}

static void *user_shared_data_thread(void *arg)
{
    struct timeval tv;

    while (TRUE)
    {
        __wine_user_shared_data();

        tv.tv_sec = 0;
        tv.tv_usec = 15600;
        select(0, NULL, NULL, NULL, &tv);
    }
    return NULL;
}


void create_user_shared_data_thread(void)
{
    static int thread_created;
    pthread_attr_t attr;
    pthread_t thread;

    if (interlocked_cmpxchg(&thread_created, 1, 0) != 0)
        return;

    TRACE("Creating user shared data update thread.\n");

    user_shared_data = user_shared_data_external;
    __wine_user_shared_data();

    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 0x10000);
    pthread_create(&thread, &attr, user_shared_data_thread, NULL);
    pthread_attr_destroy(&attr);
}

BOOL read_process_memory_stats(int unix_pid, VM_COUNTERS *pvmi)
{
    BOOL ret = FALSE;
#ifdef __linux__
    unsigned long size, resident, shared, trs, drs, lrs, dt;
    char buf[512];
    FILE *fp;

    sprintf( buf, "/proc/%u/statm", unix_pid );
    if ((fp = fopen( buf, "r" )))
    {
        if (fscanf( fp, "%lu %lu %lu %lu %lu %lu %lu",
            &size, &resident, &shared, &trs, &drs, &lrs, &dt ) == 7)
        {
            pvmi->VirtualSize = size * page_size;
            pvmi->WorkingSetSize = resident * page_size;
            pvmi->PrivatePageCount = size - shared;

            /* these values are not available through /proc/pid/statm */
            pvmi->PeakVirtualSize = pvmi->VirtualSize;
            pvmi->PageFaultCount = 0;
            pvmi->PeakWorkingSetSize = pvmi->WorkingSetSize;
            pvmi->QuotaPagedPoolUsage = pvmi->VirtualSize;
            pvmi->QuotaPeakPagedPoolUsage = pvmi->QuotaPagedPoolUsage;
            pvmi->QuotaPeakNonPagedPoolUsage = 0;
            pvmi->QuotaNonPagedPoolUsage = 0;
            pvmi->PagefileUsage = 0;
            pvmi->PeakPagefileUsage = 0;

            ret = TRUE;
        }
        fclose( fp );
    }
#endif
    return ret;
}

/***********************************************************************
 *           free_thread_data
 */
static void free_thread_data( TEB *teb )
{
    struct ntdll_thread_data *thread_data = (struct ntdll_thread_data *)&teb->GdiTebBatch;
    SIZE_T size;

    if (teb->DeallocationStack)
    {
        size = 0;
        NtFreeVirtualMemory( GetCurrentProcess(), &teb->DeallocationStack, &size, MEM_RELEASE );
    }
    if (thread_data->start_stack)
    {
        size = 0;
        NtFreeVirtualMemory( GetCurrentProcess(), &thread_data->start_stack, &size, MEM_RELEASE );
    }
    signal_free_thread( teb );
}


/***********************************************************************
 *           abort_thread
 */
void abort_thread( int status )
{
    pthread_sigmask( SIG_BLOCK, &server_block_set, NULL );
    if (interlocked_xchg_add( &nb_threads, -1 ) <= 1) _exit( get_unix_exit_code( status ));
    signal_exit_thread( status );
}


/***********************************************************************
 *           exit_thread
 */
void exit_thread( int status )
{
    close( ntdll_get_thread_data()->wait_fd[0] );
    close( ntdll_get_thread_data()->wait_fd[1] );
    close( ntdll_get_thread_data()->reply_fd );
    close( ntdll_get_thread_data()->request_fd );
    pthread_exit( UIntToPtr(status) );
}

=======
>>>>>>> github-desktop-wine-mirror/master

/***********************************************************************
 *           RtlExitUserThread  (NTDLL.@)
 */
void WINAPI RtlExitUserThread( ULONG status )
{
<<<<<<< HEAD
    static void *prev_teb;
    shmlocal_t *shmlocal;
    sigset_t sigset;
    TEB *teb;

    if (status)  /* send the exit code to the server (0 is already the default) */
    {
        SERVER_START_REQ( terminate_thread )
        {
            req->handle    = wine_server_obj_handle( GetCurrentThread() );
            req->exit_code = status;
            wine_server_call( req );
        }
        SERVER_END_REQ;
    }

    if (interlocked_xchg_add( &nb_threads, 0 ) <= 1)
    {
        LdrShutdownProcess();
        pthread_sigmask( SIG_BLOCK, &server_block_set, NULL );
        signal_exit_process( get_unix_exit_code( status ));
    }
=======
    ULONG last;
>>>>>>> github-desktop-wine-mirror/master

    NtQueryInformationThread( GetCurrentThread(), ThreadAmILastThread, &last, sizeof(last), NULL );
    if (last) RtlExitUserProcess( status );
    LdrShutdownThread();
    for (;;) NtTerminateThread( GetCurrentThread(), status );
}

<<<<<<< HEAD
    shmlocal = interlocked_xchg_ptr( &NtCurrentTeb()->Reserved5[2], NULL );
    if (shmlocal) NtUnmapViewOfSection( NtCurrentProcess(), shmlocal );

    pthread_sigmask( SIG_BLOCK, &server_block_set, NULL );
=======
>>>>>>> github-desktop-wine-mirror/master

/***********************************************************************
 *           RtlUserThreadStart (NTDLL.@)
 */
#ifdef __i386__
__ASM_STDCALL_FUNC( RtlUserThreadStart, 8,
                   "movl %ebx,8(%esp)\n\t"  /* arg */
                   "movl %eax,4(%esp)\n\t"  /* entry */
                   "jmp " __ASM_NAME("call_thread_func") )

/* wrapper to call BaseThreadInitThunk */
extern void DECLSPEC_NORETURN call_thread_func_wrapper( void *thunk, PRTL_THREAD_START_ROUTINE entry, void *arg );
__ASM_GLOBAL_FUNC( call_thread_func_wrapper,
                  "pushl %ebp\n\t"
                  __ASM_CFI(".cfi_adjust_cfa_offset 4\n\t")
                  __ASM_CFI(".cfi_rel_offset %ebp,0\n\t")
                  "movl %esp,%ebp\n\t"
                  __ASM_CFI(".cfi_def_cfa_register %ebp\n\t")
                   "subl $4,%esp\n\t"
                   "andl $~0xf,%esp\n\t"
                   "xorl %ecx,%ecx\n\t"
                   "movl 12(%ebp),%edx\n\t"
                   "movl 16(%ebp),%eax\n\t"
                   "movl %eax,(%esp)\n\t"
                   "call *8(%ebp)" )

void DECLSPEC_HIDDEN call_thread_func( PRTL_THREAD_START_ROUTINE entry, void *arg )
{
    __TRY
    {
        TRACE_(relay)( "\1Starting thread proc %p (arg=%p)\n", entry, arg );
        call_thread_func_wrapper( pBaseThreadInitThunk, entry, arg );
    }
<<<<<<< HEAD

    sigemptyset( &sigset );
    sigaddset( &sigset, SIGQUIT );
    pthread_sigmask( SIG_BLOCK, &sigset, NULL );
    if (interlocked_xchg_add( &nb_threads, -1 ) <= 1) _exit( status );

    signal_exit_thread( status );
=======
    __EXCEPT(call_unhandled_exception_filter)
    {
        NtTerminateProcess( GetCurrentProcess(), GetExceptionCode() );
    }
    __ENDTRY
>>>>>>> github-desktop-wine-mirror/master
}

#else  /* __i386__ */

void WINAPI RtlUserThreadStart( PRTL_THREAD_START_ROUTINE entry, void *arg )
{
    __TRY
    {
        TRACE_(relay)( "\1Starting thread proc %p (arg=%p)\n", entry, arg );
        pBaseThreadInitThunk( 0, (LPTHREAD_START_ROUTINE)entry, arg );
    }
    __EXCEPT(call_unhandled_exception_filter)
    {
        NtTerminateProcess( GetCurrentProcess(), GetExceptionCode() );
    }
    __ENDTRY
}

<<<<<<< HEAD

/***********************************************************************
 *              NtCreateThreadEx   (NTDLL.@)
 */
NTSTATUS WINAPI NtCreateThreadEx( HANDLE *handle_ptr, ACCESS_MASK access, OBJECT_ATTRIBUTES *thread_attr,
                                  HANDLE process, LPTHREAD_START_ROUTINE start, void *param,
                                  ULONG flags, ULONG zero_bits, ULONG stack_commit,
                                  ULONG stack_reserve, PPS_ATTRIBUTE_LIST ps_attr_list )
{
    sigset_t sigset;
    pthread_t pthread_id;
    pthread_attr_t pthread_attr;
    struct ntdll_thread_data *thread_data;
    struct startup_info *info;
    BOOLEAN suspended = !!(flags & THREAD_CREATE_FLAGS_CREATE_SUSPENDED);
    CLIENT_ID *id = NULL;
    HANDLE handle = 0, actctx = 0;
    TEB *teb = NULL;
    DWORD tid = 0;
    int request_pipe[2];
=======
#endif  /* __i386__ */


/***********************************************************************
 *              RtlCreateUserThread   (NTDLL.@)
 */
NTSTATUS WINAPI RtlCreateUserThread( HANDLE process, SECURITY_DESCRIPTOR *descr,
                                     BOOLEAN suspended, ULONG zero_bits,
                                     SIZE_T stack_reserve, SIZE_T stack_commit,
                                     PRTL_THREAD_START_ROUTINE start, void *param,
                                     HANDLE *handle_ptr, CLIENT_ID *id )
{
    ULONG flags = suspended ? THREAD_CREATE_FLAGS_CREATE_SUSPENDED : 0;
    ULONG_PTR buffer[offsetof( PS_ATTRIBUTE_LIST, Attributes[2] ) / sizeof(ULONG_PTR)];
    PS_ATTRIBUTE_LIST *attr_list = (PS_ATTRIBUTE_LIST *)buffer;
    HANDLE handle, actctx;
    TEB *teb;
    ULONG ret;
>>>>>>> github-desktop-wine-mirror/master
    NTSTATUS status;
    CLIENT_ID client_id;
    OBJECT_ATTRIBUTES attr;

<<<<<<< HEAD
    TRACE("(%p, %d, %p, %p, %p, %p, %u, %u, %u, %u, %p)\n",
          handle_ptr, access, thread_attr, process, start, param, flags,
          zero_bits, stack_commit, stack_reserve, ps_attr_list);

    if (ps_attr_list != NULL)
    {
        PS_ATTRIBUTE *ps_attr,
                     *ps_attr_end = (PS_ATTRIBUTE *)((UINT_PTR)ps_attr_list + ps_attr_list->TotalLength);
        for (ps_attr = &ps_attr_list->Attributes[0]; ps_attr < ps_attr_end; ps_attr++)
        {
            switch (ps_attr->Attribute)
            {
            case PS_ATTRIBUTE_CLIENT_ID:
                /* TODO validate ps_attr->Size == sizeof(CLIENT_ID) */
                /* TODO set *ps_attr->ReturnLength */
                id = ps_attr->ValuePtr;
                break;
            default:
                FIXME("Unsupported attribute %08X\n", ps_attr->Attribute);
                break;
            }
        }
    }

    if (access == (ACCESS_MASK)0)
        access = THREAD_ALL_ACCESS;

    if (process != NtCurrentProcess())
=======
    attr_list->TotalLength = sizeof(buffer);
    attr_list->Attributes[0].Attribute    = PS_ATTRIBUTE_CLIENT_ID;
    attr_list->Attributes[0].Size         = sizeof(client_id);
    attr_list->Attributes[0].ValuePtr     = &client_id;
    attr_list->Attributes[0].ReturnLength = NULL;
    attr_list->Attributes[1].Attribute    = PS_ATTRIBUTE_TEB_ADDRESS;
    attr_list->Attributes[1].Size         = sizeof(teb);
    attr_list->Attributes[1].ValuePtr     = &teb;
    attr_list->Attributes[1].ReturnLength = NULL;

    InitializeObjectAttributes( &attr, NULL, 0, NULL, descr );

    RtlGetActiveActivationContext( &actctx );
    if (actctx) flags |= THREAD_CREATE_FLAGS_CREATE_SUSPENDED;

    status = NtCreateThreadEx( &handle, THREAD_ALL_ACCESS, &attr, process, start, param,
                               flags, zero_bits, stack_commit, stack_reserve, attr_list );
    if (!status)
>>>>>>> github-desktop-wine-mirror/master
    {
        if (actctx)
        {
            ULONG_PTR cookie;
            RtlActivateActivationContextEx( 0, teb, actctx, &cookie );
            if (!suspended) NtResumeThread( handle, &ret );
        }
        if (id) *id = client_id;
        if (handle_ptr) *handle_ptr = handle;
        else NtClose( handle );
    }
<<<<<<< HEAD

    if ((status = alloc_object_attributes( thread_attr, &objattr, &len ))) return status;

    if (server_pipe( request_pipe ) == -1)
    {
        RtlFreeHeap( GetProcessHeap(), 0, objattr );
        return STATUS_TOO_MANY_OPENED_FILES;
    }
    wine_server_send_fd( request_pipe[0] );

    SERVER_START_REQ( new_thread )
    {
        req->process    = wine_server_obj_handle( process );
        req->access     = access;
        req->suspend    = suspended;
        req->request_fd = request_pipe[0];
        wine_server_add_data( req, objattr, len );
        if (!(status = wine_server_call( req )))
        {
            handle = wine_server_ptr_handle( reply->handle );
            tid = reply->tid;
        }
        close( request_pipe[0] );
    }
    SERVER_END_REQ;

    RtlFreeHeap( GetProcessHeap(), 0, objattr );
    if (status)
    {
        close( request_pipe[1] );
        return status;
    }

    pthread_sigmask( SIG_BLOCK, &server_block_set, &sigset );

    if ((status = signal_alloc_thread( &teb ))) goto error;

    teb->Peb = NtCurrentTeb()->Peb;
    teb->ClientId.UniqueProcess = ULongToHandle(GetCurrentProcessId());
    teb->ClientId.UniqueThread  = ULongToHandle(tid);
    teb->StaticUnicodeString.Buffer        = teb->StaticUnicodeBuffer;
    teb->StaticUnicodeString.MaximumLength = sizeof(teb->StaticUnicodeBuffer);

    /* create default activation context frame for new thread */
    RtlGetActiveActivationContext(&actctx);
    if (actctx)
    {
        RTL_ACTIVATION_CONTEXT_STACK_FRAME *frame;

        frame = RtlAllocateHeap(GetProcessHeap(), 0, sizeof(*frame));
        frame->Previous = NULL;
        frame->ActivationContext = actctx;
        frame->Flags = 0;
        teb->ActivationContextStack.ActiveFrame = frame;
    }

    info = (struct startup_info *)(teb + 1);
    info->teb         = teb;
    info->entry_point = start;
    info->entry_arg   = param;

    if ((status = virtual_alloc_thread_stack( &stack, stack_reserve, stack_commit, &extra_stack )))
        goto error;

    teb->Tib.StackBase = stack.StackBase;
    teb->Tib.StackLimit = stack.StackLimit;
    teb->DeallocationStack = stack.DeallocationStack;

    thread_data = (struct ntdll_thread_data *)&teb->GdiTebBatch;
    thread_data->request_fd  = request_pipe[1];
    thread_data->reply_fd    = -1;
    thread_data->wait_fd[0]  = -1;
    thread_data->wait_fd[1]  = -1;
    thread_data->start_stack = (char *)teb->Tib.StackBase;
    thread_data->esync_queue_fd = -1;
    thread_data->esync_apc_fd = -1;

    pthread_attr_init( &pthread_attr );
    pthread_attr_setstack( &pthread_attr, teb->DeallocationStack,
                         (char *)teb->Tib.StackBase + extra_stack - (char *)teb->DeallocationStack );
    pthread_attr_setguardsize( &pthread_attr, 0 );
    pthread_attr_setscope( &pthread_attr, PTHREAD_SCOPE_SYSTEM ); /* force creating a kernel thread */
    interlocked_xchg_add( &nb_threads, 1 );
    if (pthread_create( &pthread_id, &pthread_attr, (void * (*)(void *))start_thread, info ))
    {
        interlocked_xchg_add( &nb_threads, -1 );
        pthread_attr_destroy( &pthread_attr );
        status = STATUS_NO_MEMORY;
        goto error;
    }
    pthread_attr_destroy( &pthread_attr );
    pthread_sigmask( SIG_SETMASK, &sigset, NULL );

    if (id) id->UniqueThread = ULongToHandle(tid);
    if (handle_ptr) *handle_ptr = handle;
    else NtClose( handle );

    return STATUS_SUCCESS;

error:
    if (teb) free_thread_data( teb );
    if (handle) NtClose( handle );
    pthread_sigmask( SIG_SETMASK, &sigset, NULL );
    close( request_pipe[1] );
=======
    if (actctx) RtlReleaseActivationContext( actctx );
>>>>>>> github-desktop-wine-mirror/master
    return status;
}

NTSTATUS WINAPI NtCreateThread( HANDLE *handle_ptr, ACCESS_MASK access, OBJECT_ATTRIBUTES *attr, HANDLE process,
                                CLIENT_ID *id, CONTEXT *context, INITIAL_TEB *teb, BOOLEAN suspended )
{
    LPTHREAD_START_ROUTINE entry;
    void *arg;
    ULONG flags = suspended ? THREAD_CREATE_FLAGS_CREATE_SUSPENDED : 0;
    PS_ATTRIBUTE_LIST attr_list, *pattr_list = NULL;

#if defined(__i386__)
        entry = (LPTHREAD_START_ROUTINE) context->Eax;
        arg = (void *)context->Ebx;
#elif defined(__x86_64__)
        entry = (LPTHREAD_START_ROUTINE) context->Rcx;
        arg = (void *)context->Rdx;
#elif defined(__arm__)
        entry = (LPTHREAD_START_ROUTINE) context->R0;
        arg = (void *)context->R1;
#elif defined(__aarch64__)
        entry = (LPTHREAD_START_ROUTINE) context->u.X0;
        arg = (void *)context->u.X1;
#elif defined(__powerpc__)
        entry = (LPTHREAD_START_ROUTINE) context->Gpr3;
        arg = (void *)context->Gpr4;
#endif

    if (id)
    {
        attr_list.TotalLength = sizeof(PS_ATTRIBUTE_LIST);
        attr_list.Attributes[0].Attribute = PS_ATTRIBUTE_CLIENT_ID;
        attr_list.Attributes[0].Size = sizeof(CLIENT_ID);
        attr_list.Attributes[0].ValuePtr = id;
        attr_list.Attributes[0].ReturnLength = NULL;
        pattr_list = &attr_list;
    }

    return NtCreateThreadEx(handle_ptr, access, attr, process, entry, arg, flags, 0, 0, 0, pattr_list);
}

NTSTATUS WINAPI __syscall_NtCreateThread( HANDLE *handle_ptr, ACCESS_MASK access, OBJECT_ATTRIBUTES *attr,
                                          HANDLE process, CLIENT_ID *id, CONTEXT *context, INITIAL_TEB *teb,
                                          BOOLEAN suspended );
NTSTATUS WINAPI __syscall_NtCreateThreadEx( HANDLE *handle_ptr, ACCESS_MASK access, OBJECT_ATTRIBUTES *attr,
                                            HANDLE process, LPTHREAD_START_ROUTINE start, void *param,
                                            ULONG flags, ULONG zero_bits, ULONG stack_commit,
                                            ULONG stack_reserve, PPS_ATTRIBUTE_LIST ps_attr_list );

/***********************************************************************
 *              RtlCreateUserThread   (NTDLL.@)
 */
NTSTATUS WINAPI RtlCreateUserThread( HANDLE process, SECURITY_DESCRIPTOR *descr,
                                     BOOLEAN suspended, void *stack_addr,
                                     SIZE_T stack_reserve, SIZE_T stack_commit,
                                     PRTL_THREAD_START_ROUTINE entry, void *arg,
                                     HANDLE *handle_ptr, CLIENT_ID *id )
{
    OBJECT_ATTRIBUTES thread_attr;
    InitializeObjectAttributes( &thread_attr, NULL, 0, NULL, descr );
    if (stack_addr)
        FIXME("stack_addr != NULL is unimplemented\n");

    if (NtCurrentTeb()->Peb->OSMajorVersion < 6)
    {
        /* Use old API. */
        CONTEXT context = { 0 };

        if (stack_commit)
            FIXME("stack_commit != 0 is unimplemented\n");
        if (stack_reserve)
            FIXME("stack_reserve != 0 is unimplemented\n");

        context.ContextFlags = CONTEXT_FULL;
#if defined(__i386__)
        context.Eax = (DWORD)entry;
        context.Ebx = (DWORD)arg;
#elif defined(__x86_64__)
        context.Rcx = (ULONG_PTR)entry;
        context.Rdx = (ULONG_PTR)arg;
#elif defined(__arm__)
        context.R0 = (DWORD)entry;
        context.R1 = (DWORD)arg;
#elif defined(__aarch64__)
        context.u.X0 = (DWORD_PTR)entry;
        context.u.X1 = (DWORD_PTR)arg;
#elif defined(__powerpc__)
        context.Gpr3 = (DWORD)entry;
        context.Gpr4 = (DWORD)arg;
#endif

#if defined(__i386__) || defined(__x86_64__)
        return __syscall_NtCreateThread(handle_ptr, (ACCESS_MASK)0, &thread_attr, process, id, &context, NULL, suspended);
#else
        return NtCreateThread(handle_ptr, (ACCESS_MASK)0, &thread_attr, process, id, &context, NULL, suspended);
#endif
    }
    else
    {
        /* Use new API from Vista+. */
        ULONG flags = suspended ? THREAD_CREATE_FLAGS_CREATE_SUSPENDED : 0;
        PS_ATTRIBUTE_LIST attr_list, *pattr_list = NULL;

        if (id)
        {
            attr_list.TotalLength = sizeof(PS_ATTRIBUTE_LIST);
            attr_list.Attributes[0].Attribute = PS_ATTRIBUTE_CLIENT_ID;
            attr_list.Attributes[0].Size = sizeof(CLIENT_ID);
            attr_list.Attributes[0].ValuePtr = id;
            attr_list.Attributes[0].ReturnLength = NULL;
            pattr_list = &attr_list;
        }

#if defined(__i386__) || defined(__x86_64__)
        return __syscall_NtCreateThreadEx(handle_ptr, (ACCESS_MASK)0, &thread_attr, process, (LPTHREAD_START_ROUTINE)entry, arg, flags, 0, stack_commit, stack_reserve, pattr_list);
#else
        return NtCreateThreadEx(handle_ptr, (ACCESS_MASK)0, &thread_attr, process, (LPTHREAD_START_ROUTINE)entry, arg, flags, 0, stack_commit, stack_reserve, pattr_list);
#endif
    }
}


/**********************************************************************
 *           RtlCreateUserStack (NTDLL.@)
 */
NTSTATUS WINAPI RtlCreateUserStack( SIZE_T commit, SIZE_T reserve, ULONG zero_bits,
                                    SIZE_T commit_align, SIZE_T reserve_align, INITIAL_TEB *stack )
{
    PROCESS_STACK_ALLOCATION_INFORMATION alloc;
    NTSTATUS status;

    TRACE("commit %#lx, reserve %#lx, zero_bits %u, commit_align %#lx, reserve_align %#lx, stack %p\n",
            commit, reserve, zero_bits, commit_align, reserve_align, stack);

    if (!commit_align || !reserve_align)
        return STATUS_INVALID_PARAMETER;

    if (!commit || !reserve)
    {
        IMAGE_NT_HEADERS *nt = RtlImageNtHeader( NtCurrentTeb()->Peb->ImageBaseAddress );
        if (!reserve) reserve = nt->OptionalHeader.SizeOfStackReserve;
        if (!commit) commit = nt->OptionalHeader.SizeOfStackCommit;
    }

    reserve = (reserve + reserve_align - 1) & ~(reserve_align - 1);
    commit = (commit + commit_align - 1) & ~(commit_align - 1);

    if (reserve < commit) reserve = commit;
    if (reserve < 0x100000) reserve = 0x100000;
    reserve = (reserve + 0xffff) & ~0xffff;  /* round to 64K boundary */

    alloc.ReserveSize = reserve;
    alloc.ZeroBits = zero_bits;
    status = NtSetInformationProcess( GetCurrentProcess(), ProcessThreadStackAllocation,
                                      &alloc, sizeof(alloc) );
    if (!status)
    {
        void *addr = alloc.StackBase;
        SIZE_T size = page_size;

        NtAllocateVirtualMemory( GetCurrentProcess(), &addr, 0, &size, MEM_COMMIT, PAGE_NOACCESS );
        addr = (char *)alloc.StackBase + page_size;
        NtAllocateVirtualMemory( GetCurrentProcess(), &addr, 0, &size, MEM_COMMIT, PAGE_READWRITE | PAGE_GUARD );
        addr = (char *)alloc.StackBase + 2 * page_size;
        size = reserve - 2 * page_size;
        NtAllocateVirtualMemory( GetCurrentProcess(), &addr, 0, &size, MEM_COMMIT, PAGE_READWRITE );

        /* note: limit is lower than base since the stack grows down */
        stack->OldStackBase = 0;
        stack->OldStackLimit = 0;
        stack->DeallocationStack = alloc.StackBase;
        stack->StackBase = (char *)alloc.StackBase + reserve;
        stack->StackLimit = (char *)alloc.StackBase + 2 * page_size;
    }
    return status;
}


/**********************************************************************
 *           RtlFreeUserStack (NTDLL.@)
 */
void WINAPI RtlFreeUserStack( void *stack )
{
    SIZE_T size = 0;

    TRACE("stack %p\n", stack);

    NtFreeVirtualMemory( NtCurrentProcess(), &stack, &size, MEM_RELEASE );
}


/******************************************************************************
 *              RtlGetNtGlobalFlags   (NTDLL.@)
 */
ULONG WINAPI RtlGetNtGlobalFlags(void)
{
    return NtCurrentTeb()->Peb->NtGlobalFlag;
}


/******************************************************************************
 *              RtlPushFrame  (NTDLL.@)
 */
void WINAPI RtlPushFrame( TEB_ACTIVE_FRAME *frame )
{
    frame->Previous = NtCurrentTeb()->ActiveFrame;
    NtCurrentTeb()->ActiveFrame = frame;
}


/******************************************************************************
 *              RtlPopFrame  (NTDLL.@)
 */
void WINAPI RtlPopFrame( TEB_ACTIVE_FRAME *frame )
{
    NtCurrentTeb()->ActiveFrame = frame->Previous;
}


/******************************************************************************
 *              RtlGetFrame  (NTDLL.@)
 */
TEB_ACTIVE_FRAME * WINAPI RtlGetFrame(void)
{
    return NtCurrentTeb()->ActiveFrame;
}


/***********************************************************************
 * Fibers
 ***********************************************************************/


static GLOBAL_FLS_DATA fls_data = { { NULL }, { &fls_data.fls_list_head, &fls_data.fls_list_head } };

static RTL_CRITICAL_SECTION fls_section;
static RTL_CRITICAL_SECTION_DEBUG fls_critsect_debug =
{
    0, 0, &fls_section,
    { &fls_critsect_debug.ProcessLocksList, &fls_critsect_debug.ProcessLocksList },
            0, 0, { (DWORD_PTR)(__FILE__ ": fls_section") }
};
static RTL_CRITICAL_SECTION fls_section = { &fls_critsect_debug, -1, 0, 0, 0, 0 };

#define MAX_FLS_DATA_COUNT 0xff0

static void lock_fls_data(void)
{
    RtlEnterCriticalSection( &fls_section );
}

static void unlock_fls_data(void)
{
    RtlLeaveCriticalSection( &fls_section );
}

static unsigned int fls_chunk_size( unsigned int chunk_index )
{
    return 0x10 << chunk_index;
}

static unsigned int fls_index_from_chunk_index( unsigned int chunk_index, unsigned int index )
{
    return 0x10 * ((1 << chunk_index) - 1) + index;
}

static unsigned int fls_chunk_index_from_index( unsigned int index, unsigned int *index_in_chunk )
{
    unsigned int chunk_index = 0;

    while (index >= fls_chunk_size( chunk_index ))
        index -= fls_chunk_size( chunk_index++ );

    *index_in_chunk = index;
    return chunk_index;
}

TEB_FLS_DATA *fls_alloc_data(void)
{
    TEB_FLS_DATA *fls;

    if (!(fls = RtlAllocateHeap( GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*fls) )))
        return NULL;

    lock_fls_data();
    InsertTailList( &fls_data.fls_list_head, &fls->fls_list_entry );
    unlock_fls_data();

    return fls;
}


/***********************************************************************
 *              RtlFlsAlloc  (NTDLL.@)
 */
NTSTATUS WINAPI DECLSPEC_HOTPATCH RtlFlsAlloc( PFLS_CALLBACK_FUNCTION callback, ULONG *ret_index )
{
    unsigned int chunk_index, index, i;
    FLS_INFO_CHUNK *chunk;
    TEB_FLS_DATA *fls;

    if (!(fls = NtCurrentTeb()->FlsSlots)
            && !(NtCurrentTeb()->FlsSlots = fls = fls_alloc_data()))
        return STATUS_NO_MEMORY;

    lock_fls_data();
    for (i = 0; i < ARRAY_SIZE(fls_data.fls_callback_chunks); ++i)
    {
        if (!fls_data.fls_callback_chunks[i] || fls_data.fls_callback_chunks[i]->count < fls_chunk_size( i ))
            break;
    }

    if ((chunk_index = i) == ARRAY_SIZE(fls_data.fls_callback_chunks))
    {
        unlock_fls_data();
        return STATUS_NO_MEMORY;
    }

    if ((chunk = fls_data.fls_callback_chunks[chunk_index]))
    {
        for (index = 0; index < fls_chunk_size( chunk_index ); ++index)
            if (!chunk->callbacks[index].callback)
                break;
        assert( index < fls_chunk_size( chunk_index ));
    }
    else
    {
        fls_data.fls_callback_chunks[chunk_index] = chunk = RtlAllocateHeap( GetProcessHeap(), HEAP_ZERO_MEMORY,
                offsetof(FLS_INFO_CHUNK, callbacks) + sizeof(*chunk->callbacks) * fls_chunk_size( chunk_index ));
        if (!chunk)
        {
            unlock_fls_data();
            return STATUS_NO_MEMORY;
        }

        if (chunk_index)
        {
            index = 0;
        }
        else
        {
            chunk->count = 1; /* FLS index 0 is prohibited. */
            chunk->callbacks[0].callback = (void *)~(ULONG_PTR)0;
            index = 1;
        }
    }

    ++chunk->count;
    chunk->callbacks[index].callback = callback ? callback : (PFLS_CALLBACK_FUNCTION)~(ULONG_PTR)0;

    if ((*ret_index = fls_index_from_chunk_index( chunk_index, index )) > fls_data.fls_high_index)
        fls_data.fls_high_index = *ret_index;

    unlock_fls_data();

    return STATUS_SUCCESS;
}


/***********************************************************************
 *              RtlFlsFree   (NTDLL.@)
 */
NTSTATUS WINAPI DECLSPEC_HOTPATCH RtlFlsFree( ULONG index )
{
    PFLS_CALLBACK_FUNCTION callback;
    unsigned int chunk_index, idx;
    FLS_INFO_CHUNK *chunk;
    LIST_ENTRY *entry;

    lock_fls_data();

    if (!index || index > fls_data.fls_high_index)
    {
<<<<<<< HEAD
    case ThreadBasicInformation:
        {
            THREAD_BASIC_INFORMATION info;
            const ULONG_PTR affinity_mask = get_system_affinity_mask();

            SERVER_START_REQ( get_thread_info )
            {
                req->handle = wine_server_obj_handle( handle );
                req->tid_in = 0;
                if (!(status = wine_server_call( req )))
                {
                    info.ExitStatus             = reply->exit_code;
                    info.TebBaseAddress         = wine_server_get_ptr( reply->teb );
                    info.ClientId.UniqueProcess = ULongToHandle(reply->pid);
                    info.ClientId.UniqueThread  = ULongToHandle(reply->tid);
                    info.AffinityMask           = reply->affinity & affinity_mask;
                    info.Priority               = reply->priority;
                    info.BasePriority           = reply->priority;  /* FIXME */
                }
            }
            SERVER_END_REQ;
            if (status == STATUS_SUCCESS)
            {
                if (data) memcpy( data, &info, min( length, sizeof(info) ));
                if (ret_len) *ret_len = min( length, sizeof(info) );
            }
        }
        return status;
    case ThreadAffinityMask:
        {
            const ULONG_PTR affinity_mask = get_system_affinity_mask();
            ULONG_PTR affinity = 0;

            SERVER_START_REQ( get_thread_info )
            {
                req->handle = wine_server_obj_handle( handle );
                req->tid_in = 0;
                if (!(status = wine_server_call( req )))
                    affinity = reply->affinity & affinity_mask;
            }
            SERVER_END_REQ;
            if (status == STATUS_SUCCESS)
            {
                if (data) memcpy( data, &affinity, min( length, sizeof(affinity) ));
                if (ret_len) *ret_len = min( length, sizeof(affinity) );
            }
        }
        return status;
    case ThreadTimes:
        {
            KERNEL_USER_TIMES   kusrt;
            int unix_pid, unix_tid;

            /* We need to do a server call to get the creation time, exit time, PID and TID */
            /* This works on any thread */
            SERVER_START_REQ( get_thread_times )
            {
                req->handle = wine_server_obj_handle( handle );
                status = wine_server_call( req );
                if (status == STATUS_SUCCESS)
                {
                    kusrt.CreateTime.QuadPart = reply->creation_time;
                    kusrt.ExitTime.QuadPart = reply->exit_time;
                    unix_pid = reply->unix_pid;
                    unix_tid = reply->unix_tid;
                }
            }
            SERVER_END_REQ;
            if (status == STATUS_SUCCESS)
            {
                unsigned long clk_tck = sysconf(_SC_CLK_TCK);
                BOOL filled_times = FALSE;

#ifdef __linux__
                /* only /proc provides exact values for a specific thread */
                if (unix_pid != -1 && unix_tid != -1)
                    filled_times = read_process_time(unix_pid, unix_tid, clk_tck, &kusrt.KernelTime, &kusrt.UserTime);
#endif

                /* get values for current process instead */
                if (!filled_times && handle == GetCurrentThread())
                {
                    struct tms time_buf;
                    times(&time_buf);

                    kusrt.KernelTime.QuadPart = (ULONGLONG)time_buf.tms_stime * 10000000 / clk_tck;
                    kusrt.UserTime.QuadPart   = (ULONGLONG)time_buf.tms_utime * 10000000 / clk_tck;
                    filled_times = TRUE;
                }

                /* unable to determine exact values, fill with zero */
                if (!filled_times)
                {
                    static int once;
                    if (!once++)
                        FIXME("Cannot get kerneltime or usertime of other threads\n");

                    kusrt.KernelTime.QuadPart = 0;
                    kusrt.UserTime.QuadPart   = 0;
                }

                if (data) memcpy( data, &kusrt, min( length, sizeof(kusrt) ));
                if (ret_len) *ret_len = min( length, sizeof(kusrt) );
            }
        }
        return status;

    case ThreadDescriptorTableEntry:
        return get_thread_ldt_entry( handle, data, length, ret_len );

    case ThreadAmILastThread:
        {
            SERVER_START_REQ(get_thread_info)
            {
                req->handle = wine_server_obj_handle( handle );
                req->tid_in = 0;
                status = wine_server_call( req );
                if (status == STATUS_SUCCESS)
                {
                    BOOLEAN last = reply->last;
                    if (data) memcpy( data, &last, min( length, sizeof(last) ));
                    if (ret_len) *ret_len = min( length, sizeof(last) );
                }
            }
            SERVER_END_REQ;
            return status;
        }
    case ThreadQuerySetWin32StartAddress:
        {
            SERVER_START_REQ( get_thread_info )
            {
                req->handle = wine_server_obj_handle( handle );
                req->tid_in = 0;
                status = wine_server_call( req );
                if (status == STATUS_SUCCESS)
                {
                    PRTL_THREAD_START_ROUTINE entry = wine_server_get_ptr( reply->entry_point );
                    if (data) memcpy( data, &entry, min( length, sizeof(entry) ) );
                    if (ret_len) *ret_len = min( length, sizeof(entry) );
                }
            }
            SERVER_END_REQ;
            return status;
        }
    case ThreadGroupInformation:
        {
            const ULONG_PTR affinity_mask = get_system_affinity_mask();
            GROUP_AFFINITY affinity;

            memset(&affinity, 0, sizeof(affinity));
            affinity.Group = 0; /* Wine only supports max 64 processors */

            SERVER_START_REQ( get_thread_info )
            {
                req->handle = wine_server_obj_handle( handle );
                req->tid_in = 0;
                if (!(status = wine_server_call( req )))
                    affinity.Mask = reply->affinity & affinity_mask;
            }
            SERVER_END_REQ;
            if (status == STATUS_SUCCESS)
            {
                if (data) memcpy( data, &affinity, min( length, sizeof(affinity) ));
                if (ret_len) *ret_len = min( length, sizeof(affinity) );
            }
        }
        return status;
    case ThreadIsIoPending:
        FIXME( "ThreadIsIoPending info class not supported yet\n" );
        if (length != sizeof(BOOL)) return STATUS_INFO_LENGTH_MISMATCH;
        if (!data) return STATUS_ACCESS_DENIED;

        *(BOOL*)data = FALSE;
        if (ret_len) *ret_len = sizeof(BOOL);
        return STATUS_SUCCESS;
    case ThreadSuspendCount:
        {
            ULONG count = 0;

            if (length != sizeof(ULONG)) return STATUS_INFO_LENGTH_MISMATCH;
            if (!data) return STATUS_ACCESS_VIOLATION;

            SERVER_START_REQ( get_thread_info )
            {
                req->handle = wine_server_obj_handle( handle );
                req->tid_in = 0;
                if (!(status = wine_server_call( req )))
                    count = reply->suspend_count;
            }
            SERVER_END_REQ;

            if (!status)
                *(ULONG *)data = count;

            return status;
        }
    case ThreadDescription:
        {
            THREAD_DESCRIPTION_INFORMATION *info = data;
            data_size_t len, desc_len = 0;
            WCHAR *ptr;

            len = length >= sizeof(*info) ? length - sizeof(*info) : 0;
            ptr = info ? (WCHAR *)(info + 1) : NULL;

            SERVER_START_REQ( get_thread_info )
            {
                req->handle = wine_server_obj_handle( handle );
                if (ptr) wine_server_set_reply( req, ptr, len );
                status = wine_server_call( req );
                desc_len = reply->desc_len;
            }
            SERVER_END_REQ;

            if (!info)
                status = STATUS_BUFFER_TOO_SMALL;
            else if (status == STATUS_SUCCESS)
            {
                info->Description.Length = info->Description.MaximumLength = desc_len;
                info->Description.Buffer = ptr;
            }

            if (ret_len && (status == STATUS_SUCCESS || status == STATUS_BUFFER_TOO_SMALL))
                *ret_len = sizeof(*info) + desc_len;
        }
        return status;
    case ThreadHideFromDebugger:
        if (length != sizeof(BOOLEAN)) return STATUS_INFO_LENGTH_MISMATCH;
        *(BOOLEAN *)data = TRUE;
        if (ret_len) *ret_len = sizeof(BOOLEAN);
        return STATUS_SUCCESS;
    case ThreadPriority:
    case ThreadBasePriority:
    case ThreadImpersonationToken:
    case ThreadEnableAlignmentFaultFixup:
    case ThreadEventPair_Reusable:
    case ThreadZeroTlsCell:
    case ThreadPerformanceCount:
    case ThreadIdealProcessor:
    case ThreadPriorityBoost:
    case ThreadSetTlsArrayAddress:
    default:
        FIXME( "info class %d not supported yet\n", class );
        return STATUS_NOT_IMPLEMENTED;
=======
        unlock_fls_data();
        return STATUS_INVALID_PARAMETER;
>>>>>>> github-desktop-wine-mirror/master
    }

    chunk_index = fls_chunk_index_from_index( index, &idx );
    if (!(chunk = fls_data.fls_callback_chunks[chunk_index])
            || !(callback = chunk->callbacks[idx].callback))
    {
        unlock_fls_data();
        return STATUS_INVALID_PARAMETER;
    }

    for (entry = fls_data.fls_list_head.Flink; entry != &fls_data.fls_list_head; entry = entry->Flink)
    {
        TEB_FLS_DATA *fls = CONTAINING_RECORD(entry, TEB_FLS_DATA, fls_list_entry);

        if (fls->fls_data_chunks[chunk_index] && fls->fls_data_chunks[chunk_index][idx + 1])
        {
            if (callback != (void *)~(ULONG_PTR)0)
            {
                TRACE_(relay)("Calling FLS callback %p, arg %p.\n", callback,
                        fls->fls_data_chunks[chunk_index][idx + 1]);

                callback( fls->fls_data_chunks[chunk_index][idx + 1] );
            }
            fls->fls_data_chunks[chunk_index][idx + 1] = NULL;
        }
    }

    --chunk->count;
    chunk->callbacks[idx].callback = NULL;

    unlock_fls_data();
    return STATUS_SUCCESS;
}


/***********************************************************************
 *              RtlFlsSetValue (NTDLL.@)
 */
NTSTATUS WINAPI DECLSPEC_HOTPATCH RtlFlsSetValue( ULONG index, void *data )
{
    unsigned int chunk_index, idx;
    TEB_FLS_DATA *fls;

    if (!index || index >= MAX_FLS_DATA_COUNT)
        return STATUS_INVALID_PARAMETER;

    if (!(fls = NtCurrentTeb()->FlsSlots)
            && !(NtCurrentTeb()->FlsSlots = fls = fls_alloc_data()))
        return STATUS_NO_MEMORY;

    chunk_index = fls_chunk_index_from_index( index, &idx );

    if (!fls->fls_data_chunks[chunk_index] &&
            !(fls->fls_data_chunks[chunk_index] = RtlAllocateHeap( GetProcessHeap(), HEAP_ZERO_MEMORY,
            (fls_chunk_size( chunk_index ) + 1) * sizeof(*fls->fls_data_chunks[chunk_index]) )))
        return STATUS_NO_MEMORY;

    fls->fls_data_chunks[chunk_index][idx + 1] = data;

    return STATUS_SUCCESS;
}


/***********************************************************************
 *              RtlFlsGetValue (NTDLL.@)
 */
NTSTATUS WINAPI DECLSPEC_HOTPATCH RtlFlsGetValue( ULONG index, void **data )
{
    unsigned int chunk_index, idx;
    TEB_FLS_DATA *fls;

    if (!index || index >= MAX_FLS_DATA_COUNT || !(fls = NtCurrentTeb()->FlsSlots))
        return STATUS_INVALID_PARAMETER;

    chunk_index = fls_chunk_index_from_index( index, &idx );

    *data = fls->fls_data_chunks[chunk_index] ? fls->fls_data_chunks[chunk_index][idx + 1] : NULL;
    return STATUS_SUCCESS;
}


/***********************************************************************
 *              RtlProcessFlsData (NTDLL.@)
 */
void WINAPI DECLSPEC_HOTPATCH RtlProcessFlsData( void *teb_fls_data, ULONG flags )
{
    TEB_FLS_DATA *fls = teb_fls_data;
    unsigned int i, index;

    TRACE_(thread)( "teb_fls_data %p, flags %#x.\n", teb_fls_data, flags );

    if (flags & ~3)
        FIXME_(thread)( "Unknown flags %#x.\n", flags );

    if (!fls)
        return;

    if (flags & 1)
    {
        lock_fls_data();
        for (i = 0; i < ARRAY_SIZE(fls->fls_data_chunks); ++i)
        {
            if (!fls->fls_data_chunks[i] || !fls_data.fls_callback_chunks[i]
                    || !fls_data.fls_callback_chunks[i]->count)
                continue;

            for (index = 0; index < fls_chunk_size( i ); ++index)
            {
                PFLS_CALLBACK_FUNCTION callback = fls_data.fls_callback_chunks[i]->callbacks[index].callback;

                if (!fls->fls_data_chunks[i][index + 1])
                    continue;

                if (callback && callback != (void *)~(ULONG_PTR)0)
                {
                    TRACE_(relay)("Calling FLS callback %p, arg %p.\n", callback,
                            fls->fls_data_chunks[i][index + 1]);

                    callback( fls->fls_data_chunks[i][index + 1] );
                }
                fls->fls_data_chunks[i][index + 1] = NULL;
            }
        }
        /* Not using RemoveEntryList() as Windows does not zero list entry here. */
        fls->fls_list_entry.Flink->Blink = fls->fls_list_entry.Blink;
        fls->fls_list_entry.Blink->Flink = fls->fls_list_entry.Flink;
        unlock_fls_data();
    }

    if (flags & 2)
    {
        for (i = 0; i < ARRAY_SIZE(fls->fls_data_chunks); ++i)
            RtlFreeHeap( GetProcessHeap(), 0, fls->fls_data_chunks[i] );

        RtlFreeHeap( GetProcessHeap(), 0, fls );
    }
}
