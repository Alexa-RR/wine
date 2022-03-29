/*
 * File handling functions
 *
 * Copyright 1993 Erik Bos
 * Copyright 1996, 2004 Alexandre Julliard
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
 *
 */

#include <errno.h>
#include <stdio.h>
#include <stdarg.h>

#include "winerror.h"
#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winnls.h"
#include "winternl.h"
#include "winioctl.h"
#include "ntifs.h"

#include "kernel_private.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(file);

#define MAX_PATHNAME_LEN        1024

static const WCHAR system_dir[] = L"C:\\windows\\system32";

/***********************************************************************
 *           copy_filename_WtoA
 *
 * copy a file name back to OEM/Ansi, but only if the buffer is large enough
 */
static DWORD copy_filename_WtoA( LPCWSTR nameW, LPSTR buffer, DWORD len )
{
    UNICODE_STRING strW;
    DWORD ret;
    BOOL is_ansi = AreFileApisANSI();

    RtlInitUnicodeString( &strW, nameW );

    ret = is_ansi ? RtlUnicodeStringToAnsiSize(&strW) : RtlUnicodeStringToOemSize(&strW);
    if (buffer && ret <= len)
    {
        ANSI_STRING str;

        str.Buffer = buffer;
        str.MaximumLength = min( len, UNICODE_STRING_MAX_CHARS );
        if (is_ansi)
            RtlUnicodeStringToAnsiString( &str, &strW, FALSE );
        else
            RtlUnicodeStringToOemString( &str, &strW, FALSE );
        ret = str.Length;  /* length without terminating 0 */
    }
    return ret;
}

/***********************************************************************
 *           GetShortPathNameA   (KERNEL32.@)
 */
DWORD WINAPI GetShortPathNameA( LPCSTR longpath, LPSTR shortpath, DWORD shortlen )
{
    WCHAR *longpathW;
    WCHAR shortpathW[MAX_PATH];
    DWORD ret;

    TRACE("%s\n", debugstr_a(longpath));

    if (!(longpathW = FILE_name_AtoW( longpath, FALSE ))) return 0;

    ret = GetShortPathNameW(longpathW, shortpathW, MAX_PATH);

    if (!ret) return 0;
    if (ret > MAX_PATH)
    {
        SetLastError(ERROR_FILENAME_EXCED_RANGE);
        return 0;
    }
    return copy_filename_WtoA( shortpathW, shortpath, shortlen );
}


/**************************************************************************
 *           CopyFileA   (KERNEL32.@)
 */
BOOL WINAPI CopyFileA( LPCSTR source, LPCSTR dest, BOOL fail_if_exists)
{
    WCHAR *sourceW, *destW;
    BOOL ret;

    if (!(sourceW = FILE_name_AtoW( source, FALSE ))) return FALSE;
    if (!(destW = FILE_name_AtoW( dest, TRUE ))) return FALSE;

    ret = CopyFileW( sourceW, destW, fail_if_exists );

    HeapFree( GetProcessHeap(), 0, destW );
    return ret;
}


/**************************************************************************
<<<<<<< HEAD
 *           CopyFileExW   (KERNEL32.@)
 */
BOOL WINAPI CopyFileExW(LPCWSTR source, LPCWSTR dest,
                        LPPROGRESS_ROUTINE progress, LPVOID param,
                        LPBOOL cancel_ptr, DWORD flags)
{
    static const int buffer_size = 65536;
    HANDLE h1, h2;
    BY_HANDLE_FILE_INFORMATION info;
    DWORD count;
    BOOL ret = FALSE;
    char *buffer;
    LARGE_INTEGER size;
    LARGE_INTEGER transferred;
    DWORD cbret;

    if (!source || !dest)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (!(buffer = HeapAlloc( GetProcessHeap(), 0, buffer_size )))
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }

    TRACE("%s -> %s, %x\n", debugstr_w(source), debugstr_w(dest), flags);

    if (flags & COPY_FILE_RESTARTABLE)
        FIXME("COPY_FILE_RESTARTABLE is not supported\n");
    if (flags & COPY_FILE_COPY_SYMLINK)
        FIXME("COPY_FILE_COPY_SYMLINK is not supported\n");

    if ((h1 = CreateFileW(source, (flags & COPY_FILE_OPEN_SOURCE_FOR_WRITE) ?
                     GENERIC_WRITE | GENERIC_READ : GENERIC_READ,
                     FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                     NULL, OPEN_EXISTING, 0, 0)) == INVALID_HANDLE_VALUE)
    {
        WARN("Unable to open source %s\n", debugstr_w(source));
        HeapFree( GetProcessHeap(), 0, buffer );
        return FALSE;
    }

    if (!GetFileInformationByHandle( h1, &info ))
    {
        WARN("GetFileInformationByHandle returned error for %s\n", debugstr_w(source));
        HeapFree( GetProcessHeap(), 0, buffer );
        CloseHandle( h1 );
        return FALSE;
    }

    if (!(flags & COPY_FILE_FAIL_IF_EXISTS))
    {
        BOOL same_file = FALSE;
        h2 = CreateFileW( dest, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                         OPEN_EXISTING, 0, 0);
        if (h2 != INVALID_HANDLE_VALUE)
        {
            same_file = is_same_file( h1, h2 );
            CloseHandle( h2 );
        }
        if (same_file)
        {
            HeapFree( GetProcessHeap(), 0, buffer );
            CloseHandle( h1 );
            SetLastError( ERROR_SHARING_VIOLATION );
            return FALSE;
        }
    }

    if ((h2 = CreateFileW( dest, GENERIC_WRITE | DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                           (flags & COPY_FILE_FAIL_IF_EXISTS) ? CREATE_NEW : CREATE_ALWAYS,
                           info.dwFileAttributes, h1 )) == INVALID_HANDLE_VALUE &&
        /* retry without DELETE if we got a sharing violation */
        (h2 = CreateFileW( dest, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                           (flags & COPY_FILE_FAIL_IF_EXISTS) ? CREATE_NEW : CREATE_ALWAYS,
                           info.dwFileAttributes, h1 )) == INVALID_HANDLE_VALUE)
    {
        WARN("Unable to open dest %s\n", debugstr_w(dest));
        HeapFree( GetProcessHeap(), 0, buffer );
        CloseHandle( h1 );
        return FALSE;
    }

    size.u.LowPart = info.nFileSizeLow;
    size.u.HighPart = info.nFileSizeHigh;
    transferred.QuadPart = 0;

    if (progress)
    {
        cbret = progress( size, transferred, size, transferred, 1,
                          CALLBACK_STREAM_SWITCH, h1, h2, param );
        if (cbret == PROGRESS_QUIET)
            progress = NULL;
        else if (cbret == PROGRESS_STOP)
        {
            SetLastError( ERROR_REQUEST_ABORTED );
            goto done;
        }
        else if (cbret == PROGRESS_CANCEL)
        {
            BOOLEAN disp = TRUE;
            SetFileInformationByHandle( h2, FileDispositionInfo, &disp, sizeof(disp) );
            SetLastError( ERROR_REQUEST_ABORTED );
            goto done;
        }
    }

    while (ReadFile( h1, buffer, buffer_size, &count, NULL ) && count)
    {
        char *p = buffer;
        while (count != 0)
        {
            DWORD res;
            if (!WriteFile( h2, p, count, &res, NULL ) || !res) goto done;
            p += res;
            count -= res;

            if (progress)
            {
                transferred.QuadPart += res;
                cbret = progress( size, transferred, size, transferred, 1,
                                  CALLBACK_CHUNK_FINISHED, h1, h2, param );
                if (cbret == PROGRESS_QUIET)
                    progress = NULL;
                else if (cbret == PROGRESS_STOP)
                {
                    SetLastError( ERROR_REQUEST_ABORTED );
                    goto done;
                }
                else if (cbret == PROGRESS_CANCEL)
                {
                    BOOLEAN disp = TRUE;
                    SetFileInformationByHandle( h2, FileDispositionInfo, &disp, sizeof(disp) );
                    SetLastError( ERROR_REQUEST_ABORTED );
                    goto done;
                }
            }
        }
    }
    ret =  TRUE;
done:
    /* Maintain the timestamp of source file to destination file */
    SetFileTime(h2, NULL, NULL, &info.ftLastWriteTime);
    HeapFree( GetProcessHeap(), 0, buffer );
    CloseHandle( h1 );
    CloseHandle( h2 );
    return ret;
}


/**************************************************************************
=======
>>>>>>> github-desktop-wine-mirror/master
 *           CopyFileExA   (KERNEL32.@)
 */
BOOL WINAPI CopyFileExA(LPCSTR sourceFilename, LPCSTR destFilename,
                        LPPROGRESS_ROUTINE progressRoutine, LPVOID appData,
                        LPBOOL cancelFlagPointer, DWORD copyFlags)
{
    WCHAR *sourceW, *destW;
    BOOL ret;

    /* can't use the TEB buffer since we may have a callback routine */
    if (!(sourceW = FILE_name_AtoW( sourceFilename, TRUE ))) return FALSE;
    if (!(destW = FILE_name_AtoW( destFilename, TRUE )))
    {
        HeapFree( GetProcessHeap(), 0, sourceW );
        return FALSE;
    }
    ret = CopyFileExW(sourceW, destW, progressRoutine, appData,
                      cancelFlagPointer, copyFlags);
    HeapFree( GetProcessHeap(), 0, sourceW );
    HeapFree( GetProcessHeap(), 0, destW );
    return ret;
}

/**************************************************************************
 *           MoveFileTransactedA   (KERNEL32.@)
 */
BOOL WINAPI MoveFileTransactedA(const char *source, const char *dest, LPPROGRESS_ROUTINE progress, void *data, DWORD flags, HANDLE handle)
{
    FIXME("(%s, %s, %p, %p, %ld, %p)\n", debugstr_a(source), debugstr_a(dest), progress, data, flags, handle);
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

/**************************************************************************
 *           MoveFileTransactedW   (KERNEL32.@)
 */
BOOL WINAPI MoveFileTransactedW(const WCHAR *source, const WCHAR *dest, LPPROGRESS_ROUTINE progress, void *data, DWORD flags, HANDLE handle)
{
    FIXME("(%s, %s, %p, %p, %ld, %p)\n", debugstr_w(source), debugstr_w(dest), progress, data, flags, handle);
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

/**************************************************************************
 *           MoveFileWithProgressA   (KERNEL32.@)
 */
BOOL WINAPI MoveFileWithProgressA( LPCSTR source, LPCSTR dest,
                                   LPPROGRESS_ROUTINE fnProgress,
                                   LPVOID param, DWORD flag )
{
    WCHAR *sourceW, *destW;
    BOOL ret;

    if (!(sourceW = FILE_name_AtoW( source, FALSE ))) return FALSE;
    if (dest)
    {
        if (!(destW = FILE_name_AtoW( dest, TRUE ))) return FALSE;
    }
    else
        destW = NULL;

    ret = MoveFileWithProgressW( sourceW, destW, fnProgress, param, flag );
    HeapFree( GetProcessHeap(), 0, destW );
    return ret;
}

/**************************************************************************
 *           MoveFileExA   (KERNEL32.@)
 */
BOOL WINAPI MoveFileExA( LPCSTR source, LPCSTR dest, DWORD flag )
{
    return MoveFileWithProgressA( source, dest, NULL, NULL, flag );
}


/**************************************************************************
 *           MoveFileW   (KERNEL32.@)
 *
 *  Move file or directory
 */
BOOL WINAPI MoveFileW( LPCWSTR source, LPCWSTR dest )
{
    return MoveFileExW( source, dest, MOVEFILE_COPY_ALLOWED );
}


/**************************************************************************
 *           MoveFileA   (KERNEL32.@)
 */
BOOL WINAPI MoveFileA( LPCSTR source, LPCSTR dest )
{
    return MoveFileExA( source, dest, MOVEFILE_COPY_ALLOWED );
}


/***********************************************************************
 *           CreateDirectoryExA   (KERNEL32.@)
 */
BOOL WINAPI CreateDirectoryExA( LPCSTR template, LPCSTR path, LPSECURITY_ATTRIBUTES sa )
{
    WCHAR *pathW, *templateW = NULL;
    BOOL ret;

    if (!(pathW = FILE_name_AtoW( path, FALSE ))) return FALSE;
    if (template && !(templateW = FILE_name_AtoW( template, TRUE ))) return FALSE;

    ret = CreateDirectoryExW( templateW, pathW, sa );
    HeapFree( GetProcessHeap(), 0, templateW );
    return ret;
}


/***********************************************************************
<<<<<<< HEAD
 *           RemoveDirectoryW   (KERNEL32.@)
 */
BOOL WINAPI RemoveDirectoryW( LPCWSTR path )
{
    FILE_BASIC_INFORMATION info;
    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING nt_name;
    ANSI_STRING unix_name;
    IO_STATUS_BLOCK io;
    NTSTATUS status;
    HANDLE handle;
    BOOL ret = FALSE;

    TRACE( "%s\n", debugstr_w(path) );

    if (!RtlDosPathNameToNtPathName_U( path, &nt_name, NULL, NULL ))
    {
        SetLastError( ERROR_PATH_NOT_FOUND );
        return FALSE;
    }
    attr.Length = sizeof(attr);
    attr.RootDirectory = 0;
    attr.Attributes = OBJ_CASE_INSENSITIVE;
    attr.ObjectName = &nt_name;
    attr.SecurityDescriptor = NULL;
    attr.SecurityQualityOfService = NULL;

    if (!set_ntstatus( NtOpenFile( &handle, DELETE | SYNCHRONIZE, &attr, &io,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                   FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT )))
    {
        RtlFreeUnicodeString( &nt_name );
        return FALSE;
    }

    status = wine_nt_to_unix_file_name( &nt_name, &unix_name, FILE_OPEN, FALSE );
    if (status == STATUS_SUCCESS)
    {
        status = NtQueryAttributesFile( &attr, &info );
        if (status == STATUS_SUCCESS && (info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
                                        (info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            ret = (unlink( unix_name.Buffer ) != -1);
        else
            ret = (rmdir( unix_name.Buffer ) != -1);
        if (status == STATUS_SUCCESS && (info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
                                        !(info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            SetLastError( ERROR_DIRECTORY );
        else if (!ret) FILE_SetDosError();
        RtlFreeAnsiString( &unix_name );
    }
    else
        set_ntstatus( status );
    RtlFreeUnicodeString( &nt_name );

    NtClose( handle );
    return ret;
}


/***********************************************************************
 *           RemoveDirectoryA   (KERNEL32.@)
 */
BOOL WINAPI RemoveDirectoryA( LPCSTR path )
{
    WCHAR *pathW;

    if (!(pathW = FILE_name_AtoW( path, FALSE ))) return FALSE;
    return RemoveDirectoryW( pathW );
}


/***********************************************************************
=======
>>>>>>> github-desktop-wine-mirror/master
 *           GetSystemDirectoryW   (KERNEL32.@)
 *
 * See comment for GetWindowsDirectoryA.
 */
UINT WINAPI GetSystemDirectoryW( LPWSTR path, UINT count )
{
    UINT len = ARRAY_SIZE(system_dir);
    if (path && count >= len)
    {
        lstrcpyW( path, system_dir );
        len--;
    }
    return len;
}


/***********************************************************************
 *           GetSystemDirectoryA   (KERNEL32.@)
 *
 * See comment for GetWindowsDirectoryA.
 */
UINT WINAPI GetSystemDirectoryA( LPSTR path, UINT count )
{
    return copy_filename_WtoA( system_dir, path, count );
}


/***********************************************************************
 *           Wow64EnableWow64FsRedirection   (KERNEL32.@)
 *
 * Microsoft C++ Redistributable installers are depending on all %eax bits being set.
 */
DWORD /*BOOLEAN*/ WINAPI KERNEL32_Wow64EnableWow64FsRedirection( BOOLEAN enable )
{
    return set_ntstatus( RtlWow64EnableFsRedirection( enable ));
}


/***********************************************************************
 *           wine_get_unix_file_name (KERNEL32.@) Not a Windows API
 *
 * Return the full Unix file name for a given path.
 * Returned buffer must be freed by caller.
 */
char * CDECL wine_get_unix_file_name( LPCWSTR dosW )
{
    UNICODE_STRING nt_name;
    OBJECT_ATTRIBUTES attr;
    NTSTATUS status;
    ULONG size = 256;
    char *buffer;

    if (!RtlDosPathNameToNtPathName_U( dosW, &nt_name, NULL, NULL )) return NULL;
    InitializeObjectAttributes( &attr, &nt_name, 0, 0, NULL );
    for (;;)
    {
        if (!(buffer = HeapAlloc( GetProcessHeap(), 0, size )))
        {
            RtlFreeUnicodeString( &nt_name );
            return NULL;
        }
        status = wine_nt_to_unix_file_name( &attr, buffer, &size, FILE_OPEN_IF );
        if (status != STATUS_BUFFER_TOO_SMALL) break;
        HeapFree( GetProcessHeap(), 0, buffer );
    }
    RtlFreeUnicodeString( &nt_name );
    if (status && status != STATUS_NO_SUCH_FILE)
    {
        HeapFree( GetProcessHeap(), 0, buffer );
        SetLastError( RtlNtStatusToDosError( status ) );
        return NULL;
    }
    return buffer;
}


/***********************************************************************
 *           wine_get_dos_file_name (KERNEL32.@) Not a Windows API
 *
 * Return the full DOS file name for a given Unix path.
 * Returned buffer must be freed by caller.
 */
WCHAR * CDECL wine_get_dos_file_name( LPCSTR str )
{
    UNICODE_STRING nt_name;
    NTSTATUS status;
    WCHAR *buffer;
    ULONG len = strlen(str) + 1;

    if (str[0] != '/')  /* relative path name */
    {
        if (!(buffer = RtlAllocateHeap( GetProcessHeap(), 0, len * sizeof(WCHAR) ))) return NULL;
        MultiByteToWideChar( CP_UNIXCP, 0, str, len, buffer, len );
        status = RtlDosPathNameToNtPathName_U_WithStatus( buffer, &nt_name, NULL, NULL );
        RtlFreeHeap( GetProcessHeap(), 0, buffer );
        if (!set_ntstatus( status )) return NULL;
        buffer = nt_name.Buffer;
        len = nt_name.Length / sizeof(WCHAR) + 1;
    }
    else
    {
        len += 8;  /* \??\unix prefix */
        if (!(buffer = HeapAlloc( GetProcessHeap(), 0, len * sizeof(WCHAR) ))) return NULL;
        if (!set_ntstatus( wine_unix_to_nt_file_name( str, buffer, &len )))
        {
            HeapFree( GetProcessHeap(), 0, buffer );
            return NULL;
        }
    }
    if (buffer[5] == ':')
    {
        /* get rid of the \??\ prefix */
        /* FIXME: should implement RtlNtPathNameToDosPathName and use that instead */
        memmove( buffer, buffer + 4, (len - 4) * sizeof(WCHAR) );
    }
<<<<<<< HEAD
    else
        nt_name.Buffer[1] = '\\';
    return nt_name.Buffer;
}

/*************************************************************************
 *           CreateSymbolicLinkW   (KERNEL32.@)
 */
BOOLEAN WINAPI CreateSymbolicLinkW(LPCWSTR link, LPCWSTR target, DWORD flags)
{
    static INT struct_size = offsetof(REPARSE_DATA_BUFFER, SymbolicLinkReparseBuffer.PathBuffer[0]);
    static INT header_size = offsetof(REPARSE_DATA_BUFFER, GenericReparseBuffer);
    INT buffer_size, data_size, string_len, prefix_len;
    WCHAR *subst_dest, *print_dest, *string;
    REPARSE_DATA_BUFFER *buffer;
    LPWSTR target_path = NULL;
    BOOL is_relative, is_dir;
    int target_path_len = 0;
    UNICODE_STRING nt_name;
    BOOLEAN bret = FALSE;
    NTSTATUS status;
    HANDLE hlink;
    DWORD dwret;

    TRACE("(%s %s %d)\n", debugstr_w(link), debugstr_w(target), flags);

    is_relative = (RtlDetermineDosPathNameType_U( target ) == RELATIVE_PATH);
    is_dir = (flags & SYMBOLIC_LINK_FLAG_DIRECTORY);
    if (is_dir && !CreateDirectoryW( link, NULL ))
        return FALSE;
    hlink = CreateFileW( link, GENERIC_READ | GENERIC_WRITE, 0, 0,
                         is_dir ? OPEN_EXISTING : CREATE_NEW,
                         FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, 0 );
    if (hlink == INVALID_HANDLE_VALUE)
        goto cleanup;
    if (is_relative)
    {
        UNICODE_STRING nt_path;
        int len;

        status = RtlDosPathNameToNtPathName_U_WithStatus( link, &nt_path, NULL, NULL );
        if (status != STATUS_SUCCESS)
        {
            SetLastError( RtlNtStatusToDosError(status) );
            goto cleanup;
        }
        /* obtain the path of the link */
        for (; nt_path.Length > 0; nt_path.Length -= sizeof(WCHAR))
        {
            WCHAR c = nt_path.Buffer[nt_path.Length/sizeof(WCHAR)];
            if (c == '/' || c == '\\')
            {
                nt_path.Length += sizeof(WCHAR);
                break;
            }
        }
        /* append the target to the link path */
        target_path_len = nt_path.Length / sizeof(WCHAR);
        len = target_path_len + (strlenW( target ) + 1);
        target_path = HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, len*sizeof(WCHAR) );
        lstrcpynW( target_path, nt_path.Buffer, target_path_len+1 );
        target_path[target_path_len+1] = 0;
        lstrcatW( target_path, target );
        RtlFreeUnicodeString( &nt_path );
    }
    else
        target_path = (LPWSTR)target;
    status = RtlDosPathNameToNtPathName_U_WithStatus( target_path, &nt_name, NULL, NULL );
    if (status != STATUS_SUCCESS)
    {
        SetLastError( RtlNtStatusToDosError(status) );
        goto cleanup;
    }
    if (is_relative && strncmpW( target_path, nt_name.Buffer, target_path_len ) != 0)
    {
        SetLastError( RtlNtStatusToDosError(status) );
        goto cleanup;
    }
    prefix_len = is_relative ? 0 : strlen("\\??\\");
    string = &nt_name.Buffer[target_path_len];
    string_len = lstrlenW( &string[prefix_len] );
    data_size = (prefix_len + 2 * string_len + 2) * sizeof(WCHAR);
    buffer_size = struct_size + data_size;
    buffer = HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, buffer_size );
    buffer->ReparseTag = IO_REPARSE_TAG_SYMLINK;
    buffer->ReparseDataLength = struct_size - header_size + data_size;
    buffer->SymbolicLinkReparseBuffer.SubstituteNameLength = (prefix_len + string_len) * sizeof(WCHAR);
    buffer->SymbolicLinkReparseBuffer.PrintNameOffset = (prefix_len + string_len + 1) * sizeof(WCHAR);
    buffer->SymbolicLinkReparseBuffer.PrintNameLength = string_len * sizeof(WCHAR);
    buffer->SymbolicLinkReparseBuffer.Flags = is_relative ? SYMLINK_FLAG_RELATIVE : 0;
    subst_dest = &buffer->SymbolicLinkReparseBuffer.PathBuffer[0];
    print_dest = &buffer->SymbolicLinkReparseBuffer.PathBuffer[prefix_len + string_len + 1];
    lstrcpyW( subst_dest, string );
    lstrcpyW( print_dest, &string[prefix_len] );
    RtlFreeUnicodeString( &nt_name );
    bret = DeviceIoControl( hlink, FSCTL_SET_REPARSE_POINT, (LPVOID)buffer, buffer_size, NULL, 0,
                            &dwret, 0 );
    HeapFree( GetProcessHeap(), 0, buffer );

cleanup:
    CloseHandle( hlink );
    if (!bret)
    {
        if (is_dir)
            RemoveDirectoryW( link );
        else
            DeleteFileW( link );
    }
    if (is_relative) HeapFree( GetProcessHeap(), 0, target_path );
    return bret;
=======
    else buffer[1] = '\\';
    return buffer;
>>>>>>> github-desktop-wine-mirror/master
}

/*************************************************************************
 *           CreateSymbolicLinkA   (KERNEL32.@)
 */
BOOLEAN WINAPI CreateSymbolicLinkA(LPCSTR link, LPCSTR target, DWORD flags)
{
<<<<<<< HEAD
    WCHAR *targetW, *linkW;
    BOOL ret;

    TRACE("(%s %s %d)\n", debugstr_a(link), debugstr_a(target), flags);

    if (!(linkW = FILE_name_AtoW( link, TRUE )))
    {
        return FALSE;
    }
    if (!(targetW = FILE_name_AtoW( target, TRUE )))
    {
        HeapFree( GetProcessHeap(), 0, linkW );
        return FALSE;
    }
    ret = CreateSymbolicLinkW( linkW, targetW, flags );
    HeapFree( GetProcessHeap(), 0, linkW );
    HeapFree( GetProcessHeap(), 0, targetW );
    return ret;
=======
    FIXME("(%s %s %ld): stub\n", debugstr_a(link), debugstr_a(target), flags);
    return TRUE;
>>>>>>> github-desktop-wine-mirror/master
}

/*************************************************************************
 *           CreateHardLinkTransactedA   (KERNEL32.@)
 */
BOOL WINAPI CreateHardLinkTransactedA(LPCSTR link, LPCSTR target, LPSECURITY_ATTRIBUTES sa, HANDLE transaction)
{
    FIXME("(%s %s %p %p): stub\n", debugstr_a(link), debugstr_a(target), sa, transaction);
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

/*************************************************************************
 *           CreateHardLinkTransactedW   (KERNEL32.@)
 */
BOOL WINAPI CreateHardLinkTransactedW(LPCWSTR link, LPCWSTR target, LPSECURITY_ATTRIBUTES sa, HANDLE transaction)
{
    FIXME("(%s %s %p %p): stub\n", debugstr_w(link), debugstr_w(target), sa, transaction);
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

/*************************************************************************
 *           CheckNameLegalDOS8Dot3A   (KERNEL32.@)
 */
BOOL WINAPI CheckNameLegalDOS8Dot3A(const char *name, char *oemname, DWORD oemname_len,
        BOOL *contains_spaces, BOOL *is_legal)
{
    WCHAR *nameW;

    TRACE("(%s %p %lu %p %p)\n", name, oemname,
            oemname_len, contains_spaces, is_legal);

    if (!name || !is_legal)
        return FALSE;

    if (!(nameW = FILE_name_AtoW( name, FALSE ))) return FALSE;

    return CheckNameLegalDOS8Dot3W( nameW, oemname, oemname_len, contains_spaces, is_legal );
}

/*************************************************************************
 *           CheckNameLegalDOS8Dot3W   (KERNEL32.@)
 */
BOOL WINAPI CheckNameLegalDOS8Dot3W(const WCHAR *name, char *oemname, DWORD oemname_len,
        BOOL *contains_spaces_ret, BOOL *is_legal)
{
    OEM_STRING oem_str;
    UNICODE_STRING nameW;
    BOOLEAN contains_spaces;

    TRACE("(%s %p %lu %p %p)\n", wine_dbgstr_w(name), oemname,
          oemname_len, contains_spaces_ret, is_legal);

    if (!name || !is_legal)
        return FALSE;

    RtlInitUnicodeString( &nameW, name );

    if (oemname) {
        oem_str.Length = oemname_len;
        oem_str.MaximumLength = oemname_len;
        oem_str.Buffer = oemname;
    }

    *is_legal = RtlIsNameLegalDOS8Dot3( &nameW, oemname ? &oem_str : NULL, &contains_spaces );
    if (contains_spaces_ret) *contains_spaces_ret = contains_spaces;

    return TRUE;
}

/*************************************************************************
 *           SetSearchPathMode   (KERNEL32.@)
 */
BOOL WINAPI SetSearchPathMode( DWORD flags )
{
    return set_ntstatus( RtlSetSearchPathMode( flags ));
}
