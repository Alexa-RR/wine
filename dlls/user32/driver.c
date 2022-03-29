/*
 * USER driver support
 *
 * Copyright 2000, 2005 Alexandre Julliard
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

#include <stdarg.h>
#include <stdio.h>
#include <wchar.h>

#include "user_private.h"
#include "winnls.h"
#include "wine/debug.h"
#include "controls.h"

WINE_DEFAULT_DEBUG_CHANNEL(user);

static struct user_driver_funcs null_driver, lazy_load_driver;

const struct user_driver_funcs *USER_Driver = &lazy_load_driver;

/* load the graphics driver */
static const struct user_driver_funcs *load_driver(void)
{
    wait_graphics_driver_ready();
    if (USER_Driver == &lazy_load_driver)
    {
<<<<<<< HEAD
        USEROBJECTFLAGS flags;
        HWINSTA winstation;

        winstation = GetProcessWindowStation();
        if (!GetUserObjectInformationA(winstation, UOI_FLAGS, &flags, sizeof(flags), NULL)
            || (flags.dwFlags & WSF_VISIBLE))
            driver->pCreateWindow = nodrv_CreateWindow;
    }
    else if (graphics_driver)
    {
#define GET_USER_FUNC(name) \
    do { if ((ptr = GetProcAddress( graphics_driver, #name ))) driver->p##name = ptr; } while(0)

        GET_USER_FUNC(ActivateKeyboardLayout);
        GET_USER_FUNC(Beep);
        GET_USER_FUNC(GetKeyNameText);
        GET_USER_FUNC(GetKeyboardLayout);
        GET_USER_FUNC(GetKeyboardLayoutList);
        GET_USER_FUNC(GetKeyboardLayoutName);
        GET_USER_FUNC(LoadKeyboardLayout);
        GET_USER_FUNC(MapVirtualKeyEx);
        GET_USER_FUNC(RegisterHotKey);
        GET_USER_FUNC(ToUnicodeEx);
        GET_USER_FUNC(UnloadKeyboardLayout);
        GET_USER_FUNC(UnregisterHotKey);
        GET_USER_FUNC(VkKeyScanEx);
        GET_USER_FUNC(DestroyCursorIcon);
        GET_USER_FUNC(SetCursor);
        GET_USER_FUNC(GetCursorPos);
        GET_USER_FUNC(SetCursorPos);
        GET_USER_FUNC(ClipCursor);
        GET_USER_FUNC(UpdateClipboard);
        GET_USER_FUNC(ChangeDisplaySettingsEx);
        GET_USER_FUNC(EnumDisplayMonitors);
        GET_USER_FUNC(EnumDisplaySettingsEx);
        GET_USER_FUNC(GetMonitorInfo);
        GET_USER_FUNC(CreateDesktopWindow);
        GET_USER_FUNC(CreateWindow);
        GET_USER_FUNC(DestroyWindow);
        GET_USER_FUNC(FlashWindowEx);
        GET_USER_FUNC(GetDC);
        GET_USER_FUNC(MsgWaitForMultipleObjectsEx);
        GET_USER_FUNC(ReleaseDC);
        GET_USER_FUNC(ScrollDC);
        GET_USER_FUNC(SetActiveWindow);
        GET_USER_FUNC(SetCapture);
        GET_USER_FUNC(SetFocus);
        GET_USER_FUNC(SetLayeredWindowAttributes);
        GET_USER_FUNC(SetParent);
        GET_USER_FUNC(SetWindowRgn);
        GET_USER_FUNC(SetWindowIcon);
        GET_USER_FUNC(SetWindowStyle);
        GET_USER_FUNC(SetWindowText);
        GET_USER_FUNC(ShowWindow);
        GET_USER_FUNC(SysCommand);
        GET_USER_FUNC(UpdateLayeredWindow);
        GET_USER_FUNC(WindowMessage);
        GET_USER_FUNC(WindowPosChanging);
        GET_USER_FUNC(WindowPosChanged);
        GET_USER_FUNC(SystemParametersInfo);
        GET_USER_FUNC(UpdateCandidatePos);
        GET_USER_FUNC(ThreadDetach);
#undef GET_USER_FUNC
=======
        static struct user_driver_funcs empty_funcs;
        WARN( "failed to load the display driver, falling back to null driver\n" );
        __wine_set_user_driver( &empty_funcs, WINE_GDI_DRIVER_VERSION );
>>>>>>> master
    }

    return USER_Driver;
}

/* unload the graphics driver on process exit */
void USER_unload_driver(void)
{
    struct user_driver_funcs *prev;
    __wine_set_display_driver( &null_driver, WINE_GDI_DRIVER_VERSION );
    /* make sure we don't try to call the driver after it has been detached */
    prev = InterlockedExchangePointer( (void **)&USER_Driver, &null_driver );
    if (prev != &lazy_load_driver && prev != &null_driver)
        HeapFree( GetProcessHeap(), 0, prev );
}


/**********************************************************************
 * Null user driver
 *
 * These are fallbacks for entry points that are not implemented in the real driver.
 */

<<<<<<< HEAD
static HKL CDECL nulldrv_ActivateKeyboardLayout( HKL layout, UINT flags )
{
    return 0;
}

static void CDECL nulldrv_Beep(void)
{
}

static UINT CDECL nulldrv_GetKeyboardLayoutList( INT size, HKL *layouts )
{
    INT count = 0;
    ULONG_PTR baselayout;
    LANGID langid;

    baselayout = GetUserDefaultLCID();
    langid = PRIMARYLANGID(LANGIDFROMLCID(baselayout));
    if (langid == LANG_CHINESE || langid == LANG_JAPANESE || langid == LANG_KOREAN)
        baselayout = MAKELONG( baselayout, 0xe001 ); /* IME */
    else
        baselayout |= baselayout << 16;

    /* make sure our base layout is on the list */
    if (baselayout != 0)
    {
        if (size && layouts)
        {
            if (count < size)
            {
                layouts[count] = (HKL)baselayout;
                count++;
            }
        }
        else
            count++;
    }

    return count;
}

static INT CDECL nulldrv_GetKeyNameText( LONG lparam, LPWSTR buffer, INT size )
{
    return 0;
}

static HKL CDECL nulldrv_GetKeyboardLayout( DWORD thread_id )
{
    return 0;
}

static BOOL CDECL nulldrv_GetKeyboardLayoutName( LPWSTR name )
{
    return FALSE;
}

static HKL CDECL nulldrv_LoadKeyboardLayout( LPCWSTR name, UINT flags )
{
    return 0;
}

static UINT CDECL nulldrv_MapVirtualKeyEx( UINT code, UINT type, HKL layout )
{
    return 0;
}

static BOOL CDECL nulldrv_RegisterHotKey( HWND hwnd, UINT modifiers, UINT vk )
{
    return TRUE;
}

static INT CDECL nulldrv_ToUnicodeEx( UINT virt, UINT scan, const BYTE *state, LPWSTR str,
                                      int size, UINT flags, HKL layout )
{
    return 0;
}

static BOOL CDECL nulldrv_UnloadKeyboardLayout( HKL layout )
{
    return 0;
}

static void CDECL nulldrv_UnregisterHotKey( HWND hwnd, UINT modifiers, UINT vk )
{
}

static SHORT CDECL nulldrv_VkKeyScanEx( WCHAR ch, HKL layout )
{
    return -1;
}

static void CDECL nulldrv_DestroyCursorIcon( HCURSOR cursor )
{
}

static void CDECL nulldrv_SetCursor( HCURSOR cursor )
{
}

static BOOL CDECL nulldrv_GetCursorPos( LPPOINT pt )
{
    return FALSE;
}

=======
>>>>>>> master
static BOOL CDECL nulldrv_SetCursorPos( INT x, INT y )
{
    return TRUE;
}

static void CDECL nulldrv_UpdateClipboard(void)
{
}

static DWORD CDECL nulldrv_MsgWaitForMultipleObjectsEx( DWORD count, const HANDLE *handles, DWORD timeout,
                                                        DWORD mask, DWORD flags )
{
    if (!count && !timeout) return WAIT_TIMEOUT;
    return WaitForMultipleObjectsEx( count, handles, flags & MWMO_WAITALL,
                                     timeout, flags & MWMO_ALERTABLE );
}

<<<<<<< HEAD
static void CDECL nulldrv_ReleaseDC( HWND hwnd, HDC hdc )
{
}

static BOOL CDECL nulldrv_ScrollDC( HDC hdc, INT dx, INT dy, HRGN update )
{
    RECT rect;

    GetClipBox( hdc, &rect );
    return BitBlt( hdc, rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top,
                   hdc, rect.left - dx, rect.top - dy, SRCCOPY );
}

static void CDECL nulldrv_SetActiveWindow( HWND hwnd )
{
}

static void CDECL nulldrv_SetCapture( HWND hwnd, UINT flags )
{
}

static void CDECL nulldrv_SetFocus( HWND hwnd )
{
}

static void CDECL nulldrv_SetLayeredWindowAttributes( HWND hwnd, COLORREF key, BYTE alpha, DWORD flags )
{
}

static void CDECL nulldrv_SetParent( HWND hwnd, HWND parent, HWND old_parent )
{
}

static void CDECL nulldrv_SetWindowRgn( HWND hwnd, HRGN hrgn, BOOL redraw )
{
}

=======
>>>>>>> master
static void CDECL nulldrv_SetWindowIcon( HWND hwnd, UINT type, HICON icon )
{
}

static void CDECL nulldrv_SetWindowText( HWND hwnd, LPCWSTR text )
{
}

static LRESULT CDECL nulldrv_SysCommand( HWND hwnd, WPARAM wparam, LPARAM lparam )
{
    return -1;
}

<<<<<<< HEAD
static BOOL CDECL nulldrv_UpdateLayeredWindow( HWND hwnd, const UPDATELAYEREDWINDOWINFO *info,
                                               const RECT *window_rect )
{
    return TRUE;
}

static LRESULT CDECL nulldrv_WindowMessage( HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam )
{
    return 0;
}

static void CDECL nulldrv_WindowPosChanging( HWND hwnd, HWND insert_after, UINT swp_flags,
                                             const RECT *window_rect, const RECT *client_rect,
                                             RECT *visible_rect, struct window_surface **surface )
{
}

static void CDECL nulldrv_WindowPosChanged( HWND hwnd, HWND insert_after, UINT swp_flags,
                                            const RECT *window_rect, const RECT *client_rect,
                                            const RECT *visible_rect, const RECT *valid_rects,
                                            struct window_surface *surface )
{
}

static BOOL CDECL nulldrv_SystemParametersInfo( UINT action, UINT int_param, void *ptr_param, UINT flags )
{
    return FALSE;
}

static void CDECL nulldrv_UpdateCandidatePos( HWND hwnd, const RECT *caret_rect )
{
}

static void CDECL nulldrv_ThreadDetach( void )
{
}

static USER_DRIVER null_driver =
{
    /* keyboard functions */
    nulldrv_ActivateKeyboardLayout,
    nulldrv_Beep,
    nulldrv_GetKeyNameText,
    nulldrv_GetKeyboardLayout,
    nulldrv_GetKeyboardLayoutList,
    nulldrv_GetKeyboardLayoutName,
    nulldrv_LoadKeyboardLayout,
    nulldrv_MapVirtualKeyEx,
    nulldrv_RegisterHotKey,
    nulldrv_ToUnicodeEx,
    nulldrv_UnloadKeyboardLayout,
    nulldrv_UnregisterHotKey,
    nulldrv_VkKeyScanEx,
    /* cursor/icon functions */
    nulldrv_DestroyCursorIcon,
    nulldrv_SetCursor,
    nulldrv_GetCursorPos,
    nulldrv_SetCursorPos,
    nulldrv_ClipCursor,
    /* clipboard functions */
    nulldrv_UpdateClipboard,
    /* display modes */
    nulldrv_ChangeDisplaySettingsEx,
    nulldrv_EnumDisplayMonitors,
    nulldrv_EnumDisplaySettingsEx,
    nulldrv_GetMonitorInfo,
    /* windowing functions */
    nulldrv_CreateDesktopWindow,
    nulldrv_CreateWindow,
    nulldrv_DestroyWindow,
    nulldrv_FlashWindowEx,
    nulldrv_GetDC,
    nulldrv_MsgWaitForMultipleObjectsEx,
    nulldrv_ReleaseDC,
    nulldrv_ScrollDC,
    nulldrv_SetActiveWindow,
    nulldrv_SetCapture,
    nulldrv_SetFocus,
    nulldrv_SetLayeredWindowAttributes,
    nulldrv_SetParent,
    nulldrv_SetWindowRgn,
    nulldrv_SetWindowIcon,
    nulldrv_SetWindowStyle,
    nulldrv_SetWindowText,
    nulldrv_ShowWindow,
    nulldrv_SysCommand,
    nulldrv_UpdateLayeredWindow,
    nulldrv_WindowMessage,
    nulldrv_WindowPosChanging,
    nulldrv_WindowPosChanged,
    /* system parameters */
    nulldrv_SystemParametersInfo,
    /* candidate pos functions */
    nulldrv_UpdateCandidatePos,
    /* thread management */
    nulldrv_ThreadDetach
};

=======
>>>>>>> master

/**********************************************************************
 * Lazy loading user driver
 *
 * Initial driver used before another driver is loaded.
 * Each entry point simply loads the real driver and chains to it.
 */

static BOOL CDECL loaderdrv_SetCursorPos( INT x, INT y )
{
    return load_driver()->pSetCursorPos( x, y );
}

static void CDECL loaderdrv_UpdateClipboard(void)
{
    load_driver()->pUpdateClipboard();
}

<<<<<<< HEAD
static LONG CDECL loaderdrv_ChangeDisplaySettingsEx( LPCWSTR name, LPDEVMODEW mode, HWND hwnd,
                                                     DWORD flags, LPVOID lparam )
{
    return load_driver()->pChangeDisplaySettingsEx( name, mode, hwnd, flags, lparam );
}

static BOOL CDECL loaderdrv_EnumDisplayMonitors( HDC hdc, LPRECT rect, MONITORENUMPROC proc, LPARAM lp )
{
    return load_driver()->pEnumDisplayMonitors( hdc, rect, proc, lp );
}

static BOOL CDECL loaderdrv_EnumDisplaySettingsEx( LPCWSTR name, DWORD num, LPDEVMODEW mode, DWORD flags )
{
    return load_driver()->pEnumDisplaySettingsEx( name, num, mode, flags );
}

static BOOL CDECL loaderdrv_GetMonitorInfo( HMONITOR handle, LPMONITORINFO info )
{
    return load_driver()->pGetMonitorInfo( handle, info );
}

static BOOL CDECL loaderdrv_CreateDesktopWindow( HWND hwnd )
{
    return load_driver()->pCreateDesktopWindow( hwnd );
}

static BOOL CDECL loaderdrv_CreateWindow( HWND hwnd )
{
    return load_driver()->pCreateWindow( hwnd );
}

static void CDECL loaderdrv_FlashWindowEx( FLASHWINFO *info )
{
    load_driver()->pFlashWindowEx( info );
}

static void CDECL loaderdrv_GetDC( HDC hdc, HWND hwnd, HWND top_win, const RECT *win_rect,
                                   const RECT *top_rect, DWORD flags )
{
    load_driver()->pGetDC( hdc, hwnd, top_win, win_rect, top_rect, flags );
}

static void CDECL loaderdrv_SetLayeredWindowAttributes( HWND hwnd, COLORREF key, BYTE alpha, DWORD flags )
{
    load_driver()->pSetLayeredWindowAttributes( hwnd, key, alpha, flags );
}

static void CDECL loaderdrv_SetWindowRgn( HWND hwnd, HRGN hrgn, BOOL redraw )
{
    load_driver()->pSetWindowRgn( hwnd, hrgn, redraw );
}

static BOOL CDECL loaderdrv_UpdateLayeredWindow( HWND hwnd, const UPDATELAYEREDWINDOWINFO *info,
                                                 const RECT *window_rect )
{
    return load_driver()->pUpdateLayeredWindow( hwnd, info, window_rect );
}

static void CDECL loaderdrv_UpdateCandidatePos( HWND hwnd, const RECT *caret_rect )
{
    load_driver()->pUpdateCandidatePos( hwnd, caret_rect );
}

static USER_DRIVER lazy_load_driver =
=======
static struct user_driver_funcs lazy_load_driver =
>>>>>>> master
{
    { NULL },
    /* keyboard functions */
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    /* cursor/icon functions */
    NULL,
    NULL,
    NULL,
    loaderdrv_SetCursorPos,
    NULL,
    /* clipboard functions */
    loaderdrv_UpdateClipboard,
    /* display modes */
    NULL,
    NULL,
    NULL,
    /* windowing functions */
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    nulldrv_MsgWaitForMultipleObjectsEx,
<<<<<<< HEAD
    nulldrv_ReleaseDC,
    nulldrv_ScrollDC,
    nulldrv_SetActiveWindow,
    nulldrv_SetCapture,
    nulldrv_SetFocus,
    loaderdrv_SetLayeredWindowAttributes,
    nulldrv_SetParent,
    loaderdrv_SetWindowRgn,
=======
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
>>>>>>> master
    nulldrv_SetWindowIcon,
    NULL,
    nulldrv_SetWindowText,
    NULL,
    nulldrv_SysCommand,
    NULL,
    NULL,
    NULL,
    NULL,
    /* system parameters */
<<<<<<< HEAD
    nulldrv_SystemParametersInfo,
    /* candidate pos functions */
    loaderdrv_UpdateCandidatePos,
=======
    NULL,
    /* vulkan support */
    NULL,
    /* opengl support */
    NULL,
>>>>>>> master
    /* thread management */
    NULL,
};

void CDECL __wine_set_user_driver( const struct user_driver_funcs *funcs, UINT version )
{
    struct user_driver_funcs *driver, *prev;

    if (version != WINE_GDI_DRIVER_VERSION)
    {
        ERR( "version mismatch, driver wants %u but user32 has %u\n", version, WINE_GDI_DRIVER_VERSION );
        return;
    }

    driver = HeapAlloc( GetProcessHeap(), 0, sizeof(*driver) );
    *driver = *funcs;

#define SET_USER_FUNC(name) \
    do { if (!driver->p##name) driver->p##name = nulldrv_##name; } while(0)

    SET_USER_FUNC(SetCursorPos);
    SET_USER_FUNC(UpdateClipboard);
    SET_USER_FUNC(MsgWaitForMultipleObjectsEx);
    SET_USER_FUNC(SetWindowIcon);
    SET_USER_FUNC(SetWindowText);
    SET_USER_FUNC(SysCommand);
#undef SET_USER_FUNC

    prev = InterlockedCompareExchangePointer( (void **)&USER_Driver, driver, &lazy_load_driver );
    if (prev != &lazy_load_driver)
    {
        /* another thread beat us to it */
        HeapFree( GetProcessHeap(), 0, driver );
        driver = prev;
    }

    __wine_set_display_driver( driver, version );
}
