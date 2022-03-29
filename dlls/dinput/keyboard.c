/*		DirectInput Keyboard device
 *
 * Copyright 1998 Marcus Meissner
 * Copyright 1998,1999 Lionel Ulmer
 * Copyright 2000-2001 TransGaming Technologies Inc.
 * Copyright 2005 Raphael Junqueira
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
#include <string.h>
#include "windef.h"
#include "winbase.h"
#include "winuser.h"
#include "winerror.h"
#include "dinput.h"

#include "dinput_private.h"
#include "device_private.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(dinput);

static const struct dinput_device_vtbl keyboard_vtbl;

struct keyboard
{
    struct dinput_device base;
};

static inline struct keyboard *impl_from_IDirectInputDevice8W( IDirectInputDevice8W *iface )
{
    return CONTAINING_RECORD( CONTAINING_RECORD( iface, struct dinput_device, IDirectInputDevice8W_iface ),
                              struct keyboard, base );
}

static BYTE map_dik_code(DWORD scanCode, DWORD vkCode, DWORD subType, DWORD version)
{
    if (!scanCode && version < 0x0800)
        scanCode = MapVirtualKeyW(vkCode, MAPVK_VK_TO_VSC);

    if (subType == DIDEVTYPEKEYBOARD_JAPAN106)
    {
        switch (scanCode)
        {
        case 0x0d: /* ^ */
            scanCode = DIK_CIRCUMFLEX;
            break;
        case 0x1a: /* @ */
            scanCode = DIK_AT;
            break;
        case 0x1b: /* [ */
            scanCode = DIK_LBRACKET;
            break;
        case 0x28: /* : */
            scanCode = DIK_COLON;
            break;
        case 0x29: /* Hankaku/Zenkaku */
            scanCode = DIK_KANJI;
            break;
        case 0x2b: /* ] */
            scanCode = DIK_RBRACKET;
            break;
        case 0x73: /* \ */
            scanCode = DIK_BACKSLASH;
            break;
        }
    }
    if (scanCode & 0x100) scanCode |= 0x80;
    return (BYTE)scanCode;
}

int dinput_keyboard_hook( IDirectInputDevice8W *iface, WPARAM wparam, LPARAM lparam )
{
    struct keyboard *impl = impl_from_IDirectInputDevice8W( iface );
    BYTE new_diks, subtype = GET_DIDEVICE_SUBTYPE( impl->base.instance.dwDevType );
    int dik_code, ret = impl->base.dwCoopLevel & DISCL_EXCLUSIVE;
    KBDLLHOOKSTRUCT *hook = (KBDLLHOOKSTRUCT *)lparam;
    DWORD scan_code;

    if (wparam != WM_KEYDOWN && wparam != WM_KEYUP &&
        wparam != WM_SYSKEYDOWN && wparam != WM_SYSKEYUP)
        return 0;

    TRACE( "iface %p, wparam %#Ix, lparam %#Ix, vkCode %#lx, scanCode %#lx.\n", iface, wparam,
           lparam, hook->vkCode, hook->scanCode );

    switch (hook->vkCode)
    {
        /* R-Shift is special - it is an extended key with separate scan code */
        case VK_RSHIFT  : dik_code = DIK_RSHIFT; break;
        case VK_PAUSE   : dik_code = DIK_PAUSE; break;
        case VK_NUMLOCK : dik_code = DIK_NUMLOCK; break;
        case VK_SUBTRACT: dik_code = DIK_SUBTRACT; break;
        default:
            scan_code = hook->scanCode & 0xff;
            if (hook->flags & LLKHF_EXTENDED) scan_code |= 0x100;
            dik_code = map_dik_code( scan_code, hook->vkCode, subtype, impl->base.dinput->dwVersion );
    }
    new_diks = hook->flags & LLKHF_UP ? 0 : 0x80;

    /* returns now if key event already known */
    if (new_diks == impl->base.device_state[dik_code]) return ret;

    impl->base.device_state[dik_code] = new_diks;
    TRACE( " setting key %02x to %02x\n", dik_code, impl->base.device_state[dik_code] );

    EnterCriticalSection( &impl->base.crit );
    queue_event( iface, DIDFT_MAKEINSTANCE( dik_code ) | DIDFT_PSHBUTTON, new_diks,
                 GetCurrentTime(), impl->base.dinput->evsequence++ );
    if (impl->base.hEvent) SetEvent( impl->base.hEvent );
    LeaveCriticalSection( &impl->base.crit );

    return ret;
}

static DWORD get_keyboard_subtype(void)
{
    INT kbd_type, kbd_subtype, dev_subtype;
    kbd_type = GetKeyboardType(0);
    kbd_subtype = GetKeyboardType(1);

    if (kbd_type == 4 || (kbd_type == 7 && kbd_subtype == 0))
        dev_subtype = DIDEVTYPEKEYBOARD_PCENH;
    else if (kbd_type == 7 && kbd_subtype == 2)
        dev_subtype = DIDEVTYPEKEYBOARD_JAPAN106;
    else {
        FIXME( "Unknown keyboard type %d, subtype %d\n", kbd_type, kbd_subtype );
        dev_subtype = DIDEVTYPEKEYBOARD_PCENH;
    }
    return dev_subtype;
}

HRESULT keyboard_enum_device( DWORD type, DWORD flags, DIDEVICEINSTANCEW *instance, DWORD version )
{
    BYTE subtype = get_keyboard_subtype();
    DWORD size;

    TRACE( "type %#lx, flags %#lx, instance %p, version %#lx.\n", type, flags, instance, version );

    size = instance->dwSize;
    memset( instance, 0, size );
    instance->dwSize = size;
    instance->guidInstance = GUID_SysKeyboard;
    instance->guidProduct = GUID_SysKeyboard;
    if (version >= 0x0800) instance->dwDevType = DI8DEVTYPE_KEYBOARD | (subtype << 8);
    else instance->dwDevType = DIDEVTYPE_KEYBOARD | (subtype << 8);
    MultiByteToWideChar( CP_ACP, 0, "Keyboard", -1, instance->tszInstanceName, MAX_PATH );
    MultiByteToWideChar( CP_ACP, 0, "Wine Keyboard", -1, instance->tszProductName, MAX_PATH );

    return DI_OK;
}

HRESULT keyboard_create_device( struct dinput *dinput, const GUID *guid, IDirectInputDevice8W **out )
{
    struct keyboard *impl;
    HRESULT hr;

    TRACE( "dinput %p, guid %s, out %p.\n", dinput, debugstr_guid( guid ), out );

    *out = NULL;
    if (!IsEqualGUID( &GUID_SysKeyboard, guid )) return DIERR_DEVICENOTREG;

    if (FAILED(hr = dinput_device_alloc( sizeof(struct keyboard), &keyboard_vtbl, guid, dinput, (void **)&impl )))
        return hr;
    impl->base.crit.DebugInfo->Spare[0] = (DWORD_PTR)(__FILE__ ": struct keyboard*->base.crit");

    keyboard_enum_device( 0, 0, &impl->base.instance, dinput->dwVersion );
    impl->base.caps.dwDevType = impl->base.instance.dwDevType;
    impl->base.caps.dwFirmwareRevision = 100;
    impl->base.caps.dwHardwareRevision = 100;

    if (FAILED(hr = dinput_device_init( &impl->base.IDirectInputDevice8W_iface )))
    {
        IDirectInputDevice_Release( &impl->base.IDirectInputDevice8W_iface );
        return hr;
    }

    *out = &impl->base.IDirectInputDevice8W_iface;
    return DI_OK;
}

static HRESULT keyboard_poll( IDirectInputDevice8W *iface )
{
    check_dinput_events();
    return DI_OK;
}

static HRESULT keyboard_acquire( IDirectInputDevice8W *iface )
{
    return DI_OK;
}

static HRESULT keyboard_unacquire( IDirectInputDevice8W *iface )
{
    struct keyboard *impl = impl_from_IDirectInputDevice8W( iface );
    memset( impl->base.device_state, 0, sizeof(impl->base.device_state) );
    return DI_OK;
}

static BOOL try_enum_object( const DIPROPHEADER *filter, DWORD flags, LPDIENUMDEVICEOBJECTSCALLBACKW callback,
                             DIDEVICEOBJECTINSTANCEW *instance, void *data )
{
    if (flags != DIDFT_ALL && !(flags & DIDFT_GETTYPE( instance->dwType ))) return DIENUM_CONTINUE;

    switch (filter->dwHow)
    {
    case DIPH_DEVICE:
        return callback( instance, data );
    case DIPH_BYOFFSET:
        if (filter->dwObj != instance->dwOfs) return DIENUM_CONTINUE;
        return callback( instance, data );
    case DIPH_BYID:
        if ((filter->dwObj & 0x00ffffff) != (instance->dwType & 0x00ffffff)) return DIENUM_CONTINUE;
        return callback( instance, data );
    }

    return DIENUM_CONTINUE;
}

static HRESULT keyboard_enum_objects( IDirectInputDevice8W *iface, const DIPROPHEADER *filter,
                                      DWORD flags, LPDIENUMDEVICEOBJECTSCALLBACKW callback, void *context )
{
    struct keyboard *impl = impl_from_IDirectInputDevice8W( iface );
    BYTE subtype = GET_DIDEVICE_SUBTYPE( impl->base.instance.dwDevType );
    DIDEVICEOBJECTINSTANCEW instance =
    {
        .dwSize = sizeof(DIDEVICEOBJECTINSTANCEW),
        .guidType = GUID_Key,
        .dwOfs = DIK_ESCAPE,
        .dwType = DIDFT_PSHBUTTON | DIDFT_MAKEINSTANCE( DIK_ESCAPE ),
    };
    DWORD i, dik;
    BOOL ret;

    for (i = 0; i < 512; ++i)
    {
        if (!GetKeyNameTextW( i << 16, instance.tszName, ARRAY_SIZE(instance.tszName) )) continue;
        if (!(dik = map_dik_code( i, 0, subtype, impl->base.dinput->dwVersion ))) continue;
        instance.dwOfs = dik;
        instance.dwType = DIDFT_PSHBUTTON | DIDFT_MAKEINSTANCE( dik );
        ret = try_enum_object( filter, flags, callback, &instance, context );
        if (ret != DIENUM_CONTINUE) return DIENUM_STOP;
    }

    return DIENUM_CONTINUE;
}

static HRESULT keyboard_get_property( IDirectInputDevice8W *iface, DWORD property,
                                      DIPROPHEADER *header, const DIDEVICEOBJECTINSTANCEW *instance )
{
    switch (property)
    {
    case (DWORD_PTR)DIPROP_KEYNAME:
    {
        DIPROPSTRING *value = (DIPROPSTRING *)header;
        lstrcpynW( value->wsz, instance->tszName, ARRAY_SIZE(value->wsz) );
        return DI_OK;
    }
    }
    return DIERR_UNSUPPORTED;
}

<<<<<<< HEAD
const struct dinput_device keyboard_device = {
  "Wine keyboard driver",
  keyboarddev_enum_deviceA,
  keyboarddev_enum_deviceW,
  keyboarddev_create_device
};

static HRESULT WINAPI SysKeyboardWImpl_GetDeviceState(LPDIRECTINPUTDEVICE8W iface, DWORD len, LPVOID ptr)
{
    SysKeyboardImpl *This = impl_from_IDirectInputDevice8W(iface);
    TRACE("(%p)->(%d,%p)\n", This, len, ptr);

    if (!This->base.acquired) return DIERR_NOTACQUIRED;

    if (len != This->base.data_format.user_df->dwDataSize )
        return DIERR_INVALIDPARAM;

    check_dinput_events();

    EnterCriticalSection(&This->base.crit);

    if (TRACE_ON(dinput)) {
	int i;
	for (i = 0; i < WINE_DINPUT_KEYBOARD_MAX_KEYS; i++) {
	    if (This->DInputKeyState[i] != 0x00)
		TRACE(" - %02X: %02x\n", i, This->DInputKeyState[i]);
	}
    }

    fill_DataFormat(ptr, len, This->DInputKeyState, &This->base.data_format);
    LeaveCriticalSection(&This->base.crit);

    return DI_OK;
}

static HRESULT WINAPI SysKeyboardAImpl_GetDeviceState(LPDIRECTINPUTDEVICE8A iface, DWORD len, LPVOID ptr)
{
    SysKeyboardImpl *This = impl_from_IDirectInputDevice8A(iface);
    return SysKeyboardWImpl_GetDeviceState(IDirectInputDevice8W_from_impl(This), len, ptr);
}

/******************************************************************************
  *     GetCapabilities : get the device capabilities
  */
static HRESULT WINAPI SysKeyboardWImpl_GetCapabilities(LPDIRECTINPUTDEVICE8W iface, LPDIDEVCAPS lpDIDevCaps)
{
    SysKeyboardImpl *This = impl_from_IDirectInputDevice8W(iface);
    DIDEVCAPS devcaps;

    TRACE("(this=%p,%p)\n",This,lpDIDevCaps);

    if ((lpDIDevCaps->dwSize != sizeof(DIDEVCAPS)) && (lpDIDevCaps->dwSize != sizeof(DIDEVCAPS_DX3))) {
        WARN("invalid parameter\n");
        return DIERR_INVALIDPARAM;
    }

    devcaps.dwSize = lpDIDevCaps->dwSize;
    devcaps.dwFlags = DIDC_ATTACHED | DIDC_EMULATED;
    if (This->base.dinput->dwVersion >= 0x0800)
        devcaps.dwDevType = DI8DEVTYPE_KEYBOARD | (This->subtype << 8);
    else
        devcaps.dwDevType = DIDEVTYPE_KEYBOARD | (This->subtype << 8);
    devcaps.dwAxes = 0;
    devcaps.dwButtons = This->base.data_format.wine_df->dwNumObjs;
    devcaps.dwPOVs = 0;
    devcaps.dwFFSamplePeriod = 0;
    devcaps.dwFFMinTimeResolution = 0;
    devcaps.dwFirmwareRevision = 100;
    devcaps.dwHardwareRevision = 100;
    devcaps.dwFFDriverVersion = 0;

    memcpy(lpDIDevCaps, &devcaps, lpDIDevCaps->dwSize);

    return DI_OK;
}

static HRESULT WINAPI SysKeyboardAImpl_GetCapabilities(LPDIRECTINPUTDEVICE8A iface, LPDIDEVCAPS lpDIDevCaps)
{
    SysKeyboardImpl *This = impl_from_IDirectInputDevice8A(iface);
    return SysKeyboardWImpl_GetCapabilities(IDirectInputDevice8W_from_impl(This), lpDIDevCaps);
}

static DWORD map_dik_to_scan(DWORD dik_code, DWORD subtype)
{
    if (dik_code == DIK_PAUSE || dik_code == DIK_NUMLOCK) dik_code ^= 0x80;
    if (subtype == DIDEVTYPEKEYBOARD_JAPAN106)
    {
        switch (dik_code)
        {
        case DIK_CIRCUMFLEX:
            dik_code = 0x0d;
            break;
        case DIK_AT:
            dik_code = 0x1a;
            break;
        case DIK_LBRACKET:
            dik_code = 0x1b;
            break;
        case DIK_COLON:
            dik_code = 0x28;
            break;
        case DIK_KANJI:
            dik_code = 0x29;
            break;
        case DIK_RBRACKET:
            dik_code = 0x2b;
            break;
        case DIK_BACKSLASH:
            dik_code = 0x73;
            break;
        }
    }

    return dik_code;
}

/******************************************************************************
  *     GetObjectInfo : get information about a device object such as a button
  *                     or axis
  */
static HRESULT WINAPI
SysKeyboardAImpl_GetObjectInfo(
	LPDIRECTINPUTDEVICE8A iface,
	LPDIDEVICEOBJECTINSTANCEA pdidoi,
	DWORD dwObj,
	DWORD dwHow)
{
    SysKeyboardImpl *This = impl_from_IDirectInputDevice8A(iface);
    HRESULT res;
    LONG scan;

    res = IDirectInputDevice2AImpl_GetObjectInfo(iface, pdidoi, dwObj, dwHow);
    if (res != DI_OK) return res;

    scan = map_dik_to_scan(DIDFT_GETINSTANCE(pdidoi->dwType), This->subtype);
    if (!GetKeyNameTextA((scan & 0x80) << 17 | (scan & 0x7f) << 16,
                         pdidoi->tszName, sizeof(pdidoi->tszName)))
        return DIERR_OBJECTNOTFOUND;

    _dump_OBJECTINSTANCEA(pdidoi);
    return res;
}

static HRESULT WINAPI SysKeyboardWImpl_GetObjectInfo(LPDIRECTINPUTDEVICE8W iface,
						     LPDIDEVICEOBJECTINSTANCEW pdidoi,
						     DWORD dwObj,
						     DWORD dwHow)
{
    SysKeyboardImpl *This = impl_from_IDirectInputDevice8W(iface);
    HRESULT res;
    LONG scan;

    res = IDirectInputDevice2WImpl_GetObjectInfo(iface, pdidoi, dwObj, dwHow);
    if (res != DI_OK) return res;

    scan = map_dik_to_scan(DIDFT_GETINSTANCE(pdidoi->dwType), This->subtype);
    if (!GetKeyNameTextW((scan & 0x80) << 17 | (scan & 0x7f) << 16,
                         pdidoi->tszName, ARRAY_SIZE(pdidoi->tszName)))
        return DIERR_OBJECTNOTFOUND;

    _dump_OBJECTINSTANCEW(pdidoi);
    return res;
}

/******************************************************************************
  *     GetDeviceInfo : get information about a device's identity
  */
static HRESULT WINAPI SysKeyboardAImpl_GetDeviceInfo(
	LPDIRECTINPUTDEVICE8A iface,
	LPDIDEVICEINSTANCEA pdidi)
{
    SysKeyboardImpl *This = impl_from_IDirectInputDevice8A(iface);
    TRACE("(this=%p,%p)\n", This, pdidi);

    fill_keyboard_dideviceinstanceA(pdidi, This->base.dinput->dwVersion, This->subtype);
    
    return DI_OK;
}

static HRESULT WINAPI SysKeyboardWImpl_GetDeviceInfo(LPDIRECTINPUTDEVICE8W iface, LPDIDEVICEINSTANCEW pdidi)
{
    SysKeyboardImpl *This = impl_from_IDirectInputDevice8W(iface);
    TRACE("(this=%p,%p)\n", This, pdidi);

    if (pdidi->dwSize != sizeof(DIDEVICEINSTANCEW)) {
        WARN(" dinput3 not supported yet...\n");
	return DI_OK;
    }

    fill_keyboard_dideviceinstanceW(pdidi, This->base.dinput->dwVersion, This->subtype);
    
    return DI_OK;
}

/******************************************************************************
 *      GetProperty : Retrieves information about the input device.
 */
static HRESULT WINAPI SysKeyboardWImpl_GetProperty(LPDIRECTINPUTDEVICE8W iface,
                                                   REFGUID rguid, LPDIPROPHEADER pdiph)
{
    SysKeyboardImpl *This = impl_from_IDirectInputDevice8W(iface);

    TRACE("(%p)->(%s,%p)\n", This, debugstr_guid(rguid), pdiph);
    _dump_DIPROPHEADER(pdiph);

    if (!IS_DIPROP(rguid)) return DI_OK;

    switch (LOWORD(rguid))
    {
        case (DWORD_PTR)DIPROP_KEYNAME:
        {
            HRESULT hr;
            LPDIPROPSTRING ps = (LPDIPROPSTRING)pdiph;
            DIDEVICEOBJECTINSTANCEW didoi;

            if (pdiph->dwSize != sizeof(DIPROPSTRING))
                return DIERR_INVALIDPARAM;

            didoi.dwSize = sizeof(DIDEVICEOBJECTINSTANCEW);

            hr = SysKeyboardWImpl_GetObjectInfo(iface, &didoi, ps->diph.dwObj, ps->diph.dwHow);
            if (hr == DI_OK)
                memcpy(ps->wsz, didoi.tszName, sizeof(ps->wsz));
            return hr;
        }
        case (DWORD_PTR) DIPROP_VIDPID:
        case (DWORD_PTR) DIPROP_RANGE:
            return DIERR_UNSUPPORTED;
        default:
            return IDirectInputDevice2AImpl_GetProperty( IDirectInputDevice8A_from_impl(This), rguid, pdiph );
    }
    return DI_OK;
}

static HRESULT WINAPI SysKeyboardAImpl_GetProperty(LPDIRECTINPUTDEVICE8A iface,
                                                   REFGUID rguid, LPDIPROPHEADER pdiph)
{
    SysKeyboardImpl *This = impl_from_IDirectInputDevice8A(iface);
    return SysKeyboardWImpl_GetProperty(IDirectInputDevice8W_from_impl(This), rguid, pdiph);
}

static HRESULT WINAPI SysKeyboardWImpl_Acquire(LPDIRECTINPUTDEVICE8W iface)
{
    SysKeyboardImpl *This = impl_from_IDirectInputDevice8W(iface);
    HRESULT res;

    TRACE("(%p)\n", This);

    res = IDirectInputDevice2WImpl_Acquire(iface);
    if (res == DI_OK)
    {
        TRACE("clearing keystate\n");
        memset(This->DInputKeyState, 0, sizeof(This->DInputKeyState));
    }

    return res;
}

static HRESULT WINAPI SysKeyboardAImpl_Acquire(LPDIRECTINPUTDEVICE8A iface)
{
    SysKeyboardImpl *This = impl_from_IDirectInputDevice8A(iface);
    return SysKeyboardWImpl_Acquire(IDirectInputDevice8W_from_impl(This));
}

static HRESULT WINAPI SysKeyboardWImpl_BuildActionMap(LPDIRECTINPUTDEVICE8W iface,
                                                      LPDIACTIONFORMATW lpdiaf,
                                                      LPCWSTR lpszUserName,
                                                      DWORD dwFlags)
{
    SysKeyboardImpl *This = impl_from_IDirectInputDevice8W(iface);
    FIXME("(%p)->(%p,%s,%08x): semi-stub !\n", This, lpdiaf, debugstr_w(lpszUserName), dwFlags);

    return  _build_action_map(iface, lpdiaf, lpszUserName, dwFlags, DIKEYBOARD_MASK, &c_dfDIKeyboard);
}

static HRESULT WINAPI SysKeyboardAImpl_BuildActionMap(LPDIRECTINPUTDEVICE8A iface,
                                                      LPDIACTIONFORMATA lpdiaf,
                                                      LPCSTR lpszUserName,
                                                      DWORD dwFlags)
{
    SysKeyboardImpl *This = impl_from_IDirectInputDevice8A(iface);
    DIACTIONFORMATW diafW;
    HRESULT hr;
    WCHAR *lpszUserNameW = NULL;
    int username_size;

    diafW.rgoAction = HeapAlloc(GetProcessHeap(), 0, sizeof(DIACTIONW)*lpdiaf->dwNumActions);
    _copy_diactionformatAtoW(&diafW, lpdiaf);

    if (lpszUserName != NULL)
    {
        username_size = MultiByteToWideChar(CP_ACP, 0, lpszUserName, -1, NULL, 0);
        lpszUserNameW = HeapAlloc(GetProcessHeap(), 0, sizeof(WCHAR)*username_size);
        MultiByteToWideChar(CP_ACP, 0, lpszUserName, -1, lpszUserNameW, username_size);
    }

    hr = SysKeyboardWImpl_BuildActionMap(&This->base.IDirectInputDevice8W_iface, &diafW, lpszUserNameW, dwFlags);

    _copy_diactionformatWtoA(lpdiaf, &diafW);
    HeapFree(GetProcessHeap(), 0, diafW.rgoAction);
    HeapFree(GetProcessHeap(), 0, lpszUserNameW);

    return hr;
}

static HRESULT WINAPI SysKeyboardWImpl_SetActionMap(LPDIRECTINPUTDEVICE8W iface,
                                                    LPDIACTIONFORMATW lpdiaf,
                                                    LPCWSTR lpszUserName,
                                                    DWORD dwFlags)
{
    SysKeyboardImpl *This = impl_from_IDirectInputDevice8W(iface);
    FIXME("(%p)->(%p,%s,%08x): semi-stub !\n", This, lpdiaf, debugstr_w(lpszUserName), dwFlags);

    return _set_action_map(iface, lpdiaf, lpszUserName, dwFlags, &c_dfDIKeyboard);
}

static HRESULT WINAPI SysKeyboardAImpl_SetActionMap(LPDIRECTINPUTDEVICE8A iface,
                                                    LPDIACTIONFORMATA lpdiaf,
                                                    LPCSTR lpszUserName,
                                                    DWORD dwFlags)
{
    SysKeyboardImpl *This = impl_from_IDirectInputDevice8A(iface);
    DIACTIONFORMATW diafW;
    HRESULT hr;
    WCHAR *lpszUserNameW = NULL;
    int username_size;

    diafW.rgoAction = HeapAlloc(GetProcessHeap(), 0, sizeof(DIACTIONW)*lpdiaf->dwNumActions);
    _copy_diactionformatAtoW(&diafW, lpdiaf);

    if (lpszUserName != NULL)
    {
        username_size = MultiByteToWideChar(CP_ACP, 0, lpszUserName, -1, NULL, 0);
        lpszUserNameW = HeapAlloc(GetProcessHeap(), 0, sizeof(WCHAR)*username_size);
        MultiByteToWideChar(CP_ACP, 0, lpszUserName, -1, lpszUserNameW, username_size);
    }

    hr = SysKeyboardWImpl_SetActionMap(&This->base.IDirectInputDevice8W_iface, &diafW, lpszUserNameW, dwFlags);

    lpdiaf->dwCRC = diafW.dwCRC;

    HeapFree(GetProcessHeap(), 0, diafW.rgoAction);
    HeapFree(GetProcessHeap(), 0, lpszUserNameW);

    return hr;
}

static const IDirectInputDevice8AVtbl SysKeyboardAvt =
{
    IDirectInputDevice2AImpl_QueryInterface,
    IDirectInputDevice2AImpl_AddRef,
    IDirectInputDevice2AImpl_Release,
    SysKeyboardAImpl_GetCapabilities,
    IDirectInputDevice2AImpl_EnumObjects,
    SysKeyboardAImpl_GetProperty,
    IDirectInputDevice2AImpl_SetProperty,
    SysKeyboardAImpl_Acquire,
    IDirectInputDevice2AImpl_Unacquire,
    SysKeyboardAImpl_GetDeviceState,
    IDirectInputDevice2AImpl_GetDeviceData,
    IDirectInputDevice2AImpl_SetDataFormat,
    IDirectInputDevice2AImpl_SetEventNotification,
    IDirectInputDevice2AImpl_SetCooperativeLevel,
    SysKeyboardAImpl_GetObjectInfo,
    SysKeyboardAImpl_GetDeviceInfo,
    IDirectInputDevice2AImpl_RunControlPanel,
    IDirectInputDevice2AImpl_Initialize,
    IDirectInputDevice2AImpl_CreateEffect,
    IDirectInputDevice2AImpl_EnumEffects,
    IDirectInputDevice2AImpl_GetEffectInfo,
    IDirectInputDevice2AImpl_GetForceFeedbackState,
    IDirectInputDevice2AImpl_SendForceFeedbackCommand,
    IDirectInputDevice2AImpl_EnumCreatedEffectObjects,
    IDirectInputDevice2AImpl_Escape,
    IDirectInputDevice2AImpl_Poll,
    IDirectInputDevice2AImpl_SendDeviceData,
    IDirectInputDevice7AImpl_EnumEffectsInFile,
    IDirectInputDevice7AImpl_WriteEffectToFile,
    SysKeyboardAImpl_BuildActionMap,
    SysKeyboardAImpl_SetActionMap,
    IDirectInputDevice8AImpl_GetImageInfo
};

static const IDirectInputDevice8WVtbl SysKeyboardWvt =
{
    IDirectInputDevice2WImpl_QueryInterface,
    IDirectInputDevice2WImpl_AddRef,
    IDirectInputDevice2WImpl_Release,
    SysKeyboardWImpl_GetCapabilities,
    IDirectInputDevice2WImpl_EnumObjects,
    SysKeyboardWImpl_GetProperty,
    IDirectInputDevice2WImpl_SetProperty,
    SysKeyboardWImpl_Acquire,
    IDirectInputDevice2WImpl_Unacquire,
    SysKeyboardWImpl_GetDeviceState,
    IDirectInputDevice2WImpl_GetDeviceData,
    IDirectInputDevice2WImpl_SetDataFormat,
    IDirectInputDevice2WImpl_SetEventNotification,
    IDirectInputDevice2WImpl_SetCooperativeLevel,
    SysKeyboardWImpl_GetObjectInfo,
    SysKeyboardWImpl_GetDeviceInfo,
    IDirectInputDevice2WImpl_RunControlPanel,
    IDirectInputDevice2WImpl_Initialize,
    IDirectInputDevice2WImpl_CreateEffect,
    IDirectInputDevice2WImpl_EnumEffects,
    IDirectInputDevice2WImpl_GetEffectInfo,
    IDirectInputDevice2WImpl_GetForceFeedbackState,
    IDirectInputDevice2WImpl_SendForceFeedbackCommand,
    IDirectInputDevice2WImpl_EnumCreatedEffectObjects,
    IDirectInputDevice2WImpl_Escape,
    IDirectInputDevice2WImpl_Poll,
    IDirectInputDevice2WImpl_SendDeviceData,
    IDirectInputDevice7WImpl_EnumEffectsInFile,
    IDirectInputDevice7WImpl_WriteEffectToFile,
    SysKeyboardWImpl_BuildActionMap,
    SysKeyboardWImpl_SetActionMap,
    IDirectInputDevice8WImpl_GetImageInfo
=======
static const struct dinput_device_vtbl keyboard_vtbl =
{
    NULL,
    keyboard_poll,
    NULL,
    keyboard_acquire,
    keyboard_unacquire,
    keyboard_enum_objects,
    keyboard_get_property,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
>>>>>>> github-desktop-wine-mirror/master
};
