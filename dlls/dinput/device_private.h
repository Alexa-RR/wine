/*
 * Copyright 2000 Lionel Ulmer
 * Copyright 2000-2001 TransGaming Technologies Inc.
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

#ifndef __WINE_DLLS_DINPUT_DINPUTDEVICE_PRIVATE_H
#define __WINE_DLLS_DINPUT_DINPUTDEVICE_PRIVATE_H

#include <stdarg.h>

#include "windef.h"
#include "winbase.h"
#include "dinput.h"
#include "wine/list.h"
#include "dinput_private.h"

typedef struct
{
    unsigned int offset;
    UINT_PTR uAppData;
} ActionMap;

struct dinput_device_vtbl
{
    void (*release)( IDirectInputDevice8W *iface );
    HRESULT (*poll)( IDirectInputDevice8W *iface );
    HRESULT (*read)( IDirectInputDevice8W *iface );
    HRESULT (*acquire)( IDirectInputDevice8W *iface );
    HRESULT (*unacquire)( IDirectInputDevice8W *iface );
    HRESULT (*enum_objects)( IDirectInputDevice8W *iface, const DIPROPHEADER *filter, DWORD flags,
                             LPDIENUMDEVICEOBJECTSCALLBACKW callback, void *context );
    HRESULT (*get_property)( IDirectInputDevice8W *iface, DWORD property, DIPROPHEADER *header,
                             const DIDEVICEOBJECTINSTANCEW *instance );
    HRESULT (*get_effect_info)( IDirectInputDevice8W *iface, DIEFFECTINFOW *info, const GUID *guid );
    HRESULT (*create_effect)( IDirectInputDevice8W *iface, IDirectInputEffect **out );
    HRESULT (*send_force_feedback_command)( IDirectInputDevice8W *iface, DWORD command, BOOL unacquire );
    HRESULT (*send_device_gain)( IDirectInputDevice8W *iface, LONG device_gain );
    HRESULT (*enum_created_effect_objects)( IDirectInputDevice8W *iface, LPDIENUMCREATEDEFFECTOBJECTSCALLBACK callback,
                                            void *context, DWORD flags );
};

#define DEVICE_STATE_MAX_SIZE 1024

struct object_properties
{
    LONG bit_size;
    LONG physical_min;
    LONG physical_max;
    LONG logical_min;
    LONG logical_max;
    LONG range_min;
    LONG range_max;
    LONG deadzone;
    LONG saturation;
    DWORD calibration_mode;
};

enum device_status
{
    STATUS_UNACQUIRED,
    STATUS_ACQUIRED,
    STATUS_UNPLUGGED,
};

/* Device implementation */
struct dinput_device
{
    IDirectInputDevice8W        IDirectInputDevice8W_iface;
    IDirectInputDevice8A        IDirectInputDevice8A_iface;
    LONG                        ref;
    GUID                        guid;
    CRITICAL_SECTION            crit;
    struct dinput              *dinput;
    struct list                 entry;       /* entry into acquired device list */
    HANDLE                      hEvent;
    DIDEVICEINSTANCEW           instance;
    DIDEVCAPS                   caps;
    DWORD                       dwCoopLevel;
    HWND                        win;
    enum device_status          status;

    BOOL                        use_raw_input; /* use raw input instead of low-level messages */
    RAWINPUTDEVICE              raw_device;    /* raw device to (un)register */

    BOOL                        use_raw_input; /* use raw input instead of low-level messages */
    RAWINPUTDEVICE              raw_device;    /* raw device to (un)register */

    LPDIDEVICEOBJECTDATA        data_queue;  /* buffer for 'GetDeviceData'.                 */
    int                         queue_len;   /* valid size of the queue                     */
    int                         queue_head;  /* position to write new event into queue      */
    int                         queue_tail;  /* next event to read from queue               */
    BOOL                        overflow;    /* return DI_BUFFEROVERFLOW in 'GetDeviceData' */
    DWORD                       buffersize;  /* size of the queue - set in 'SetProperty'    */

    DIDATAFORMAT *device_format;
    DIDATAFORMAT *user_format;

    /* Action mapping */
    int                         num_actions; /* number of actions mapped */
    ActionMap                  *action_map;  /* array of mappings */

    /* internal device callbacks */
    HANDLE read_event;
    const struct dinput_device_vtbl *vtbl;

    BYTE device_state_report_id;
    BYTE device_state[DEVICE_STATE_MAX_SIZE];

    BOOL autocenter;
    LONG device_gain;
    DWORD force_feedback_state;
    struct object_properties *object_properties;
};

extern HRESULT dinput_device_alloc( SIZE_T size, const struct dinput_device_vtbl *vtbl, const GUID *guid,
                                    struct dinput *dinput, void **out ) DECLSPEC_HIDDEN;
extern HRESULT dinput_device_init( IDirectInputDevice8W *iface );
extern void dinput_device_destroy( IDirectInputDevice8W *iface );

extern BOOL get_app_key(HKEY*, HKEY*) DECLSPEC_HIDDEN;
extern DWORD get_config_key( HKEY, HKEY, const WCHAR *, WCHAR *, DWORD ) DECLSPEC_HIDDEN;
extern BOOL device_instance_is_disabled( DIDEVICEINSTANCEW *instance, BOOL *override ) DECLSPEC_HIDDEN;

/* Routines to do DataFormat / WineFormat conversions */
extern void queue_event( IDirectInputDevice8W *iface, int inst_id, DWORD data, DWORD time, DWORD seq ) DECLSPEC_HIDDEN;

<<<<<<< HEAD
/* Common joystick stuff */
typedef struct
{
    LONG lDevMin;
    LONG lDevMax;
    LONG lMin;
    LONG lMax;
    LONG lDeadZone;
    LONG lSaturation;
} ObjProps;

extern DWORD joystick_map_pov(const POINTL *p) DECLSPEC_HIDDEN;
extern LONG joystick_map_axis(ObjProps *props, int val) DECLSPEC_HIDDEN;

typedef struct
{
    struct list entry;
    LPDIRECTINPUTEFFECT ref;
} effect_list_item;

extern const GUID DInput_PIDVID_Product_GUID DECLSPEC_HIDDEN;

/* Various debug tools */
extern void _dump_DIPROPHEADER(LPCDIPROPHEADER diph)  DECLSPEC_HIDDEN;
extern void _dump_OBJECTINSTANCEA(const DIDEVICEOBJECTINSTANCEA *ddoi)  DECLSPEC_HIDDEN;
extern void _dump_OBJECTINSTANCEW(const DIDEVICEOBJECTINSTANCEW *ddoi)  DECLSPEC_HIDDEN;
extern void _dump_DIDATAFORMAT(const DIDATAFORMAT *df)  DECLSPEC_HIDDEN;
extern const char *_dump_dinput_GUID(const GUID *guid)  DECLSPEC_HIDDEN;

extern LPDIOBJECTDATAFORMAT dataformat_to_odf_by_type(LPCDIDATAFORMAT df, int n, DWORD type)   DECLSPEC_HIDDEN;

extern HRESULT save_mapping_settings(IDirectInputDevice8W *iface, LPDIACTIONFORMATW lpdiaf, LPCWSTR lpszUsername) DECLSPEC_HIDDEN;
extern BOOL load_mapping_settings(IDirectInputDeviceImpl *This, LPDIACTIONFORMATW lpdiaf, const WCHAR *username) DECLSPEC_HIDDEN;

extern HRESULT _build_action_map(LPDIRECTINPUTDEVICE8W iface, LPDIACTIONFORMATW lpdiaf, LPCWSTR lpszUserName, DWORD dwFlags, DWORD devMask, LPCDIDATAFORMAT df)  DECLSPEC_HIDDEN;
extern HRESULT _set_action_map(LPDIRECTINPUTDEVICE8W iface, LPDIACTIONFORMATW lpdiaf, LPCWSTR lpszUserName, DWORD dwFlags, LPCDIDATAFORMAT df) DECLSPEC_HIDDEN;

/* And the stubs */
extern HRESULT WINAPI IDirectInputDevice2AImpl_Acquire(LPDIRECTINPUTDEVICE8A iface) DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice2WImpl_Acquire(LPDIRECTINPUTDEVICE8W iface) DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice2AImpl_Unacquire(LPDIRECTINPUTDEVICE8A iface) DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice2WImpl_Unacquire(LPDIRECTINPUTDEVICE8W iface) DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice2AImpl_SetDataFormat(LPDIRECTINPUTDEVICE8A iface, LPCDIDATAFORMAT df) DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice2WImpl_SetDataFormat(LPDIRECTINPUTDEVICE8W iface, LPCDIDATAFORMAT df) DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice2AImpl_SetCooperativeLevel(LPDIRECTINPUTDEVICE8A iface, HWND hwnd, DWORD dwflags) DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice2WImpl_SetCooperativeLevel(LPDIRECTINPUTDEVICE8W iface, HWND hwnd, DWORD dwflags) DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice2AImpl_SetEventNotification(LPDIRECTINPUTDEVICE8A iface, HANDLE hnd) DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice2WImpl_SetEventNotification(LPDIRECTINPUTDEVICE8W iface, HANDLE hnd) DECLSPEC_HIDDEN;
extern ULONG WINAPI IDirectInputDevice2AImpl_Release(LPDIRECTINPUTDEVICE8A iface)  DECLSPEC_HIDDEN;
extern ULONG WINAPI IDirectInputDevice2WImpl_Release(LPDIRECTINPUTDEVICE8W iface) DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice2AImpl_QueryInterface(LPDIRECTINPUTDEVICE8A iface, REFIID riid, LPVOID *ppobj) DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice2WImpl_QueryInterface(LPDIRECTINPUTDEVICE8W iface, REFIID riid, LPVOID *ppobj) DECLSPEC_HIDDEN;
extern ULONG WINAPI IDirectInputDevice2AImpl_AddRef(LPDIRECTINPUTDEVICE8A iface) DECLSPEC_HIDDEN;
extern ULONG WINAPI IDirectInputDevice2WImpl_AddRef(LPDIRECTINPUTDEVICE8W iface) DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice2AImpl_EnumObjects(
	LPDIRECTINPUTDEVICE8A iface,
	LPDIENUMDEVICEOBJECTSCALLBACKA lpCallback,
	LPVOID lpvRef,
	DWORD dwFlags)  DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice2WImpl_EnumObjects(
	LPDIRECTINPUTDEVICE8W iface,
	LPDIENUMDEVICEOBJECTSCALLBACKW lpCallback,
	LPVOID lpvRef,
	DWORD dwFlags)  DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice2AImpl_GetProperty(LPDIRECTINPUTDEVICE8A iface, REFGUID rguid, LPDIPROPHEADER pdiph) DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice2WImpl_GetProperty(LPDIRECTINPUTDEVICE8W iface, REFGUID rguid, LPDIPROPHEADER pdiph) DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice2AImpl_SetProperty(LPDIRECTINPUTDEVICE8A iface, REFGUID rguid, LPCDIPROPHEADER pdiph) DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice2WImpl_SetProperty(LPDIRECTINPUTDEVICE8W iface, REFGUID rguid, LPCDIPROPHEADER pdiph) DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice2AImpl_GetObjectInfo(
	LPDIRECTINPUTDEVICE8A iface,
	LPDIDEVICEOBJECTINSTANCEA pdidoi,
	DWORD dwObj,
	DWORD dwHow)  DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice2WImpl_GetObjectInfo(LPDIRECTINPUTDEVICE8W iface, 
							     LPDIDEVICEOBJECTINSTANCEW pdidoi,
							     DWORD dwObj,
							     DWORD dwHow) DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice2AImpl_GetDeviceData(LPDIRECTINPUTDEVICE8A iface, DWORD dodsize, LPDIDEVICEOBJECTDATA dod,
                                                             LPDWORD entries, DWORD flags) DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice2WImpl_GetDeviceData(LPDIRECTINPUTDEVICE8W iface, DWORD dodsize, LPDIDEVICEOBJECTDATA dod,
                                                             LPDWORD entries, DWORD flags) DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice2AImpl_RunControlPanel(LPDIRECTINPUTDEVICE8A iface, HWND hwndOwner, DWORD dwFlags) DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice2WImpl_RunControlPanel(LPDIRECTINPUTDEVICE8W iface, HWND hwndOwner, DWORD dwFlags) DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice2AImpl_Initialize(LPDIRECTINPUTDEVICE8A iface, HINSTANCE hinst, DWORD dwVersion,
                                                          REFGUID rguid) DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice2WImpl_Initialize(LPDIRECTINPUTDEVICE8W iface, HINSTANCE hinst, DWORD dwVersion,
                                                          REFGUID rguid) DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice2AImpl_CreateEffect(LPDIRECTINPUTDEVICE8A iface, REFGUID rguid, LPCDIEFFECT lpeff,
                                                            LPDIRECTINPUTEFFECT *ppdef, LPUNKNOWN pUnkOuter) DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice2WImpl_CreateEffect(LPDIRECTINPUTDEVICE8W iface, REFGUID rguid, LPCDIEFFECT lpeff,
                                                            LPDIRECTINPUTEFFECT *ppdef, LPUNKNOWN pUnkOuter) DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice2AImpl_EnumEffects(
	LPDIRECTINPUTDEVICE8A iface,
	LPDIENUMEFFECTSCALLBACKA lpCallback,
	LPVOID lpvRef,
	DWORD dwFlags)  DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice2WImpl_EnumEffects(
	LPDIRECTINPUTDEVICE8W iface,
	LPDIENUMEFFECTSCALLBACKW lpCallback,
	LPVOID lpvRef,
	DWORD dwFlags)  DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice2AImpl_GetEffectInfo(
	LPDIRECTINPUTDEVICE8A iface,
	LPDIEFFECTINFOA lpdei,
	REFGUID rguid)  DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice2WImpl_GetEffectInfo(
	LPDIRECTINPUTDEVICE8W iface,
	LPDIEFFECTINFOW lpdei,
	REFGUID rguid)  DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice2AImpl_GetForceFeedbackState(LPDIRECTINPUTDEVICE8A iface, LPDWORD pdwOut) DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice2WImpl_GetForceFeedbackState(LPDIRECTINPUTDEVICE8W iface, LPDWORD pdwOut) DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice2AImpl_SendForceFeedbackCommand(LPDIRECTINPUTDEVICE8A iface, DWORD dwFlags) DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice2WImpl_SendForceFeedbackCommand(LPDIRECTINPUTDEVICE8W iface, DWORD dwFlags) DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice2AImpl_EnumCreatedEffectObjects(LPDIRECTINPUTDEVICE8A iface,
                                                                        LPDIENUMCREATEDEFFECTOBJECTSCALLBACK lpCallback,
                                                                        LPVOID lpvRef, DWORD dwFlags) DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice2WImpl_EnumCreatedEffectObjects(LPDIRECTINPUTDEVICE8W iface,
                                                                        LPDIENUMCREATEDEFFECTOBJECTSCALLBACK lpCallback,
                                                                        LPVOID lpvRef, DWORD dwFlags) DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice2AImpl_Escape(LPDIRECTINPUTDEVICE8A iface, LPDIEFFESCAPE lpDIEEsc) DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice2WImpl_Escape(LPDIRECTINPUTDEVICE8W iface, LPDIEFFESCAPE lpDIEEsc) DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice2AImpl_Poll(LPDIRECTINPUTDEVICE8A iface) DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice2WImpl_Poll(LPDIRECTINPUTDEVICE8W iface) DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice2AImpl_SendDeviceData(LPDIRECTINPUTDEVICE8A iface, DWORD cbObjectData,
                                                              LPCDIDEVICEOBJECTDATA rgdod, LPDWORD pdwInOut, DWORD dwFlags) DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice2WImpl_SendDeviceData(LPDIRECTINPUTDEVICE8W iface, DWORD cbObjectData,
                                                              LPCDIDEVICEOBJECTDATA rgdod, LPDWORD pdwInOut, DWORD dwFlags) DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice7AImpl_EnumEffectsInFile(LPDIRECTINPUTDEVICE8A iface,
								 LPCSTR lpszFileName,
								 LPDIENUMEFFECTSINFILECALLBACK pec,
								 LPVOID pvRef,
								 DWORD dwFlags)  DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice7WImpl_EnumEffectsInFile(LPDIRECTINPUTDEVICE8W iface,
								 LPCWSTR lpszFileName,
								 LPDIENUMEFFECTSINFILECALLBACK pec,
								 LPVOID pvRef,
								 DWORD dwFlags)  DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice7AImpl_WriteEffectToFile(LPDIRECTINPUTDEVICE8A iface,
								 LPCSTR lpszFileName,
								 DWORD dwEntries,
								 LPDIFILEEFFECT rgDiFileEft,
								 DWORD dwFlags)  DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice7WImpl_WriteEffectToFile(LPDIRECTINPUTDEVICE8W iface,
								 LPCWSTR lpszFileName,
								 DWORD dwEntries,
								 LPDIFILEEFFECT rgDiFileEft,
								 DWORD dwFlags)  DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice8WImpl_BuildActionMap(LPDIRECTINPUTDEVICE8W iface,
							      LPDIACTIONFORMATW lpdiaf,
							      LPCWSTR lpszUserName,
							      DWORD dwFlags) DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice8AImpl_GetImageInfo(LPDIRECTINPUTDEVICE8A iface,
							    LPDIDEVICEIMAGEINFOHEADERA lpdiDevImageInfoHeader) DECLSPEC_HIDDEN;
extern HRESULT WINAPI IDirectInputDevice8WImpl_GetImageInfo(LPDIRECTINPUTDEVICE8W iface,
							    LPDIDEVICEIMAGEINFOHEADERW lpdiDevImageInfoHeader) DECLSPEC_HIDDEN;
=======
extern const GUID dinput_pidvid_guid DECLSPEC_HIDDEN;
>>>>>>> master

#endif /* __WINE_DLLS_DINPUT_DINPUTDEVICE_PRIVATE_H */
