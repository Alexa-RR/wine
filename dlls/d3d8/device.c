/*
 * IDirect3DDevice8 implementation
 *
 * Copyright 2002-2004 Jason Edmeades
 * Copyright 2004 Christian Costa
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

#include "config.h"

#include <math.h>
#include <stdarg.h>

#include "windef.h"
#include "winbase.h"
#include "winuser.h"
#include "wingdi.h"
#include "wine/debug.h"

#include "d3d8_private.h"

WINE_DEFAULT_DEBUG_CHANNEL(d3d8);

static void STDMETHODCALLTYPE d3d8_null_wined3d_object_destroyed(void *parent) {}

static const struct wined3d_parent_ops d3d8_null_wined3d_parent_ops =
{
    d3d8_null_wined3d_object_destroyed,
};

D3DFORMAT d3dformat_from_wined3dformat(enum wined3d_format_id format)
{
    BYTE *c = (BYTE *)&format;

    /* Don't translate FOURCC formats */
    if (isprint(c[0]) && isprint(c[1]) && isprint(c[2]) && isprint(c[3])) return format;

    switch(format)
    {
        case WINED3DFMT_UNKNOWN: return D3DFMT_UNKNOWN;
        case WINED3DFMT_B8G8R8_UNORM: return D3DFMT_R8G8B8;
        case WINED3DFMT_B8G8R8A8_UNORM: return D3DFMT_A8R8G8B8;
        case WINED3DFMT_B8G8R8X8_UNORM: return D3DFMT_X8R8G8B8;
        case WINED3DFMT_B5G6R5_UNORM: return D3DFMT_R5G6B5;
        case WINED3DFMT_B5G5R5X1_UNORM: return D3DFMT_X1R5G5B5;
        case WINED3DFMT_B5G5R5A1_UNORM: return D3DFMT_A1R5G5B5;
        case WINED3DFMT_B4G4R4A4_UNORM: return D3DFMT_A4R4G4B4;
        case WINED3DFMT_B2G3R3_UNORM: return D3DFMT_R3G3B2;
        case WINED3DFMT_A8_UNORM: return D3DFMT_A8;
        case WINED3DFMT_B2G3R3A8_UNORM: return D3DFMT_A8R3G3B2;
        case WINED3DFMT_B4G4R4X4_UNORM: return D3DFMT_X4R4G4B4;
        case WINED3DFMT_R10G10B10A2_UNORM: return D3DFMT_A2B10G10R10;
        case WINED3DFMT_R16G16_UNORM: return D3DFMT_G16R16;
        case WINED3DFMT_P8_UINT_A8_UNORM: return D3DFMT_A8P8;
        case WINED3DFMT_P8_UINT: return D3DFMT_P8;
        case WINED3DFMT_L8_UNORM: return D3DFMT_L8;
        case WINED3DFMT_L8A8_UNORM: return D3DFMT_A8L8;
        case WINED3DFMT_L4A4_UNORM: return D3DFMT_A4L4;
        case WINED3DFMT_R8G8_SNORM: return D3DFMT_V8U8;
        case WINED3DFMT_R5G5_SNORM_L6_UNORM: return D3DFMT_L6V5U5;
        case WINED3DFMT_R8G8_SNORM_L8X8_UNORM: return D3DFMT_X8L8V8U8;
        case WINED3DFMT_R8G8B8A8_SNORM: return D3DFMT_Q8W8V8U8;
        case WINED3DFMT_R16G16_SNORM: return D3DFMT_V16U16;
        case WINED3DFMT_R10G11B11_SNORM: return D3DFMT_W11V11U10;
        case WINED3DFMT_R10G10B10_SNORM_A2_UNORM: return D3DFMT_A2W10V10U10;
        case WINED3DFMT_D16_LOCKABLE: return D3DFMT_D16_LOCKABLE;
        case WINED3DFMT_D32_UNORM: return D3DFMT_D32;
        case WINED3DFMT_S1_UINT_D15_UNORM: return D3DFMT_D15S1;
        case WINED3DFMT_D24_UNORM_S8_UINT: return D3DFMT_D24S8;
        case WINED3DFMT_X8D24_UNORM: return D3DFMT_D24X8;
        case WINED3DFMT_S4X4_UINT_D24_UNORM: return D3DFMT_D24X4S4;
        case WINED3DFMT_D16_UNORM: return D3DFMT_D16;
        case WINED3DFMT_VERTEXDATA: return D3DFMT_VERTEXDATA;
        case WINED3DFMT_R16_UINT: return D3DFMT_INDEX16;
        case WINED3DFMT_R32_UINT: return D3DFMT_INDEX32;
        default:
            FIXME("Unhandled wined3d format %#x.\n", format);
            return D3DFMT_UNKNOWN;
    }
}

enum wined3d_format_id wined3dformat_from_d3dformat(D3DFORMAT format)
{
    BYTE *c = (BYTE *)&format;

    /* Don't translate FOURCC formats */
    if (isprint(c[0]) && isprint(c[1]) && isprint(c[2]) && isprint(c[3])) return format;

    switch(format)
    {
        case D3DFMT_UNKNOWN: return WINED3DFMT_UNKNOWN;
        case D3DFMT_R8G8B8: return WINED3DFMT_B8G8R8_UNORM;
        case D3DFMT_A8R8G8B8: return WINED3DFMT_B8G8R8A8_UNORM;
        case D3DFMT_X8R8G8B8: return WINED3DFMT_B8G8R8X8_UNORM;
        case D3DFMT_R5G6B5: return WINED3DFMT_B5G6R5_UNORM;
        case D3DFMT_X1R5G5B5: return WINED3DFMT_B5G5R5X1_UNORM;
        case D3DFMT_A1R5G5B5: return WINED3DFMT_B5G5R5A1_UNORM;
        case D3DFMT_A4R4G4B4: return WINED3DFMT_B4G4R4A4_UNORM;
        case D3DFMT_R3G3B2: return WINED3DFMT_B2G3R3_UNORM;
        case D3DFMT_A8: return WINED3DFMT_A8_UNORM;
        case D3DFMT_A8R3G3B2: return WINED3DFMT_B2G3R3A8_UNORM;
        case D3DFMT_X4R4G4B4: return WINED3DFMT_B4G4R4X4_UNORM;
        case D3DFMT_A2B10G10R10: return WINED3DFMT_R10G10B10A2_UNORM;
        case D3DFMT_G16R16: return WINED3DFMT_R16G16_UNORM;
        case D3DFMT_A8P8: return WINED3DFMT_P8_UINT_A8_UNORM;
        case D3DFMT_P8: return WINED3DFMT_P8_UINT;
        case D3DFMT_L8: return WINED3DFMT_L8_UNORM;
        case D3DFMT_A8L8: return WINED3DFMT_L8A8_UNORM;
        case D3DFMT_A4L4: return WINED3DFMT_L4A4_UNORM;
        case D3DFMT_V8U8: return WINED3DFMT_R8G8_SNORM;
        case D3DFMT_L6V5U5: return WINED3DFMT_R5G5_SNORM_L6_UNORM;
        case D3DFMT_X8L8V8U8: return WINED3DFMT_R8G8_SNORM_L8X8_UNORM;
        case D3DFMT_Q8W8V8U8: return WINED3DFMT_R8G8B8A8_SNORM;
        case D3DFMT_V16U16: return WINED3DFMT_R16G16_SNORM;
        case D3DFMT_W11V11U10: return WINED3DFMT_R10G11B11_SNORM;
        case D3DFMT_A2W10V10U10: return WINED3DFMT_R10G10B10_SNORM_A2_UNORM;
        case D3DFMT_D16_LOCKABLE: return WINED3DFMT_D16_LOCKABLE;
        case D3DFMT_D32: return WINED3DFMT_D32_UNORM;
        case D3DFMT_D15S1: return WINED3DFMT_S1_UINT_D15_UNORM;
        case D3DFMT_D24S8: return WINED3DFMT_D24_UNORM_S8_UINT;
        case D3DFMT_D24X8: return WINED3DFMT_X8D24_UNORM;
        case D3DFMT_D24X4S4: return WINED3DFMT_S4X4_UINT_D24_UNORM;
        case D3DFMT_D16: return WINED3DFMT_D16_UNORM;
        case D3DFMT_VERTEXDATA: return WINED3DFMT_VERTEXDATA;
        case D3DFMT_INDEX16: return WINED3DFMT_R16_UINT;
        case D3DFMT_INDEX32: return WINED3DFMT_R32_UINT;
        default:
            FIXME("Unhandled D3DFORMAT %#x\n", format);
            return WINED3DFMT_UNKNOWN;
    }
}

static UINT vertex_count_from_primitive_count(D3DPRIMITIVETYPE primitive_type, UINT primitive_count)
{
    switch(primitive_type)
    {
        case D3DPT_POINTLIST:
            return primitive_count;

        case D3DPT_LINELIST:
            return primitive_count * 2;

        case D3DPT_LINESTRIP:
            return primitive_count + 1;

        case D3DPT_TRIANGLELIST:
            return primitive_count * 3;

        case D3DPT_TRIANGLESTRIP:
        case D3DPT_TRIANGLEFAN:
            return primitive_count + 2;

        default:
            FIXME("Unhandled primitive type %#x\n", primitive_type);
            return 0;
    }
}

static void present_parameters_from_wined3d_swapchain_desc(D3DPRESENT_PARAMETERS *present_parameters,
        const struct wined3d_swapchain_desc *swapchain_desc)
{
    present_parameters->BackBufferWidth = swapchain_desc->backbuffer_width;
    present_parameters->BackBufferHeight = swapchain_desc->backbuffer_height;
    present_parameters->BackBufferFormat = d3dformat_from_wined3dformat(swapchain_desc->backbuffer_format);
    present_parameters->BackBufferCount = swapchain_desc->backbuffer_count;
    present_parameters->MultiSampleType = swapchain_desc->multisample_type;
    present_parameters->SwapEffect = swapchain_desc->swap_effect;
    present_parameters->hDeviceWindow = swapchain_desc->device_window;
    present_parameters->Windowed = swapchain_desc->windowed;
    present_parameters->EnableAutoDepthStencil = swapchain_desc->enable_auto_depth_stencil;
    present_parameters->AutoDepthStencilFormat
            = d3dformat_from_wined3dformat(swapchain_desc->auto_depth_stencil_format);
    present_parameters->Flags = swapchain_desc->flags;
    present_parameters->FullScreen_RefreshRateInHz = swapchain_desc->refresh_rate;
    present_parameters->FullScreen_PresentationInterval = swapchain_desc->swap_interval;
}

static BOOL wined3d_swapchain_desc_from_present_parameters(struct wined3d_swapchain_desc *swapchain_desc,
        const D3DPRESENT_PARAMETERS *present_parameters)
{
    if (!present_parameters->SwapEffect || present_parameters->SwapEffect > D3DSWAPEFFECT_COPY_VSYNC)
    {
        WARN("Invalid swap effect %u passed.\n", present_parameters->SwapEffect);
        return FALSE;
    }
    if (present_parameters->BackBufferCount > 3
            || ((present_parameters->SwapEffect == D3DSWAPEFFECT_COPY
            || present_parameters->SwapEffect == D3DSWAPEFFECT_COPY_VSYNC)
            && present_parameters->BackBufferCount > 1))
    {
        WARN("Invalid backbuffer count %u.\n", present_parameters->BackBufferCount);
        return FALSE;
    }

    swapchain_desc->backbuffer_width = present_parameters->BackBufferWidth;
    swapchain_desc->backbuffer_height = present_parameters->BackBufferHeight;
    swapchain_desc->backbuffer_format = wined3dformat_from_d3dformat(present_parameters->BackBufferFormat);
    swapchain_desc->backbuffer_count = max(1, present_parameters->BackBufferCount);
    swapchain_desc->multisample_type = present_parameters->MultiSampleType;
    swapchain_desc->multisample_quality = 0; /* d3d9 only */
    swapchain_desc->swap_effect = present_parameters->SwapEffect;
    swapchain_desc->device_window = present_parameters->hDeviceWindow;
    swapchain_desc->windowed = present_parameters->Windowed;
    swapchain_desc->enable_auto_depth_stencil = present_parameters->EnableAutoDepthStencil;
    swapchain_desc->auto_depth_stencil_format
            = wined3dformat_from_d3dformat(present_parameters->AutoDepthStencilFormat);
    swapchain_desc->flags = present_parameters->Flags;
    swapchain_desc->refresh_rate = present_parameters->FullScreen_RefreshRateInHz;
    swapchain_desc->swap_interval = present_parameters->FullScreen_PresentationInterval;
    swapchain_desc->auto_restore_display_mode = TRUE;

    return TRUE;
}

/* Handle table functions */
static DWORD d3d8_allocate_handle(struct d3d8_handle_table *t, void *object, enum d3d8_handle_type type)
{
    struct d3d8_handle_entry *entry;

    if (t->free_entries)
    {
        DWORD index = t->free_entries - t->entries;
        /* Use a free handle */
        entry = t->free_entries;
        if (entry->type != D3D8_HANDLE_FREE)
        {
            ERR("Handle %u(%p) is in the free list, but has type %#x.\n", index, entry, entry->type);
            return D3D8_INVALID_HANDLE;
        }
        t->free_entries = entry->object;
        entry->object = object;
        entry->type = type;

        return index;
    }

    if (!(t->entry_count < t->table_size))
    {
        /* Grow the table */
        UINT new_size = t->table_size + (t->table_size >> 1);
        struct d3d8_handle_entry *new_entries = HeapReAlloc(GetProcessHeap(),
                0, t->entries, new_size * sizeof(*t->entries));
        if (!new_entries)
        {
            ERR("Failed to grow the handle table.\n");
            return D3D8_INVALID_HANDLE;
        }
        t->entries = new_entries;
        t->table_size = new_size;
    }

    entry = &t->entries[t->entry_count];
    entry->object = object;
    entry->type = type;

    return t->entry_count++;
}

static void *d3d8_free_handle(struct d3d8_handle_table *t, DWORD handle, enum d3d8_handle_type type)
{
    struct d3d8_handle_entry *entry;
    void *object;

    if (handle == D3D8_INVALID_HANDLE || handle >= t->entry_count)
    {
        WARN("Invalid handle %u passed.\n", handle);
        return NULL;
    }

    entry = &t->entries[handle];
    if (entry->type != type)
    {
        WARN("Handle %u(%p) is not of type %#x.\n", handle, entry, type);
        return NULL;
    }

    object = entry->object;
    entry->object = t->free_entries;
    entry->type = D3D8_HANDLE_FREE;
    t->free_entries = entry;

    return object;
}

static void *d3d8_get_object(struct d3d8_handle_table *t, DWORD handle, enum d3d8_handle_type type)
{
    struct d3d8_handle_entry *entry;

    if (handle == D3D8_INVALID_HANDLE || handle >= t->entry_count)
    {
        WARN("Invalid handle %u passed.\n", handle);
        return NULL;
    }

    entry = &t->entries[handle];
    if (entry->type != type)
    {
        WARN("Handle %u(%p) is not of type %#x.\n", handle, entry, type);
        return NULL;
    }

    return entry->object;
}

static HRESULT WINAPI d3d8_device_QueryInterface(IDirect3DDevice8 *iface, REFIID riid, void **out)
{
    TRACE("iface %p, riid %s, out %p.\n",
            iface, debugstr_guid(riid), out);

    if (IsEqualGUID(riid, &IID_IDirect3DDevice8)
            || IsEqualGUID(riid, &IID_IUnknown))
    {
        IDirect3DDevice8_AddRef(iface);
        *out = iface;
        return S_OK;
    }

    WARN("%s not implemented, returning E_NOINTERFACE.\n", debugstr_guid(riid));

    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG WINAPI d3d8_device_AddRef(IDirect3DDevice8 *iface)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    ULONG ref = InterlockedIncrement(&device->ref);

    TRACE("%p increasing refcount to %u.\n", iface, ref);

    return ref;
}

static ULONG WINAPI d3d8_device_Release(IDirect3DDevice8 *iface)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    ULONG ref;

    if (device->inDestruction)
        return 0;

    ref = InterlockedDecrement(&device->ref);

    TRACE("%p decreasing refcount to %u.\n", iface, ref);

    if (!ref)
    {
        IDirect3D8 *parent = device->d3d_parent;
        unsigned i;

        TRACE("Releasing wined3d device %p.\n", device->wined3d_device);

        wined3d_mutex_lock();

        device->inDestruction = TRUE;

        for (i = 0; i < device->numConvertedDecls; ++i)
        {
            d3d8_vertex_declaration_destroy(device->decls[i].declaration);
        }
        HeapFree(GetProcessHeap(), 0, device->decls);

        if (device->vertex_buffer)
            wined3d_buffer_decref(device->vertex_buffer);
        if (device->index_buffer)
            wined3d_buffer_decref(device->index_buffer);

        wined3d_device_uninit_3d(device->wined3d_device);
        wined3d_device_release_focus_window(device->wined3d_device);
        wined3d_device_decref(device->wined3d_device);
        HeapFree(GetProcessHeap(), 0, device->handle_table.entries);
        HeapFree(GetProcessHeap(), 0, device);

        wined3d_mutex_unlock();

        IDirect3D8_Release(parent);
    }
    return ref;
}

static HRESULT WINAPI d3d8_device_TestCooperativeLevel(IDirect3DDevice8 *iface)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);

    TRACE("iface %p.\n", iface);

    TRACE("device state: %#x.\n", device->device_state);

    switch (device->device_state)
    {
        default:
        case D3D8_DEVICE_STATE_OK:
            return D3D_OK;
        case D3D8_DEVICE_STATE_LOST:
            return D3DERR_DEVICELOST;
        case D3D8_DEVICE_STATE_NOT_RESET:
            return D3DERR_DEVICENOTRESET;
    }
}

static UINT WINAPI d3d8_device_GetAvailableTextureMem(IDirect3DDevice8 *iface)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    UINT ret;

    TRACE("iface %p.\n", iface);

    wined3d_mutex_lock();
    ret = wined3d_device_get_available_texture_mem(device->wined3d_device);
    wined3d_mutex_unlock();

    return ret;
}

static HRESULT WINAPI d3d8_device_ResourceManagerDiscardBytes(IDirect3DDevice8 *iface, DWORD byte_count)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);

    TRACE("iface %p, byte_count %u.\n", iface, byte_count);

    if (byte_count)
        FIXME("Byte count ignored.\n");

    wined3d_mutex_lock();
    wined3d_device_evict_managed_resources(device->wined3d_device);
    wined3d_mutex_unlock();

    return D3D_OK;
}

static HRESULT WINAPI d3d8_device_GetDirect3D(IDirect3DDevice8 *iface, IDirect3D8 **d3d8)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);

    TRACE("iface %p, d3d8 %p.\n", iface, d3d8);

    if (!d3d8)
        return D3DERR_INVALIDCALL;

    return IDirect3D8_QueryInterface(device->d3d_parent, &IID_IDirect3D8, (void **)d3d8);
}

static HRESULT WINAPI d3d8_device_GetDeviceCaps(IDirect3DDevice8 *iface, D3DCAPS8 *caps)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    WINED3DCAPS *wined3d_caps;
    HRESULT hr;

    TRACE("iface %p, caps %p.\n", iface, caps);

    if (!caps)
        return D3DERR_INVALIDCALL;

    if (!(wined3d_caps = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*wined3d_caps))))
        return D3DERR_INVALIDCALL; /* well this is what MSDN says to return */

    wined3d_mutex_lock();
    hr = wined3d_device_get_device_caps(device->wined3d_device, wined3d_caps);
    wined3d_mutex_unlock();

    fixup_caps(wined3d_caps);
    WINECAPSTOD3D8CAPS(caps, wined3d_caps)
    HeapFree(GetProcessHeap(), 0, wined3d_caps);

    return hr;
}

static HRESULT WINAPI d3d8_device_GetDisplayMode(IDirect3DDevice8 *iface, D3DDISPLAYMODE *mode)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    struct wined3d_display_mode wined3d_mode;
    HRESULT hr;

    TRACE("iface %p, mode %p.\n", iface, mode);

    wined3d_mutex_lock();
    hr = wined3d_device_get_display_mode(device->wined3d_device, 0, &wined3d_mode, NULL);
    wined3d_mutex_unlock();

    if (SUCCEEDED(hr))
    {
        mode->Width = wined3d_mode.width;
        mode->Height = wined3d_mode.height;
        mode->RefreshRate = wined3d_mode.refresh_rate;
        mode->Format = d3dformat_from_wined3dformat(wined3d_mode.format_id);
    }

    return hr;
}

static HRESULT WINAPI d3d8_device_GetCreationParameters(IDirect3DDevice8 *iface,
        D3DDEVICE_CREATION_PARAMETERS *parameters)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);

    TRACE("iface %p, parameters %p.\n", iface, parameters);

    wined3d_mutex_lock();
    wined3d_device_get_creation_parameters(device->wined3d_device,
            (struct wined3d_device_creation_parameters *)parameters);
    wined3d_mutex_unlock();

    return D3D_OK;
}

static HRESULT WINAPI d3d8_device_SetCursorProperties(IDirect3DDevice8 *iface,
        UINT hotspot_x, UINT hotspot_y, IDirect3DSurface8 *bitmap)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    struct d3d8_surface *bitmap_impl = unsafe_impl_from_IDirect3DSurface8(bitmap);
    HRESULT hr;

    TRACE("iface %p, hotspot_x %u, hotspot_y %u, bitmap %p.\n",
            iface, hotspot_x, hotspot_y, bitmap);

    if (!bitmap)
    {
        WARN("No cursor bitmap, returning D3DERR_INVALIDCALL.\n");
        return D3DERR_INVALIDCALL;
    }

    wined3d_mutex_lock();
    hr = wined3d_device_set_cursor_properties(device->wined3d_device,
            hotspot_x, hotspot_y, bitmap_impl->wined3d_texture, bitmap_impl->sub_resource_idx);
    wined3d_mutex_unlock();

    return hr;
}

static void WINAPI d3d8_device_SetCursorPosition(IDirect3DDevice8 *iface, UINT x, UINT y, DWORD flags)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);

    TRACE("iface %p, x %u, y %u, flags %#x.\n", iface, x, y, flags);

    wined3d_mutex_lock();
    wined3d_device_set_cursor_position(device->wined3d_device, x, y, flags);
    wined3d_mutex_unlock();
}

static BOOL WINAPI d3d8_device_ShowCursor(IDirect3DDevice8 *iface, BOOL show)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    BOOL ret;

    TRACE("iface %p, show %#x.\n", iface, show);

    wined3d_mutex_lock();
    ret = wined3d_device_show_cursor(device->wined3d_device, show);
    wined3d_mutex_unlock();

    return ret;
}

static HRESULT WINAPI d3d8_device_CreateAdditionalSwapChain(IDirect3DDevice8 *iface,
        D3DPRESENT_PARAMETERS *present_parameters, IDirect3DSwapChain8 **swapchain)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    struct wined3d_swapchain_desc desc;
    struct d3d8_swapchain *object;
    UINT i, count;
    HRESULT hr;

    TRACE("iface %p, present_parameters %p, swapchain %p.\n",
            iface, present_parameters, swapchain);

    if (!present_parameters->Windowed)
    {
        WARN("Trying to create an additional fullscreen swapchain, returning D3DERR_INVALIDCALL.\n");
        return D3DERR_INVALIDCALL;
    }

    wined3d_mutex_lock();
    count = wined3d_device_get_swapchain_count(device->wined3d_device);
    for (i = 0; i < count; ++i)
    {
        struct wined3d_swapchain *wined3d_swapchain;

        wined3d_swapchain = wined3d_device_get_swapchain(device->wined3d_device, i);
        wined3d_swapchain_get_desc(wined3d_swapchain, &desc);

        if (!desc.windowed)
        {
            wined3d_mutex_unlock();
            WARN("Trying to create an additional swapchain in fullscreen mode, returning D3DERR_INVALIDCALL.\n");
            return D3DERR_INVALIDCALL;
        }
    }
    wined3d_mutex_unlock();

    if (!wined3d_swapchain_desc_from_present_parameters(&desc, present_parameters))
        return D3DERR_INVALIDCALL;
    if (SUCCEEDED(hr = d3d8_swapchain_create(device, &desc, &object)))
        *swapchain = &object->IDirect3DSwapChain8_iface;
    present_parameters_from_wined3d_swapchain_desc(present_parameters, &desc);

    return hr;
}

static HRESULT CDECL reset_enum_callback(struct wined3d_resource *resource)
{
    struct wined3d_resource_desc desc;

    wined3d_resource_get_desc(resource, &desc);
    if (desc.pool == WINED3D_POOL_DEFAULT)
    {
        struct d3d8_surface *surface;

        if (desc.resource_type == WINED3D_RTYPE_TEXTURE)
        {
            IUnknown *parent = wined3d_resource_get_parent(resource);
            IDirect3DBaseTexture8 *texture;

            if (SUCCEEDED(IUnknown_QueryInterface(parent, &IID_IDirect3DBaseTexture8, (void **)&texture)))
            {
                IDirect3DBaseTexture8_Release(texture);
                WARN("Texture %p (resource %p) in pool D3DPOOL_DEFAULT blocks the Reset call.\n", texture, resource);
                return D3DERR_DEVICELOST;
            }

            return D3D_OK;
        }

        if (desc.resource_type != WINED3D_RTYPE_SURFACE)
        {
            WARN("Resource %p in pool D3DPOOL_DEFAULT blocks the Reset call.\n", resource);
            return D3DERR_DEVICELOST;
        }

        surface = wined3d_resource_get_parent(resource);
        if (surface->resource.refcount)
        {
            WARN("Surface %p (resource %p) in pool D3DPOOL_DEFAULT blocks the Reset call.\n", surface, resource);
            return D3DERR_DEVICELOST;
        }

        WARN("Surface %p (resource %p) is an implicit resource with ref 0.\n", surface, resource);
    }

    return D3D_OK;
}

static HRESULT WINAPI d3d8_device_Reset(IDirect3DDevice8 *iface,
        D3DPRESENT_PARAMETERS *present_parameters)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    struct wined3d_swapchain_desc swapchain_desc;
    HRESULT hr;

    TRACE("iface %p, present_parameters %p.\n", iface, present_parameters);

    if (device->device_state == D3D8_DEVICE_STATE_LOST)
    {
        WARN("App not active, returning D3DERR_DEVICELOST.\n");
        return D3DERR_DEVICELOST;
    }
    if (!wined3d_swapchain_desc_from_present_parameters(&swapchain_desc, present_parameters))
        return D3DERR_INVALIDCALL;

    wined3d_mutex_lock();

    if (device->vertex_buffer)
    {
        wined3d_buffer_decref(device->vertex_buffer);
        device->vertex_buffer = NULL;
        device->vertex_buffer_size = 0;
    }
    if (device->index_buffer)
    {
        wined3d_buffer_decref(device->index_buffer);
        device->index_buffer = NULL;
        device->index_buffer_size = 0;
    }

    if (SUCCEEDED(hr = wined3d_device_reset(device->wined3d_device, &swapchain_desc,
            NULL, reset_enum_callback, TRUE)))
    {
        present_parameters->BackBufferCount = swapchain_desc.backbuffer_count;
        wined3d_device_set_render_state(device->wined3d_device, WINED3D_RS_POINTSIZE_MIN, 0);
        device->device_state = D3D8_DEVICE_STATE_OK;
    }
    else
    {
        device->device_state = D3D8_DEVICE_STATE_NOT_RESET;
    }
    wined3d_mutex_unlock();

    return hr;
}

static HRESULT WINAPI d3d8_device_Present(IDirect3DDevice8 *iface, const RECT *src_rect,
        const RECT *dst_rect, HWND dst_window_override, const RGNDATA *dirty_region)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);

    TRACE("iface %p, src_rect %s, dst_rect %s, dst_window_override %p, dirty_region %p.\n",
            iface, wine_dbgstr_rect(src_rect), wine_dbgstr_rect(dst_rect), dst_window_override, dirty_region);

    /* Fraps does not hook IDirect3DDevice8::Present regardless of the hotpatch
     * attribute. It only hooks IDirect3DSwapChain8::Present. Yet it properly
     * shows a framerate on Windows in applications that only call the device
     * method, like e.g. the dx8 sdk samples. The conclusion is that native
     * calls the swapchain's public method from the device. */
    return IDirect3DSwapChain8_Present(&device->implicit_swapchain->IDirect3DSwapChain8_iface,
            src_rect, dst_rect, dst_window_override, dirty_region);
}

static HRESULT WINAPI d3d8_device_GetBackBuffer(IDirect3DDevice8 *iface,
        UINT backbuffer_idx, D3DBACKBUFFER_TYPE backbuffer_type, IDirect3DSurface8 **backbuffer)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    struct wined3d_swapchain *wined3d_swapchain;
    struct wined3d_resource *wined3d_resource;
    struct wined3d_texture *wined3d_texture;
    struct d3d8_surface *surface_impl;

    TRACE("iface %p, backbuffer_idx %u, backbuffer_type %#x, backbuffer %p.\n",
            iface, backbuffer_idx, backbuffer_type, backbuffer);

    /* backbuffer_type is ignored by native. */

    /* No need to check for backbuffer == NULL, Windows crashes in that case. */
    wined3d_mutex_lock();

    wined3d_swapchain = device->implicit_swapchain->wined3d_swapchain;
    if (!(wined3d_texture = wined3d_swapchain_get_back_buffer(wined3d_swapchain, backbuffer_idx)))
    {
        wined3d_mutex_unlock();
        *backbuffer = NULL;
        return D3DERR_INVALIDCALL;
    }

    wined3d_resource = wined3d_texture_get_sub_resource(wined3d_texture, 0);
    surface_impl = wined3d_resource_get_parent(wined3d_resource);
    *backbuffer = &surface_impl->IDirect3DSurface8_iface;
    IDirect3DSurface8_AddRef(*backbuffer);

    wined3d_mutex_unlock();
    return D3D_OK;
}

static HRESULT WINAPI d3d8_device_GetRasterStatus(IDirect3DDevice8 *iface, D3DRASTER_STATUS *raster_status)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    HRESULT hr;

    TRACE("iface %p, raster_status %p.\n", iface, raster_status);

    wined3d_mutex_lock();
    hr = wined3d_device_get_raster_status(device->wined3d_device, 0, (struct wined3d_raster_status *)raster_status);
    wined3d_mutex_unlock();

    return hr;
}

static void WINAPI d3d8_device_SetGammaRamp(IDirect3DDevice8 *iface, DWORD flags, const D3DGAMMARAMP *ramp)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);

    TRACE("iface %p, flags %#x, ramp %p.\n", iface, flags, ramp);

    /* Note: D3DGAMMARAMP is compatible with struct wined3d_gamma_ramp. */
    wined3d_mutex_lock();
    wined3d_device_set_gamma_ramp(device->wined3d_device, 0, flags, (const struct wined3d_gamma_ramp *)ramp);
    wined3d_mutex_unlock();
}

static void WINAPI d3d8_device_GetGammaRamp(IDirect3DDevice8 *iface, D3DGAMMARAMP *ramp)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);

    TRACE("iface %p, ramp %p.\n", iface, ramp);

    /* Note: D3DGAMMARAMP is compatible with struct wined3d_gamma_ramp. */
    wined3d_mutex_lock();
    wined3d_device_get_gamma_ramp(device->wined3d_device, 0, (struct wined3d_gamma_ramp *)ramp);
    wined3d_mutex_unlock();
}

static HRESULT WINAPI d3d8_device_CreateTexture(IDirect3DDevice8 *iface,
        UINT width, UINT height, UINT levels, DWORD usage, D3DFORMAT format,
        D3DPOOL pool, IDirect3DTexture8 **texture)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    struct d3d8_texture *object;
    HRESULT hr;

    TRACE("iface %p, width %u, height %u, levels %u, usage %#x, format %#x, pool %#x, texture %p.\n",
            iface, width, height, levels, usage, format, pool, texture);

    *texture = NULL;
    object = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*object));
    if (!object)
        return D3DERR_OUTOFVIDEOMEMORY;

    hr = texture_init(object, device, width, height, levels, usage, format, pool);
    if (FAILED(hr))
    {
        WARN("Failed to initialize texture, hr %#x.\n", hr);
        HeapFree(GetProcessHeap(), 0, object);
        return hr;
    }

    TRACE("Created texture %p.\n", object);
    *texture = (IDirect3DTexture8 *)&object->IDirect3DBaseTexture8_iface;

    return D3D_OK;
}

static HRESULT WINAPI d3d8_device_CreateVolumeTexture(IDirect3DDevice8 *iface,
        UINT width, UINT height, UINT depth, UINT levels, DWORD usage, D3DFORMAT format,
        D3DPOOL pool, IDirect3DVolumeTexture8 **texture)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    struct d3d8_texture *object;
    HRESULT hr;

    TRACE("iface %p, width %u, height %u, depth %u, levels %u, usage %#x, format %#x, pool %#x, texture %p.\n",
            iface, width, height, depth, levels, usage, format, pool, texture);

    *texture = NULL;
    object = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*object));
    if (!object)
        return D3DERR_OUTOFVIDEOMEMORY;

    hr = volumetexture_init(object, device, width, height, depth, levels, usage, format, pool);
    if (FAILED(hr))
    {
        WARN("Failed to initialize volume texture, hr %#x.\n", hr);
        HeapFree(GetProcessHeap(), 0, object);
        return hr;
    }

    TRACE("Created volume texture %p.\n", object);
    *texture = (IDirect3DVolumeTexture8 *)&object->IDirect3DBaseTexture8_iface;

    return D3D_OK;
}

static HRESULT WINAPI d3d8_device_CreateCubeTexture(IDirect3DDevice8 *iface, UINT edge_length,
        UINT levels, DWORD usage, D3DFORMAT format, D3DPOOL pool, IDirect3DCubeTexture8 **texture)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    struct d3d8_texture *object;
    HRESULT hr;

    TRACE("iface %p, edge_length %u, levels %u, usage %#x, format %#x, pool %#x, texture %p.\n",
            iface, edge_length, levels, usage, format, pool, texture);

    *texture = NULL;
    object = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*object));
    if (!object)
        return D3DERR_OUTOFVIDEOMEMORY;

    hr = cubetexture_init(object, device, edge_length, levels, usage, format, pool);
    if (FAILED(hr))
    {
        WARN("Failed to initialize cube texture, hr %#x.\n", hr);
        HeapFree(GetProcessHeap(), 0, object);
        return hr;
    }

    TRACE("Created cube texture %p.\n", object);
    *texture = (IDirect3DCubeTexture8 *)&object->IDirect3DBaseTexture8_iface;

    return hr;
}

static HRESULT WINAPI d3d8_device_CreateVertexBuffer(IDirect3DDevice8 *iface, UINT size,
        DWORD usage, DWORD fvf, D3DPOOL pool, IDirect3DVertexBuffer8 **buffer)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    struct d3d8_vertexbuffer *object;
    HRESULT hr;

    TRACE("iface %p, size %u, usage %#x, fvf %#x, pool %#x, buffer %p.\n",
            iface, size, usage, fvf, pool, buffer);

    object = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*object));
    if (!object)
        return D3DERR_OUTOFVIDEOMEMORY;

    hr = vertexbuffer_init(object, device, size, usage, fvf, pool);
    if (FAILED(hr))
    {
        WARN("Failed to initialize vertex buffer, hr %#x.\n", hr);
        HeapFree(GetProcessHeap(), 0, object);
        return hr;
    }

    TRACE("Created vertex buffer %p.\n", object);
    *buffer = &object->IDirect3DVertexBuffer8_iface;

    return D3D_OK;
}

static HRESULT WINAPI d3d8_device_CreateIndexBuffer(IDirect3DDevice8 *iface, UINT size,
        DWORD usage, D3DFORMAT format, D3DPOOL pool, IDirect3DIndexBuffer8 **buffer)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    struct d3d8_indexbuffer *object;
    HRESULT hr;

    TRACE("iface %p, size %u, usage %#x, format %#x, pool %#x, buffer %p.\n",
            iface, size, usage, format, pool, buffer);

    object = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*object));
    if (!object)
        return D3DERR_OUTOFVIDEOMEMORY;

    hr = indexbuffer_init(object, device, size, usage, format, pool);
    if (FAILED(hr))
    {
        WARN("Failed to initialize index buffer, hr %#x.\n", hr);
        HeapFree(GetProcessHeap(), 0, object);
        return hr;
    }

    TRACE("Created index buffer %p.\n", object);
    *buffer = &object->IDirect3DIndexBuffer8_iface;

    return D3D_OK;
}

static HRESULT d3d8_device_create_surface(struct d3d8_device *device, UINT width, UINT height,
        D3DFORMAT format, DWORD flags, IDirect3DSurface8 **surface, UINT usage, D3DPOOL pool,
        D3DMULTISAMPLE_TYPE multisample_type, DWORD multisample_quality)
{
    struct wined3d_resource *sub_resource;
    struct wined3d_resource_desc desc;
    struct d3d8_surface *surface_impl;
    struct wined3d_texture *texture;
    HRESULT hr;

    TRACE("device %p, width %u, height %u, format %#x, flags %#x, surface %p,\n"
            "\tusage %#x, pool %#x, multisample_type %#x, multisample_quality %u.\n",
            device, width, height, format, flags, surface,
            usage, pool, multisample_type, multisample_quality);

    desc.resource_type = WINED3D_RTYPE_TEXTURE;
    desc.format = wined3dformat_from_d3dformat(format);
    desc.multisample_type = multisample_type;
    desc.multisample_quality = multisample_quality;
    desc.usage = usage & WINED3DUSAGE_MASK;
    desc.pool = pool;
    desc.width = width;
    desc.height = height;
    desc.depth = 1;
    desc.size = 0;

    wined3d_mutex_lock();

    if (FAILED(hr = wined3d_texture_create(device->wined3d_device, &desc,
            1, flags, NULL, NULL, &d3d8_null_wined3d_parent_ops, &texture)))
    {
        wined3d_mutex_unlock();
        WARN("Failed to create texture, hr %#x.\n", hr);
        return hr;
    }

    sub_resource = wined3d_texture_get_sub_resource(texture, 0);
    surface_impl = wined3d_resource_get_parent(sub_resource);
    surface_impl->parent_device = &device->IDirect3DDevice8_iface;
    *surface = &surface_impl->IDirect3DSurface8_iface;
    IDirect3DSurface8_AddRef(*surface);
    wined3d_texture_decref(texture);

    wined3d_mutex_unlock();

    return D3D_OK;
}

static HRESULT WINAPI d3d8_device_CreateRenderTarget(IDirect3DDevice8 *iface, UINT width,
        UINT height, D3DFORMAT format, D3DMULTISAMPLE_TYPE multisample_type, BOOL lockable,
        IDirect3DSurface8 **surface)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    DWORD flags = 0;

    TRACE("iface %p, width %u, height %u, format %#x, multisample_type %#x, lockable %#x, surface %p.\n",
            iface, width, height, format, multisample_type, lockable, surface);

    *surface = NULL;
    if (lockable)
        flags |= WINED3D_SURFACE_MAPPABLE;

    return d3d8_device_create_surface(device, width, height, format, flags, surface,
            D3DUSAGE_RENDERTARGET, D3DPOOL_DEFAULT, multisample_type, 0);
}

static HRESULT WINAPI d3d8_device_CreateDepthStencilSurface(IDirect3DDevice8 *iface,
        UINT width, UINT height, D3DFORMAT format, D3DMULTISAMPLE_TYPE multisample_type,
        IDirect3DSurface8 **surface)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);

    TRACE("iface %p, width %u, height %u, format %#x, multisample_type %#x, surface %p.\n",
            iface, width, height, format, multisample_type, surface);

    *surface = NULL;

    /* TODO: Verify that Discard is false */
    return d3d8_device_create_surface(device, width, height, format, WINED3D_SURFACE_MAPPABLE,
            surface, D3DUSAGE_DEPTHSTENCIL, D3DPOOL_DEFAULT, multisample_type, 0);
}

/*  IDirect3DDevice8Impl::CreateImageSurface returns surface with pool type SYSTEMMEM */
static HRESULT WINAPI d3d8_device_CreateImageSurface(IDirect3DDevice8 *iface, UINT width,
        UINT height, D3DFORMAT format, IDirect3DSurface8 **surface)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);

    TRACE("iface %p, width %u, height %u, format %#x, surface %p.\n",
            iface, width, height, format, surface);

    *surface = NULL;

    return d3d8_device_create_surface(device, width, height, format, WINED3D_SURFACE_MAPPABLE,
            surface, 0, D3DPOOL_SYSTEMMEM, D3DMULTISAMPLE_NONE, 0);
}

static HRESULT WINAPI d3d8_device_CopyRects(IDirect3DDevice8 *iface,
        IDirect3DSurface8 *src_surface, const RECT *src_rects, UINT rect_count,
        IDirect3DSurface8 *dst_surface, const POINT *dst_points)
{
    struct d3d8_surface *src = unsafe_impl_from_IDirect3DSurface8(src_surface);
    struct d3d8_surface *dst = unsafe_impl_from_IDirect3DSurface8(dst_surface);
    enum wined3d_format_id src_format, dst_format;
    struct wined3d_resource_desc wined3d_desc;
    struct wined3d_resource *wined3d_resource;
    UINT src_w, src_h;

    TRACE("iface %p, src_surface %p, src_rects %p, rect_count %u, dst_surface %p, dst_points %p.\n",
            iface, src_surface, src_rects, rect_count, dst_surface, dst_points);

    /* Check that the source texture is in WINED3D_POOL_SYSTEM_MEM and the
     * destination texture is in WINED3D_POOL_DEFAULT. */

    wined3d_mutex_lock();
    wined3d_resource = wined3d_texture_get_sub_resource(src->wined3d_texture, src->sub_resource_idx);
    wined3d_resource_get_desc(wined3d_resource, &wined3d_desc);
    if (wined3d_desc.usage & WINED3DUSAGE_DEPTHSTENCIL)
    {
        WARN("Source %p is a depth stencil surface, returning D3DERR_INVALIDCALL.\n", src_surface);
        wined3d_mutex_unlock();
        return D3DERR_INVALIDCALL;
    }
    src_format = wined3d_desc.format;
    src_w = wined3d_desc.width;
    src_h = wined3d_desc.height;

    wined3d_resource = wined3d_texture_get_sub_resource(dst->wined3d_texture, dst->sub_resource_idx);
    wined3d_resource_get_desc(wined3d_resource, &wined3d_desc);
    if (wined3d_desc.usage & WINED3DUSAGE_DEPTHSTENCIL)
    {
        WARN("Destination %p is a depth stencil surface, returning D3DERR_INVALIDCALL.\n", dst_surface);
        wined3d_mutex_unlock();
        return D3DERR_INVALIDCALL;
    }
    dst_format = wined3d_desc.format;

    /* Check that the source and destination formats match */
    if (src_format != dst_format)
    {
        WARN("Source %p format must match the destination %p format, returning D3DERR_INVALIDCALL.\n",
                src_surface, dst_surface);
        wined3d_mutex_unlock();
        return D3DERR_INVALIDCALL;
    }

    /* Quick if complete copy ... */
    if (!rect_count && !src_rects && !dst_points)
    {
        RECT rect = {0, 0, src_w, src_h};
        wined3d_texture_blt(dst->wined3d_texture, dst->sub_resource_idx, &rect,
                src->wined3d_texture, src->sub_resource_idx, &rect, 0, NULL, WINED3D_TEXF_POINT);
    }
    else
    {
        unsigned int i;
        /* Copy rect by rect */
        if (src_rects && dst_points)
        {
            for (i = 0; i < rect_count; ++i)
            {
                UINT w = src_rects[i].right - src_rects[i].left;
                UINT h = src_rects[i].bottom - src_rects[i].top;
                RECT dst_rect = {dst_points[i].x, dst_points[i].y,
                        dst_points[i].x + w, dst_points[i].y + h};

                wined3d_texture_blt(dst->wined3d_texture, dst->sub_resource_idx, &dst_rect,
                        src->wined3d_texture, src->sub_resource_idx, &src_rects[i], 0, NULL, WINED3D_TEXF_POINT);
            }
        }
        else
        {
            for (i = 0; i < rect_count; ++i)
            {
                UINT w = src_rects[i].right - src_rects[i].left;
                UINT h = src_rects[i].bottom - src_rects[i].top;
                RECT dst_rect = {0, 0, w, h};

                wined3d_texture_blt(dst->wined3d_texture, dst->sub_resource_idx, &dst_rect,
                        src->wined3d_texture, src->sub_resource_idx, &src_rects[i], 0, NULL, WINED3D_TEXF_POINT);
            }
        }
    }
    wined3d_mutex_unlock();

    return WINED3D_OK;
}

static HRESULT WINAPI d3d8_device_UpdateTexture(IDirect3DDevice8 *iface,
        IDirect3DBaseTexture8 *src_texture, IDirect3DBaseTexture8 *dst_texture)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    struct d3d8_texture *src_impl, *dst_impl;
    HRESULT hr;

    TRACE("iface %p, src_texture %p, dst_texture %p.\n", iface, src_texture, dst_texture);

    src_impl = unsafe_impl_from_IDirect3DBaseTexture8(src_texture);
    dst_impl = unsafe_impl_from_IDirect3DBaseTexture8(dst_texture);

    wined3d_mutex_lock();
    hr = wined3d_device_update_texture(device->wined3d_device,
            src_impl->wined3d_texture, dst_impl->wined3d_texture);
    wined3d_mutex_unlock();

    return hr;
}

static HRESULT WINAPI d3d8_device_GetFrontBuffer(IDirect3DDevice8 *iface, IDirect3DSurface8 *dst_surface)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    struct d3d8_surface *dst_impl = unsafe_impl_from_IDirect3DSurface8(dst_surface);
    HRESULT hr;

    TRACE("iface %p, dst_surface %p.\n", iface, dst_surface);

    if (!dst_surface)
    {
        WARN("Invalid destination surface passed.\n");
        return D3DERR_INVALIDCALL;
    }

    wined3d_mutex_lock();
    hr = wined3d_swapchain_get_front_buffer_data(device->implicit_swapchain->wined3d_swapchain,
            dst_impl->wined3d_texture, dst_impl->sub_resource_idx);
    wined3d_mutex_unlock();

    return hr;
}

static HRESULT WINAPI d3d8_device_SetRenderTarget(IDirect3DDevice8 *iface,
        IDirect3DSurface8 *render_target, IDirect3DSurface8 *depth_stencil)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    struct d3d8_surface *rt_impl = unsafe_impl_from_IDirect3DSurface8(render_target);
    struct d3d8_surface *ds_impl = unsafe_impl_from_IDirect3DSurface8(depth_stencil);
    struct wined3d_rendertarget_view *original_dsv;
    HRESULT hr = D3D_OK;

    TRACE("iface %p, render_target %p, depth_stencil %p.\n", iface, render_target, depth_stencil);

    wined3d_mutex_lock();

    if (ds_impl)
    {
        struct wined3d_rendertarget_view *original_rtv;
        struct wined3d_resource_desc ds_desc, rt_desc;
        struct wined3d_resource *wined3d_resource;
        struct d3d8_surface *original_surface;

        /* If no render target is passed in check the size against the current RT */
        if (!render_target)
        {

            if (!(original_rtv = wined3d_device_get_rendertarget_view(device->wined3d_device, 0)))
            {
                wined3d_mutex_unlock();
                return D3DERR_NOTFOUND;
            }
            original_surface = wined3d_rendertarget_view_get_sub_resource_parent(original_rtv);
            wined3d_resource = wined3d_texture_get_sub_resource(original_surface->wined3d_texture, original_surface->sub_resource_idx);
        }
        else
            wined3d_resource = wined3d_texture_get_sub_resource(rt_impl->wined3d_texture, rt_impl->sub_resource_idx);
        wined3d_resource_get_desc(wined3d_resource, &rt_desc);

        wined3d_resource = wined3d_texture_get_sub_resource(ds_impl->wined3d_texture, ds_impl->sub_resource_idx);
        wined3d_resource_get_desc(wined3d_resource, &ds_desc);

        if (ds_desc.width < rt_desc.width || ds_desc.height < rt_desc.height)
        {
            WARN("Depth stencil is smaller than the render target, returning D3DERR_INVALIDCALL\n");
            wined3d_mutex_unlock();
            return D3DERR_INVALIDCALL;
        }
        if (ds_desc.multisample_type != rt_desc.multisample_type
                || ds_desc.multisample_quality != rt_desc.multisample_quality)
        {
            WARN("Multisample settings do not match, returning D3DERR_INVALIDCALL\n");
            wined3d_mutex_unlock();
            return D3DERR_INVALIDCALL;

        }
    }

    original_dsv = wined3d_device_get_depth_stencil_view(device->wined3d_device);
    wined3d_device_set_depth_stencil_view(device->wined3d_device,
            ds_impl ? d3d8_surface_get_rendertarget_view(ds_impl) : NULL);
    if (render_target && FAILED(hr = wined3d_device_set_rendertarget_view(device->wined3d_device, 0,
            d3d8_surface_get_rendertarget_view(rt_impl), TRUE)))
        wined3d_device_set_depth_stencil_view(device->wined3d_device, original_dsv);

    wined3d_mutex_unlock();

    return hr;
}

static HRESULT WINAPI d3d8_device_GetRenderTarget(IDirect3DDevice8 *iface, IDirect3DSurface8 **render_target)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    struct wined3d_rendertarget_view *wined3d_rtv;
    struct d3d8_surface *surface_impl;
    HRESULT hr;

    TRACE("iface %p, render_target %p.\n", iface, render_target);

    if (!render_target)
        return D3DERR_INVALIDCALL;

    wined3d_mutex_lock();
    if ((wined3d_rtv = wined3d_device_get_rendertarget_view(device->wined3d_device, 0)))
    {
        /* We want the sub resource parent here, since the view itself may be
         * internal to wined3d and may not have a parent. */
        surface_impl = wined3d_rendertarget_view_get_sub_resource_parent(wined3d_rtv);
        *render_target = &surface_impl->IDirect3DSurface8_iface;
        IDirect3DSurface8_AddRef(*render_target);
        hr = D3D_OK;
    }
    else
    {
        ERR("Failed to get wined3d render target.\n");
        *render_target = NULL;
        hr = D3DERR_NOTFOUND;
    }
    wined3d_mutex_unlock();

    return hr;
}

static HRESULT WINAPI d3d8_device_GetDepthStencilSurface(IDirect3DDevice8 *iface, IDirect3DSurface8 **depth_stencil)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    struct wined3d_rendertarget_view *wined3d_dsv;
    struct d3d8_surface *surface_impl;
    HRESULT hr = D3D_OK;

    TRACE("iface %p, depth_stencil %p.\n", iface, depth_stencil);

    if (!depth_stencil)
        return D3DERR_INVALIDCALL;

    wined3d_mutex_lock();
    if ((wined3d_dsv = wined3d_device_get_depth_stencil_view(device->wined3d_device)))
    {
        /* We want the sub resource parent here, since the view itself may be
         * internal to wined3d and may not have a parent. */
        surface_impl = wined3d_rendertarget_view_get_sub_resource_parent(wined3d_dsv);
        *depth_stencil = &surface_impl->IDirect3DSurface8_iface;
        IDirect3DSurface8_AddRef(*depth_stencil);
    }
    else
    {
        hr = D3DERR_NOTFOUND;
        *depth_stencil = NULL;
    }
    wined3d_mutex_unlock();

    return hr;
}

static HRESULT WINAPI d3d8_device_BeginScene(IDirect3DDevice8 *iface)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    HRESULT hr;

    TRACE("iface %p.\n", iface);

    wined3d_mutex_lock();
    hr = wined3d_device_begin_scene(device->wined3d_device);
    wined3d_mutex_unlock();

    return hr;
}

static HRESULT WINAPI DECLSPEC_HOTPATCH d3d8_device_EndScene(IDirect3DDevice8 *iface)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    HRESULT hr;

    TRACE("iface %p.\n", iface);

    wined3d_mutex_lock();
    hr = wined3d_device_end_scene(device->wined3d_device);
    wined3d_mutex_unlock();

    return hr;
}

static HRESULT WINAPI d3d8_device_Clear(IDirect3DDevice8 *iface, DWORD rect_count,
        const D3DRECT *rects, DWORD flags, D3DCOLOR color, float z, DWORD stencil)
{
    const struct wined3d_color c =
    {
        ((color >> 16) & 0xff) / 255.0f,
        ((color >>  8) & 0xff) / 255.0f,
        (color & 0xff) / 255.0f,
        ((color >> 24) & 0xff) / 255.0f,
    };
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    HRESULT hr;

    TRACE("iface %p, rect_count %u, rects %p, flags %#x, color 0x%08x, z %.8e, stencil %u.\n",
            iface, rect_count, rects, flags, color, z, stencil);

    wined3d_mutex_lock();
    hr = wined3d_device_clear(device->wined3d_device, rect_count, (const RECT *)rects, flags, &c, z, stencil);
    wined3d_mutex_unlock();

    return hr;
}

static HRESULT WINAPI d3d8_device_SetTransform(IDirect3DDevice8 *iface,
        D3DTRANSFORMSTATETYPE state, const D3DMATRIX *matrix)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);

    TRACE("iface %p, state %#x, matrix %p.\n", iface, state, matrix);

    /* Note: D3DMATRIX is compatible with struct wined3d_matrix. */
    wined3d_mutex_lock();
    wined3d_device_set_transform(device->wined3d_device, state, (const struct wined3d_matrix *)matrix);
    wined3d_mutex_unlock();

    return D3D_OK;
}

static HRESULT WINAPI d3d8_device_GetTransform(IDirect3DDevice8 *iface,
        D3DTRANSFORMSTATETYPE state, D3DMATRIX *matrix)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);

    TRACE("iface %p, state %#x, matrix %p.\n", iface, state, matrix);

    /* Note: D3DMATRIX is compatible with struct wined3d_matrix. */
    wined3d_mutex_lock();
    wined3d_device_get_transform(device->wined3d_device, state, (struct wined3d_matrix *)matrix);
    wined3d_mutex_unlock();

    return D3D_OK;
}

static HRESULT WINAPI d3d8_device_MultiplyTransform(IDirect3DDevice8 *iface,
        D3DTRANSFORMSTATETYPE state, const D3DMATRIX *matrix)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);

    TRACE("iface %p, state %#x, matrix %p.\n", iface, state, matrix);

    /* Note: D3DMATRIX is compatible with struct wined3d_matrix. */
    wined3d_mutex_lock();
    wined3d_device_multiply_transform(device->wined3d_device, state, (const struct wined3d_matrix *)matrix);
    wined3d_mutex_unlock();

    return D3D_OK;
}

static HRESULT WINAPI d3d8_device_SetViewport(IDirect3DDevice8 *iface, const D3DVIEWPORT8 *viewport)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);

    TRACE("iface %p, viewport %p.\n", iface, viewport);

    /* Note: D3DVIEWPORT8 is compatible with struct wined3d_viewport. */
    wined3d_mutex_lock();
    wined3d_device_set_viewport(device->wined3d_device, (const struct wined3d_viewport *)viewport);
    wined3d_mutex_unlock();

    return D3D_OK;
}

static HRESULT WINAPI d3d8_device_GetViewport(IDirect3DDevice8 *iface, D3DVIEWPORT8 *viewport)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);

    TRACE("iface %p, viewport %p.\n", iface, viewport);

    /* Note: D3DVIEWPORT8 is compatible with struct wined3d_viewport. */
    wined3d_mutex_lock();
    wined3d_device_get_viewport(device->wined3d_device, (struct wined3d_viewport *)viewport);
    wined3d_mutex_unlock();

    return D3D_OK;
}

static HRESULT WINAPI d3d8_device_SetMaterial(IDirect3DDevice8 *iface, const D3DMATERIAL8 *material)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);

    TRACE("iface %p, material %p.\n", iface, material);

    /* Note: D3DMATERIAL8 is compatible with struct wined3d_material. */
    wined3d_mutex_lock();
    wined3d_device_set_material(device->wined3d_device, (const struct wined3d_material *)material);
    wined3d_mutex_unlock();

    return D3D_OK;
}

static HRESULT WINAPI d3d8_device_GetMaterial(IDirect3DDevice8 *iface, D3DMATERIAL8 *material)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);

    TRACE("iface %p, material %p.\n", iface, material);

    /* Note: D3DMATERIAL8 is compatible with struct wined3d_material. */
    wined3d_mutex_lock();
    wined3d_device_get_material(device->wined3d_device, (struct wined3d_material *)material);
    wined3d_mutex_unlock();

    return D3D_OK;
}

static HRESULT WINAPI d3d8_device_SetLight(IDirect3DDevice8 *iface, DWORD index, const D3DLIGHT8 *light)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    HRESULT hr;

    TRACE("iface %p, index %u, light %p.\n", iface, index, light);

    /* Note: D3DLIGHT8 is compatible with struct wined3d_light. */
    wined3d_mutex_lock();
    hr = wined3d_device_set_light(device->wined3d_device, index, (const struct wined3d_light *)light);
    wined3d_mutex_unlock();

    return hr;
}

static HRESULT WINAPI d3d8_device_GetLight(IDirect3DDevice8 *iface, DWORD index, D3DLIGHT8 *light)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    HRESULT hr;

    TRACE("iface %p, index %u, light %p.\n", iface, index, light);

    /* Note: D3DLIGHT8 is compatible with struct wined3d_light. */
    wined3d_mutex_lock();
    hr = wined3d_device_get_light(device->wined3d_device, index, (struct wined3d_light *)light);
    wined3d_mutex_unlock();

    return hr;
}

static HRESULT WINAPI d3d8_device_LightEnable(IDirect3DDevice8 *iface, DWORD index, BOOL enable)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    HRESULT hr;

    TRACE("iface %p, index %u, enable %#x.\n", iface, index, enable);

    wined3d_mutex_lock();
    hr = wined3d_device_set_light_enable(device->wined3d_device, index, enable);
    wined3d_mutex_unlock();

    return hr;
}

static HRESULT WINAPI d3d8_device_GetLightEnable(IDirect3DDevice8 *iface, DWORD index, BOOL *enable)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    HRESULT hr;

    TRACE("iface %p, index %u, enable %p.\n", iface, index, enable);

    wined3d_mutex_lock();
    hr = wined3d_device_get_light_enable(device->wined3d_device, index, enable);
    wined3d_mutex_unlock();

    return hr;
}

static HRESULT WINAPI d3d8_device_SetClipPlane(IDirect3DDevice8 *iface, DWORD index, const float *plane)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    HRESULT hr;

    TRACE("iface %p, index %u, plane %p.\n", iface, index, plane);

    wined3d_mutex_lock();
    hr = wined3d_device_set_clip_plane(device->wined3d_device, index, (const struct wined3d_vec4 *)plane);
    wined3d_mutex_unlock();

    return hr;
}

static HRESULT WINAPI d3d8_device_GetClipPlane(IDirect3DDevice8 *iface, DWORD index, float *plane)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    HRESULT hr;

    TRACE("iface %p, index %u, plane %p.\n", iface, index, plane);

    wined3d_mutex_lock();
    hr = wined3d_device_get_clip_plane(device->wined3d_device, index, (struct wined3d_vec4 *)plane);
    wined3d_mutex_unlock();

    return hr;
}

static HRESULT WINAPI d3d8_device_SetRenderState(IDirect3DDevice8 *iface,
        D3DRENDERSTATETYPE state, DWORD value)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);

    TRACE("iface %p, state %#x, value %#x.\n", iface, state, value);

    wined3d_mutex_lock();
    switch (state)
    {
        case D3DRS_ZBIAS:
            wined3d_device_set_render_state(device->wined3d_device, WINED3D_RS_DEPTHBIAS, value);
            break;

        default:
            wined3d_device_set_render_state(device->wined3d_device, state, value);
    }
    wined3d_mutex_unlock();

    return D3D_OK;
}

static HRESULT WINAPI d3d8_device_GetRenderState(IDirect3DDevice8 *iface,
        D3DRENDERSTATETYPE state, DWORD *value)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);

    TRACE("iface %p, state %#x, value %p.\n", iface, state, value);

    wined3d_mutex_lock();
    switch (state)
    {
        case D3DRS_ZBIAS:
            *value = wined3d_device_get_render_state(device->wined3d_device, WINED3D_RS_DEPTHBIAS);
            break;

        default:
            *value = wined3d_device_get_render_state(device->wined3d_device, state);
    }
    wined3d_mutex_unlock();

    return D3D_OK;
}

static HRESULT WINAPI d3d8_device_BeginStateBlock(IDirect3DDevice8 *iface)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    HRESULT hr;

    TRACE("iface %p.\n", iface);

    wined3d_mutex_lock();
    hr = wined3d_device_begin_stateblock(device->wined3d_device);
    wined3d_mutex_unlock();

    return hr;
}

static HRESULT WINAPI d3d8_device_EndStateBlock(IDirect3DDevice8 *iface, DWORD *token)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    struct wined3d_stateblock *stateblock;
    HRESULT hr;

    TRACE("iface %p, token %p.\n", iface, token);

    /* Tell wineD3D to endstateblock before anything else (in case we run out
     * of memory later and cause locking problems)
     */
    wined3d_mutex_lock();
    hr = wined3d_device_end_stateblock(device->wined3d_device, &stateblock);
    if (FAILED(hr))
    {
        WARN("IWineD3DDevice_EndStateBlock returned an error\n");
        wined3d_mutex_unlock();
        return hr;
    }

    *token = d3d8_allocate_handle(&device->handle_table, stateblock, D3D8_HANDLE_SB);
    wined3d_mutex_unlock();

    if (*token == D3D8_INVALID_HANDLE)
    {
        ERR("Failed to create a handle\n");
        wined3d_mutex_lock();
        wined3d_stateblock_decref(stateblock);
        wined3d_mutex_unlock();
        return E_FAIL;
    }
    ++*token;

    TRACE("Returning %#x (%p).\n", *token, stateblock);

    return hr;
}

static HRESULT WINAPI d3d8_device_ApplyStateBlock(IDirect3DDevice8 *iface, DWORD token)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    struct wined3d_stateblock *stateblock;

    TRACE("iface %p, token %#x.\n", iface, token);

    if (!token)
        return D3D_OK;

    wined3d_mutex_lock();
    stateblock = d3d8_get_object(&device->handle_table, token - 1, D3D8_HANDLE_SB);
    if (!stateblock)
    {
        WARN("Invalid handle (%#x) passed.\n", token);
        wined3d_mutex_unlock();
        return D3DERR_INVALIDCALL;
    }
    wined3d_stateblock_apply(stateblock);
    wined3d_mutex_unlock();

    return D3D_OK;
}

static HRESULT WINAPI d3d8_device_CaptureStateBlock(IDirect3DDevice8 *iface, DWORD token)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    struct wined3d_stateblock *stateblock;

    TRACE("iface %p, token %#x.\n", iface, token);

    wined3d_mutex_lock();
    stateblock = d3d8_get_object(&device->handle_table, token - 1, D3D8_HANDLE_SB);
    if (!stateblock)
    {
        WARN("Invalid handle (%#x) passed.\n", token);
        wined3d_mutex_unlock();
        return D3DERR_INVALIDCALL;
    }
    wined3d_stateblock_capture(stateblock);
    wined3d_mutex_unlock();

    return D3D_OK;
}

static HRESULT WINAPI d3d8_device_DeleteStateBlock(IDirect3DDevice8 *iface, DWORD token)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    struct wined3d_stateblock *stateblock;

    TRACE("iface %p, token %#x.\n", iface, token);

    wined3d_mutex_lock();
    stateblock = d3d8_free_handle(&device->handle_table, token - 1, D3D8_HANDLE_SB);

    if (!stateblock)
    {
        WARN("Invalid handle (%#x) passed.\n", token);
        wined3d_mutex_unlock();
        return D3DERR_INVALIDCALL;
    }

    if (wined3d_stateblock_decref(stateblock))
    {
        ERR("Stateblock %p has references left, this shouldn't happen.\n", stateblock);
    }
    wined3d_mutex_unlock();

    return D3D_OK;
}

static HRESULT WINAPI d3d8_device_CreateStateBlock(IDirect3DDevice8 *iface,
        D3DSTATEBLOCKTYPE type, DWORD *handle)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    struct wined3d_stateblock *stateblock;
    HRESULT hr;

    TRACE("iface %p, type %#x, handle %p.\n", iface, type, handle);

    if (type != D3DSBT_ALL
            && type != D3DSBT_PIXELSTATE
            && type != D3DSBT_VERTEXSTATE)
    {
        WARN("Unexpected stateblock type, returning D3DERR_INVALIDCALL\n");
        return D3DERR_INVALIDCALL;
    }

    wined3d_mutex_lock();
    hr = wined3d_stateblock_create(device->wined3d_device, (enum wined3d_stateblock_type)type, &stateblock);
    if (FAILED(hr))
    {
        wined3d_mutex_unlock();
        ERR("IWineD3DDevice_CreateStateBlock failed, hr %#x\n", hr);
        return hr;
    }

    *handle = d3d8_allocate_handle(&device->handle_table, stateblock, D3D8_HANDLE_SB);
    wined3d_mutex_unlock();

    if (*handle == D3D8_INVALID_HANDLE)
    {
        ERR("Failed to allocate a handle.\n");
        wined3d_mutex_lock();
        wined3d_stateblock_decref(stateblock);
        wined3d_mutex_unlock();
        return E_FAIL;
    }
    ++*handle;

    TRACE("Returning %#x (%p).\n", *handle, stateblock);

    return hr;
}

static HRESULT WINAPI d3d8_device_SetClipStatus(IDirect3DDevice8 *iface, const D3DCLIPSTATUS8 *clip_status)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    HRESULT hr;

    TRACE("iface %p, clip_status %p.\n", iface, clip_status);
    /* FIXME: Verify that D3DCLIPSTATUS8 ~= struct wined3d_clip_status. */

    wined3d_mutex_lock();
    hr = wined3d_device_set_clip_status(device->wined3d_device, (const struct wined3d_clip_status *)clip_status);
    wined3d_mutex_unlock();

    return hr;
}

static HRESULT WINAPI d3d8_device_GetClipStatus(IDirect3DDevice8 *iface, D3DCLIPSTATUS8 *clip_status)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    HRESULT hr;

    TRACE("iface %p, clip_status %p.\n", iface, clip_status);

    wined3d_mutex_lock();
    hr = wined3d_device_get_clip_status(device->wined3d_device, (struct wined3d_clip_status *)clip_status);
    wined3d_mutex_unlock();

    return hr;
}

static HRESULT WINAPI d3d8_device_GetTexture(IDirect3DDevice8 *iface, DWORD stage, IDirect3DBaseTexture8 **texture)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    struct wined3d_texture *wined3d_texture;
    struct d3d8_texture *texture_impl;

    TRACE("iface %p, stage %u, texture %p.\n", iface, stage, texture);

    if (!texture)
        return D3DERR_INVALIDCALL;

    wined3d_mutex_lock();
    if ((wined3d_texture = wined3d_device_get_texture(device->wined3d_device, stage)))
    {
        texture_impl = wined3d_texture_get_parent(wined3d_texture);
        *texture = &texture_impl->IDirect3DBaseTexture8_iface;
        IDirect3DBaseTexture8_AddRef(*texture);
    }
    else
    {
        *texture = NULL;
    }
    wined3d_mutex_unlock();

    return D3D_OK;
}

static HRESULT WINAPI d3d8_device_SetTexture(IDirect3DDevice8 *iface, DWORD stage, IDirect3DBaseTexture8 *texture)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    struct d3d8_texture *texture_impl;
    HRESULT hr;

    TRACE("iface %p, stage %u, texture %p.\n", iface, stage, texture);

    texture_impl = unsafe_impl_from_IDirect3DBaseTexture8(texture);

    wined3d_mutex_lock();
    hr = wined3d_device_set_texture(device->wined3d_device, stage,
            texture_impl ? texture_impl->wined3d_texture : NULL);
    wined3d_mutex_unlock();

    return hr;
}

static const struct tss_lookup
{
    BOOL sampler_state;
    enum wined3d_texture_stage_state state;
}
tss_lookup[] =
{
    {FALSE, WINED3D_TSS_INVALID},                   /*  0, unused */
    {FALSE, WINED3D_TSS_COLOR_OP},                  /*  1, D3DTSS_COLOROP */
    {FALSE, WINED3D_TSS_COLOR_ARG1},                /*  2, D3DTSS_COLORARG1 */
    {FALSE, WINED3D_TSS_COLOR_ARG2},                /*  3, D3DTSS_COLORARG2 */
    {FALSE, WINED3D_TSS_ALPHA_OP},                  /*  4, D3DTSS_ALPHAOP */
    {FALSE, WINED3D_TSS_ALPHA_ARG1},                /*  5, D3DTSS_ALPHAARG1 */
    {FALSE, WINED3D_TSS_ALPHA_ARG2},                /*  6, D3DTSS_ALPHAARG2 */
    {FALSE, WINED3D_TSS_BUMPENV_MAT00},             /*  7, D3DTSS_BUMPENVMAT00 */
    {FALSE, WINED3D_TSS_BUMPENV_MAT01},             /*  8, D3DTSS_BUMPENVMAT01 */
    {FALSE, WINED3D_TSS_BUMPENV_MAT10},             /*  9, D3DTSS_BUMPENVMAT10 */
    {FALSE, WINED3D_TSS_BUMPENV_MAT11},             /* 10, D3DTSS_BUMPENVMAT11 */
    {FALSE, WINED3D_TSS_TEXCOORD_INDEX},            /* 11, D3DTSS_TEXCOORDINDEX */
    {FALSE, WINED3D_TSS_INVALID},                   /* 12, unused */
    {TRUE,  WINED3D_SAMP_ADDRESS_U},                /* 13, D3DTSS_ADDRESSU */
    {TRUE,  WINED3D_SAMP_ADDRESS_V},                /* 14, D3DTSS_ADDRESSV */
    {TRUE,  WINED3D_SAMP_BORDER_COLOR},             /* 15, D3DTSS_BORDERCOLOR */
    {TRUE,  WINED3D_SAMP_MAG_FILTER},               /* 16, D3DTSS_MAGFILTER */
    {TRUE,  WINED3D_SAMP_MIN_FILTER},               /* 17, D3DTSS_MINFILTER */
    {TRUE,  WINED3D_SAMP_MIP_FILTER},               /* 18, D3DTSS_MIPFILTER */
    {TRUE,  WINED3D_SAMP_MIPMAP_LOD_BIAS},          /* 19, D3DTSS_MIPMAPLODBIAS */
    {TRUE,  WINED3D_SAMP_MAX_MIP_LEVEL},            /* 20, D3DTSS_MAXMIPLEVEL */
    {TRUE,  WINED3D_SAMP_MAX_ANISOTROPY},           /* 21, D3DTSS_MAXANISOTROPY */
    {FALSE, WINED3D_TSS_BUMPENV_LSCALE},            /* 22, D3DTSS_BUMPENVLSCALE */
    {FALSE, WINED3D_TSS_BUMPENV_LOFFSET},           /* 23, D3DTSS_BUMPENVLOFFSET */
    {FALSE, WINED3D_TSS_TEXTURE_TRANSFORM_FLAGS},   /* 24, D3DTSS_TEXTURETRANSFORMFLAGS */
    {TRUE,  WINED3D_SAMP_ADDRESS_W},                /* 25, D3DTSS_ADDRESSW */
    {FALSE, WINED3D_TSS_COLOR_ARG0},                /* 26, D3DTSS_COLORARG0 */
    {FALSE, WINED3D_TSS_ALPHA_ARG0},                /* 27, D3DTSS_ALPHAARG0 */
    {FALSE, WINED3D_TSS_RESULT_ARG},                /* 28, D3DTSS_RESULTARG */
};

static HRESULT WINAPI d3d8_device_GetTextureStageState(IDirect3DDevice8 *iface,
        DWORD stage, D3DTEXTURESTAGESTATETYPE Type, DWORD *value)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    const struct tss_lookup *l;

    TRACE("iface %p, stage %u, state %#x, value %p.\n", iface, stage, Type, value);

    if (Type >= sizeof(tss_lookup) / sizeof(*tss_lookup))
    {
        WARN("Invalid Type %#x passed.\n", Type);
        return D3D_OK;
    }

    l = &tss_lookup[Type];

    wined3d_mutex_lock();
    if (l->sampler_state)
        *value = wined3d_device_get_sampler_state(device->wined3d_device, stage, l->state);
    else
        *value = wined3d_device_get_texture_stage_state(device->wined3d_device, stage, l->state);
    wined3d_mutex_unlock();

    return D3D_OK;
}

static HRESULT WINAPI d3d8_device_SetTextureStageState(IDirect3DDevice8 *iface,
        DWORD stage, D3DTEXTURESTAGESTATETYPE type, DWORD value)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    const struct tss_lookup *l;

    TRACE("iface %p, stage %u, state %#x, value %#x.\n", iface, stage, type, value);

    if (type >= sizeof(tss_lookup) / sizeof(*tss_lookup))
    {
        WARN("Invalid type %#x passed.\n", type);
        return D3D_OK;
    }

    l = &tss_lookup[type];

    wined3d_mutex_lock();
    if (l->sampler_state)
        wined3d_device_set_sampler_state(device->wined3d_device, stage, l->state, value);
    else
        wined3d_device_set_texture_stage_state(device->wined3d_device, stage, l->state, value);
    wined3d_mutex_unlock();

    return D3D_OK;
}

static HRESULT WINAPI d3d8_device_ValidateDevice(IDirect3DDevice8 *iface, DWORD *pass_count)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    HRESULT hr;

    TRACE("iface %p, pass_count %p.\n", iface, pass_count);

    wined3d_mutex_lock();
    hr = wined3d_device_validate_device(device->wined3d_device, pass_count);
    wined3d_mutex_unlock();

    return hr;
}

static HRESULT WINAPI d3d8_device_GetInfo(IDirect3DDevice8 *iface,
        DWORD info_id, void *info, DWORD info_size)
{
    FIXME("iface %p, info_id %#x, info %p, info_size %u stub!\n", iface, info_id, info, info_size);

    return D3D_OK;
}

static HRESULT WINAPI d3d8_device_SetPaletteEntries(IDirect3DDevice8 *iface,
        UINT palette_idx, const PALETTEENTRY *entries)
{
    WARN("iface %p, palette_idx %u, entries %p unimplemented\n", iface, palette_idx, entries);

    /* GPUs stopped supporting palettized textures with the Shader Model 1 generation. Wined3d
     * does not have a d3d8/9-style palette API */

    return D3D_OK;
}

static HRESULT WINAPI d3d8_device_GetPaletteEntries(IDirect3DDevice8 *iface,
        UINT palette_idx, PALETTEENTRY *entries)
{
    FIXME("iface %p, palette_idx %u, entries %p unimplemented.\n", iface, palette_idx, entries);

    return D3DERR_INVALIDCALL;
}

static HRESULT WINAPI d3d8_device_SetCurrentTexturePalette(IDirect3DDevice8 *iface, UINT palette_idx)
{
    WARN("iface %p, palette_idx %u unimplemented.\n", iface, palette_idx);

    return D3D_OK;
}

static HRESULT WINAPI d3d8_device_GetCurrentTexturePalette(IDirect3DDevice8 *iface, UINT *palette_idx)
{
    FIXME("iface %p, palette_idx %p unimplemented.\n", iface, palette_idx);

    return D3DERR_INVALIDCALL;
}

static HRESULT WINAPI d3d8_device_DrawPrimitive(IDirect3DDevice8 *iface,
        D3DPRIMITIVETYPE primitive_type, UINT start_vertex, UINT primitive_count)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    HRESULT hr;

    TRACE("iface %p, primitive_type %#x, start_vertex %u, primitive_count %u.\n",
            iface, primitive_type, start_vertex, primitive_count);

    wined3d_mutex_lock();
    wined3d_device_set_primitive_type(device->wined3d_device, primitive_type);
    hr = wined3d_device_draw_primitive(device->wined3d_device, start_vertex,
            vertex_count_from_primitive_count(primitive_type, primitive_count));
    wined3d_mutex_unlock();

    return hr;
}

static HRESULT WINAPI d3d8_device_DrawIndexedPrimitive(IDirect3DDevice8 *iface,
        D3DPRIMITIVETYPE primitive_type, UINT min_vertex_idx, UINT vertex_count,
        UINT start_idx, UINT primitive_count)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    HRESULT hr;

    TRACE("iface %p, primitive_type %#x, min_vertex_idx %u, vertex_count %u, start_idx %u, primitive_count %u.\n",
            iface, primitive_type, min_vertex_idx, vertex_count, start_idx, primitive_count);

    wined3d_mutex_lock();
    wined3d_device_set_primitive_type(device->wined3d_device, primitive_type);
    hr = wined3d_device_draw_indexed_primitive(device->wined3d_device, start_idx,
            vertex_count_from_primitive_count(primitive_type, primitive_count));
    wined3d_mutex_unlock();

    return hr;
}

/* The caller is responsible for wined3d locking */
static HRESULT d3d8_device_prepare_vertex_buffer(struct d3d8_device *device, UINT min_size)
{
    HRESULT hr;

    if (device->vertex_buffer_size < min_size || !device->vertex_buffer)
    {
        UINT size = max(device->vertex_buffer_size * 2, min_size);
        struct wined3d_buffer *buffer;

        TRACE("Growing vertex buffer to %u bytes\n", size);

        hr = wined3d_buffer_create_vb(device->wined3d_device, size, WINED3DUSAGE_DYNAMIC | WINED3DUSAGE_WRITEONLY,
                WINED3D_POOL_DEFAULT, NULL, &d3d8_null_wined3d_parent_ops, &buffer);
        if (FAILED(hr))
        {
            ERR("(%p) wined3d_buffer_create_vb failed with hr = %08x\n", device, hr);
            return hr;
        }

        if (device->vertex_buffer)
            wined3d_buffer_decref(device->vertex_buffer);

        device->vertex_buffer = buffer;
        device->vertex_buffer_size = size;
        device->vertex_buffer_pos = 0;
    }
    return D3D_OK;
}

static HRESULT WINAPI d3d8_device_DrawPrimitiveUP(IDirect3DDevice8 *iface,
        D3DPRIMITIVETYPE primitive_type, UINT primitive_count, const void *data,
        UINT stride)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    HRESULT hr;
    UINT vtx_count = vertex_count_from_primitive_count(primitive_type, primitive_count);
    UINT size = vtx_count * stride;
    UINT vb_pos, align;
    BYTE *buffer_data;

    TRACE("iface %p, primitive_type %#x, primitive_count %u, data %p, stride %u.\n",
            iface, primitive_type, primitive_count, data, stride);

    if (!primitive_count)
    {
        WARN("primitive_count is 0, returning D3D_OK\n");
        return D3D_OK;
    }

    wined3d_mutex_lock();
    hr = d3d8_device_prepare_vertex_buffer(device, size);
    if (FAILED(hr))
        goto done;

    vb_pos = device->vertex_buffer_pos;
    align = vb_pos % stride;
    if (align) align = stride - align;
    if (vb_pos + size + align > device->vertex_buffer_size)
        vb_pos = 0;
    else
        vb_pos += align;

    hr = wined3d_buffer_map(device->vertex_buffer, vb_pos, size, &buffer_data,
            vb_pos ? WINED3D_MAP_NOOVERWRITE : WINED3D_MAP_DISCARD);
    if (FAILED(hr))
        goto done;
    memcpy(buffer_data, data, size);
    wined3d_buffer_unmap(device->vertex_buffer);
    device->vertex_buffer_pos = vb_pos + size;

    hr = wined3d_device_set_stream_source(device->wined3d_device, 0, device->vertex_buffer, 0, stride);
    if (FAILED(hr))
        goto done;

    wined3d_device_set_primitive_type(device->wined3d_device, primitive_type);
    hr = wined3d_device_draw_primitive(device->wined3d_device, vb_pos / stride, vtx_count);
    wined3d_device_set_stream_source(device->wined3d_device, 0, NULL, 0, 0);

done:
    wined3d_mutex_unlock();
    return hr;
}

/* The caller is responsible for wined3d locking */
static HRESULT d3d8_device_prepare_index_buffer(struct d3d8_device *device, UINT min_size)
{
    HRESULT hr;

    if (device->index_buffer_size < min_size || !device->index_buffer)
    {
        UINT size = max(device->index_buffer_size * 2, min_size);
        struct wined3d_buffer *buffer;

        TRACE("Growing index buffer to %u bytes\n", size);

        hr = wined3d_buffer_create_ib(device->wined3d_device, size, WINED3DUSAGE_DYNAMIC | WINED3DUSAGE_WRITEONLY,
                WINED3D_POOL_DEFAULT, NULL, &d3d8_null_wined3d_parent_ops, &buffer);
        if (FAILED(hr))
        {
            ERR("(%p) wined3d_buffer_create_ib failed with hr = %08x\n", device, hr);
            return hr;
        }

        if (device->index_buffer)
            wined3d_buffer_decref(device->index_buffer);

        device->index_buffer = buffer;
        device->index_buffer_size = size;
        device->index_buffer_pos = 0;
    }
    return D3D_OK;
}

static HRESULT WINAPI d3d8_device_DrawIndexedPrimitiveUP(IDirect3DDevice8 *iface,
        D3DPRIMITIVETYPE primitive_type, UINT min_vertex_idx, UINT vertex_count,
        UINT primitive_count, const void *index_data, D3DFORMAT index_format,
        const void *vertex_data, UINT vertex_stride)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    HRESULT hr;
    BYTE *buffer_data;

    UINT idx_count = vertex_count_from_primitive_count(primitive_type, primitive_count);
    UINT idx_fmt_size = index_format == D3DFMT_INDEX16 ? 2 : 4;
    UINT idx_size = idx_count * idx_fmt_size;
    UINT ib_pos;

    UINT vtx_size = vertex_count * vertex_stride;
    UINT vb_pos, align;

    TRACE("iface %p, primitive_type %#x, min_vertex_idx %u, vertex_count %u, primitive_count %u,\n"
            "index_data %p, index_format %#x, vertex_data %p, vertex_stride %u.\n",
            iface, primitive_type, min_vertex_idx, vertex_count, primitive_count,
            index_data, index_format, vertex_data, vertex_stride);

    if (!primitive_count)
    {
        WARN("primitive_count is 0, returning D3D_OK\n");
        return D3D_OK;
    }

    wined3d_mutex_lock();

    hr = d3d8_device_prepare_vertex_buffer(device, vtx_size);
    if (FAILED(hr))
        goto done;

    vb_pos = device->vertex_buffer_pos;
    align = vb_pos % vertex_stride;
    if (align) align = vertex_stride - align;
    if (vb_pos + vtx_size + align > device->vertex_buffer_size)
        vb_pos = 0;
    else
        vb_pos += align;

    hr = wined3d_buffer_map(device->vertex_buffer, vb_pos, vtx_size, &buffer_data,
            vb_pos ? WINED3D_MAP_NOOVERWRITE : WINED3D_MAP_DISCARD);
    if (FAILED(hr))
        goto done;
    memcpy(buffer_data, vertex_data, vtx_size);
    wined3d_buffer_unmap(device->vertex_buffer);
    device->vertex_buffer_pos = vb_pos + vtx_size;

    hr = d3d8_device_prepare_index_buffer(device, idx_size);
    if (FAILED(hr))
        goto done;

    ib_pos = device->index_buffer_pos;
    align = ib_pos % idx_fmt_size;
    if (align) align = idx_fmt_size - align;
    if (ib_pos + idx_size + align > device->index_buffer_size)
        ib_pos = 0;
    else
        ib_pos += align;

    hr = wined3d_buffer_map(device->index_buffer, ib_pos, idx_size, &buffer_data,
            ib_pos ? WINED3D_MAP_NOOVERWRITE : WINED3D_MAP_DISCARD);
    if (FAILED(hr))
        goto done;
    memcpy(buffer_data, index_data, idx_size);
    wined3d_buffer_unmap(device->index_buffer);
    device->index_buffer_pos = ib_pos + idx_size;

    hr = wined3d_device_set_stream_source(device->wined3d_device, 0, device->vertex_buffer, 0, vertex_stride);
    if (FAILED(hr))
        goto done;

    wined3d_device_set_index_buffer(device->wined3d_device, device->index_buffer,
            wined3dformat_from_d3dformat(index_format));
    wined3d_device_set_base_vertex_index(device->wined3d_device, vb_pos / vertex_stride);

    wined3d_device_set_primitive_type(device->wined3d_device, primitive_type);
    hr = wined3d_device_draw_indexed_primitive(device->wined3d_device, ib_pos / idx_fmt_size, idx_count);

    wined3d_device_set_stream_source(device->wined3d_device, 0, NULL, 0, 0);
    wined3d_device_set_index_buffer(device->wined3d_device, NULL, WINED3DFMT_UNKNOWN);
    wined3d_device_set_base_vertex_index(device->wined3d_device, 0);

done:
    wined3d_mutex_unlock();
    return hr;
}

static HRESULT WINAPI d3d8_device_ProcessVertices(IDirect3DDevice8 *iface, UINT src_start_idx,
        UINT dst_idx, UINT vertex_count, IDirect3DVertexBuffer8 *dst_buffer, DWORD flags)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    struct d3d8_vertexbuffer *dst = unsafe_impl_from_IDirect3DVertexBuffer8(dst_buffer);
    HRESULT hr;

    TRACE("iface %p, src_start_idx %u, dst_idx %u, vertex_count %u, dst_buffer %p, flags %#x.\n",
            iface, src_start_idx, dst_idx, vertex_count, dst_buffer, flags);

    wined3d_mutex_lock();
    hr = wined3d_device_process_vertices(device->wined3d_device, src_start_idx, dst_idx,
            vertex_count, dst->wined3d_buffer, NULL, flags, dst->fvf);
    wined3d_mutex_unlock();

    return hr;
}

static HRESULT WINAPI d3d8_device_CreateVertexShader(IDirect3DDevice8 *iface,
        const DWORD *declaration, const DWORD *byte_code, DWORD *shader, DWORD usage)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    struct d3d8_vertex_shader *object;
    DWORD shader_handle;
    DWORD handle;
    HRESULT hr;

    TRACE("iface %p, declaration %p, byte_code %p, shader %p, usage %#x.\n",
            iface, declaration, byte_code, shader, usage);

    object = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*object));
    if (!object)
    {
        *shader = 0;
        return E_OUTOFMEMORY;
    }

    wined3d_mutex_lock();
    handle = d3d8_allocate_handle(&device->handle_table, object, D3D8_HANDLE_VS);
    wined3d_mutex_unlock();
    if (handle == D3D8_INVALID_HANDLE)
    {
        ERR("Failed to allocate vertex shader handle.\n");
        HeapFree(GetProcessHeap(), 0, object);
        *shader = 0;
        return E_OUTOFMEMORY;
    }

    shader_handle = handle + VS_HIGHESTFIXEDFXF + 1;

    hr = d3d8_vertex_shader_init(object, device, declaration, byte_code, shader_handle, usage);
    if (FAILED(hr))
    {
        WARN("Failed to initialize vertex shader, hr %#x.\n", hr);
        wined3d_mutex_lock();
        d3d8_free_handle(&device->handle_table, handle, D3D8_HANDLE_VS);
        wined3d_mutex_unlock();
        HeapFree(GetProcessHeap(), 0, object);
        *shader = 0;
        return hr;
    }

    TRACE("Created vertex shader %p (handle %#x).\n", object, shader_handle);
    *shader = shader_handle;

    return D3D_OK;
}

static struct d3d8_vertex_declaration *d3d8_device_get_fvf_declaration(struct d3d8_device *device, DWORD fvf)
{
    struct d3d8_vertex_declaration *d3d8_declaration;
    struct FvfToDecl *convertedDecls = device->decls;
    int p, low, high; /* deliberately signed */
    HRESULT hr;

    TRACE("Searching for declaration for fvf %08x... ", fvf);

    low = 0;
    high = device->numConvertedDecls - 1;
    while (low <= high)
    {
        p = (low + high) >> 1;
        TRACE("%d ", p);

        if (convertedDecls[p].fvf == fvf)
        {
            TRACE("found %p\n", convertedDecls[p].declaration);
            return convertedDecls[p].declaration;
        }

        if (convertedDecls[p].fvf < fvf)
            low = p + 1;
        else
            high = p - 1;
    }
    TRACE("not found. Creating and inserting at position %d.\n", low);

    if (!(d3d8_declaration = HeapAlloc(GetProcessHeap(), 0, sizeof(*d3d8_declaration))))
        return NULL;

    if (FAILED(hr = d3d8_vertex_declaration_init_fvf(d3d8_declaration, device, fvf)))
    {
        WARN("Failed to initialize vertex declaration, hr %#x.\n", hr);
        HeapFree(GetProcessHeap(), 0, d3d8_declaration);
        return NULL;
    }

    if (device->declArraySize == device->numConvertedDecls)
    {
        UINT grow = device->declArraySize / 2;

        convertedDecls = HeapReAlloc(GetProcessHeap(), 0, convertedDecls,
                sizeof(*convertedDecls) * (device->numConvertedDecls + grow));
        if (!convertedDecls)
        {
            d3d8_vertex_declaration_destroy(d3d8_declaration);
            return NULL;
        }
        device->decls = convertedDecls;
        device->declArraySize += grow;
    }

    memmove(convertedDecls + low + 1, convertedDecls + low,
            sizeof(*convertedDecls) * (device->numConvertedDecls - low));
    convertedDecls[low].declaration = d3d8_declaration;
    convertedDecls[low].fvf = fvf;
    ++device->numConvertedDecls;

    TRACE("Returning %p. %u decls in array.\n", d3d8_declaration, device->numConvertedDecls);

    return d3d8_declaration;
}

static HRESULT WINAPI d3d8_device_SetVertexShader(IDirect3DDevice8 *iface, DWORD shader)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    struct d3d8_vertex_shader *shader_impl;

    TRACE("iface %p, shader %#x.\n", iface, shader);

    if (VS_HIGHESTFIXEDFXF >= shader)
    {
        TRACE("Setting FVF, %#x\n", shader);

        wined3d_mutex_lock();
        wined3d_device_set_vertex_declaration(device->wined3d_device,
                d3d8_device_get_fvf_declaration(device, shader)->wined3d_vertex_declaration);
        wined3d_device_set_vertex_shader(device->wined3d_device, NULL);
        wined3d_mutex_unlock();

        return D3D_OK;
    }

    TRACE("Setting shader\n");

    wined3d_mutex_lock();
    if (!(shader_impl = d3d8_get_object(&device->handle_table, shader - (VS_HIGHESTFIXEDFXF + 1), D3D8_HANDLE_VS)))
    {
        WARN("Invalid handle (%#x) passed.\n", shader);
        wined3d_mutex_unlock();

        return D3DERR_INVALIDCALL;
    }

    wined3d_device_set_vertex_declaration(device->wined3d_device,
            shader_impl->vertex_declaration->wined3d_vertex_declaration);
    wined3d_device_set_vertex_shader(device->wined3d_device, shader_impl->wined3d_shader);
    wined3d_mutex_unlock();

    return D3D_OK;
}

static HRESULT WINAPI d3d8_device_GetVertexShader(IDirect3DDevice8 *iface, DWORD *shader)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    struct wined3d_vertex_declaration *wined3d_declaration;
    struct d3d8_vertex_declaration *d3d8_declaration;

    TRACE("iface %p, shader %p.\n", iface, shader);

    wined3d_mutex_lock();
    if ((wined3d_declaration = wined3d_device_get_vertex_declaration(device->wined3d_device)))
    {
        d3d8_declaration = wined3d_vertex_declaration_get_parent(wined3d_declaration);
        *shader = d3d8_declaration->shader_handle;
    }
    else
    {
        *shader = 0;
    }
    wined3d_mutex_unlock();

    TRACE("Returning %#x.\n", *shader);

    return D3D_OK;
}

static HRESULT WINAPI d3d8_device_DeleteVertexShader(IDirect3DDevice8 *iface, DWORD shader)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    struct d3d8_vertex_shader *shader_impl;

    TRACE("iface %p, shader %#x.\n", iface, shader);

    wined3d_mutex_lock();
    if (!(shader_impl = d3d8_free_handle(&device->handle_table, shader - (VS_HIGHESTFIXEDFXF + 1), D3D8_HANDLE_VS)))
    {
        WARN("Invalid handle (%#x) passed.\n", shader);
        wined3d_mutex_unlock();

        return D3DERR_INVALIDCALL;
    }

    if (shader_impl->wined3d_shader
            && wined3d_device_get_vertex_shader(device->wined3d_device) == shader_impl->wined3d_shader)
        IDirect3DDevice8_SetVertexShader(iface, 0);

    wined3d_mutex_unlock();

    d3d8_vertex_shader_destroy(shader_impl);

    return D3D_OK;
}

static HRESULT WINAPI d3d8_device_SetVertexShaderConstant(IDirect3DDevice8 *iface,
        DWORD start_register, const void *data, DWORD count)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    HRESULT hr;

    TRACE("iface %p, start_register %u, data %p, count %u.\n",
            iface, start_register, data, count);

    if (start_register + count > D3D8_MAX_VERTEX_SHADER_CONSTANTF)
    {
        WARN("Trying to access %u constants, but d3d8 only supports %u\n",
             start_register + count, D3D8_MAX_VERTEX_SHADER_CONSTANTF);
        return D3DERR_INVALIDCALL;
    }

    wined3d_mutex_lock();
    hr = wined3d_device_set_vs_consts_f(device->wined3d_device, start_register, data, count);
    wined3d_mutex_unlock();

    return hr;
}

static HRESULT WINAPI d3d8_device_GetVertexShaderConstant(IDirect3DDevice8 *iface,
        DWORD start_register, void *data, DWORD count)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    HRESULT hr;

    TRACE("iface %p, start_register %u, data %p, count %u.\n",
            iface, start_register, data, count);

    if (start_register + count > D3D8_MAX_VERTEX_SHADER_CONSTANTF)
    {
        WARN("Trying to access %u constants, but d3d8 only supports %u\n",
             start_register + count, D3D8_MAX_VERTEX_SHADER_CONSTANTF);
        return D3DERR_INVALIDCALL;
    }

    wined3d_mutex_lock();
    hr = wined3d_device_get_vs_consts_f(device->wined3d_device, start_register, data, count);
    wined3d_mutex_unlock();

    return hr;
}

static HRESULT WINAPI d3d8_device_GetVertexShaderDeclaration(IDirect3DDevice8 *iface,
        DWORD shader, void *data, DWORD *data_size)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    struct d3d8_vertex_declaration *declaration;
    struct d3d8_vertex_shader *shader_impl;

    TRACE("iface %p, shader %#x, data %p, data_size %p.\n",
            iface, shader, data, data_size);

    wined3d_mutex_lock();
    shader_impl = d3d8_get_object(&device->handle_table, shader - (VS_HIGHESTFIXEDFXF + 1), D3D8_HANDLE_VS);
    wined3d_mutex_unlock();

    if (!shader_impl)
    {
        WARN("Invalid handle (%#x) passed.\n", shader);
        return D3DERR_INVALIDCALL;
    }
    declaration = shader_impl->vertex_declaration;

    if (!data)
    {
        *data_size = declaration->elements_size;
        return D3D_OK;
    }

    /* MSDN claims that if *data_size is smaller than the required size
     * we should write the required size and return D3DERR_MOREDATA.
     * That's not actually true. */
    if (*data_size < declaration->elements_size)
        return D3DERR_INVALIDCALL;

    memcpy(data, declaration->elements, declaration->elements_size);

    return D3D_OK;
}

static HRESULT WINAPI d3d8_device_GetVertexShaderFunction(IDirect3DDevice8 *iface,
        DWORD shader, void *data, DWORD *data_size)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    struct d3d8_vertex_shader *shader_impl = NULL;
    HRESULT hr;

    TRACE("iface %p, shader %#x, data %p, data_size %p.\n",
            iface, shader, data, data_size);

    wined3d_mutex_lock();
    if (!(shader_impl = d3d8_get_object(&device->handle_table, shader - (VS_HIGHESTFIXEDFXF + 1), D3D8_HANDLE_VS)))
    {
        WARN("Invalid handle (%#x) passed.\n", shader);
        wined3d_mutex_unlock();

        return D3DERR_INVALIDCALL;
    }

    if (!shader_impl->wined3d_shader)
    {
        wined3d_mutex_unlock();
        *data_size = 0;
        return D3D_OK;
    }

    hr = wined3d_shader_get_byte_code(shader_impl->wined3d_shader, data, data_size);
    wined3d_mutex_unlock();

    return hr;
}

static HRESULT WINAPI d3d8_device_SetIndices(IDirect3DDevice8 *iface,
        IDirect3DIndexBuffer8 *buffer, UINT base_vertex_idx)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    struct d3d8_indexbuffer *ib = unsafe_impl_from_IDirect3DIndexBuffer8(buffer);

    TRACE("iface %p, buffer %p, base_vertex_idx %u.\n", iface, buffer, base_vertex_idx);

    /* WineD3D takes an INT(due to d3d9), but d3d8 uses UINTs. Do I have to add a check here that
     * the UINT doesn't cause an overflow in the INT? It seems rather unlikely because such large
     * vertex buffers can't be created to address them with an index that requires the 32nd bit
     * (4 Byte minimum vertex size * 2^31-1 -> 8 gb buffer. The index sign would be the least
     * problem)
     */
    wined3d_mutex_lock();
    wined3d_device_set_base_vertex_index(device->wined3d_device, base_vertex_idx);
    wined3d_device_set_index_buffer(device->wined3d_device,
            ib ? ib->wined3d_buffer : NULL,
            ib ? ib->format : WINED3DFMT_UNKNOWN);
    wined3d_mutex_unlock();

    return D3D_OK;
}

static HRESULT WINAPI d3d8_device_GetIndices(IDirect3DDevice8 *iface,
        IDirect3DIndexBuffer8 **buffer, UINT *base_vertex_index)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    enum wined3d_format_id wined3d_format;
    struct wined3d_buffer *wined3d_buffer;
    struct d3d8_indexbuffer *buffer_impl;

    TRACE("iface %p, buffer %p, base_vertex_index %p.\n", iface, buffer, base_vertex_index);

    if (!buffer)
        return D3DERR_INVALIDCALL;

    /* The case from UINT to INT is safe because d3d8 will never set negative values */
    wined3d_mutex_lock();
    *base_vertex_index = wined3d_device_get_base_vertex_index(device->wined3d_device);
    if ((wined3d_buffer = wined3d_device_get_index_buffer(device->wined3d_device, &wined3d_format)))
    {
        buffer_impl = wined3d_buffer_get_parent(wined3d_buffer);
        *buffer = &buffer_impl->IDirect3DIndexBuffer8_iface;
        IDirect3DIndexBuffer8_AddRef(*buffer);
    }
    else
    {
        *buffer = NULL;
    }
    wined3d_mutex_unlock();

    return D3D_OK;
}

static HRESULT WINAPI d3d8_device_CreatePixelShader(IDirect3DDevice8 *iface,
        const DWORD *byte_code, DWORD *shader)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    struct d3d8_pixel_shader *object;
    DWORD shader_handle;
    DWORD handle;
    HRESULT hr;

    TRACE("iface %p, byte_code %p, shader %p.\n", iface, byte_code, shader);

    if (!shader)
        return D3DERR_INVALIDCALL;

    object = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*object));
    if (!object)
        return E_OUTOFMEMORY;

    wined3d_mutex_lock();
    handle = d3d8_allocate_handle(&device->handle_table, object, D3D8_HANDLE_PS);
    wined3d_mutex_unlock();
    if (handle == D3D8_INVALID_HANDLE)
    {
        ERR("Failed to allocate pixel shader handle.\n");
        HeapFree(GetProcessHeap(), 0, object);
        return E_OUTOFMEMORY;
    }

    shader_handle = handle + VS_HIGHESTFIXEDFXF + 1;

    hr = d3d8_pixel_shader_init(object, device, byte_code, shader_handle);
    if (FAILED(hr))
    {
        WARN("Failed to initialize pixel shader, hr %#x.\n", hr);
        wined3d_mutex_lock();
        d3d8_free_handle(&device->handle_table, handle, D3D8_HANDLE_PS);
        wined3d_mutex_unlock();
        HeapFree(GetProcessHeap(), 0, object);
        *shader = 0;
        return hr;
    }

    TRACE("Created pixel shader %p (handle %#x).\n", object, shader_handle);
    *shader = shader_handle;

    return D3D_OK;
}

static HRESULT WINAPI d3d8_device_SetPixelShader(IDirect3DDevice8 *iface, DWORD shader)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    struct d3d8_pixel_shader *shader_impl;

    TRACE("iface %p, shader %#x.\n", iface, shader);

    wined3d_mutex_lock();

    if (!shader)
    {
        wined3d_device_set_pixel_shader(device->wined3d_device, NULL);
        wined3d_mutex_unlock();
        return D3D_OK;
    }

    if (!(shader_impl = d3d8_get_object(&device->handle_table, shader - (VS_HIGHESTFIXEDFXF + 1), D3D8_HANDLE_PS)))
    {
        WARN("Invalid handle (%#x) passed.\n", shader);
        wined3d_mutex_unlock();
        return D3DERR_INVALIDCALL;
    }

    TRACE("Setting shader %p.\n", shader_impl);
    wined3d_device_set_pixel_shader(device->wined3d_device, shader_impl->wined3d_shader);
    wined3d_mutex_unlock();

    return D3D_OK;
}

static HRESULT WINAPI d3d8_device_GetPixelShader(IDirect3DDevice8 *iface, DWORD *shader)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    struct wined3d_shader *object;

    TRACE("iface %p, shader %p.\n", iface, shader);

    if (!shader)
        return D3DERR_INVALIDCALL;

    wined3d_mutex_lock();
    if ((object = wined3d_device_get_pixel_shader(device->wined3d_device)))
    {
        struct d3d8_pixel_shader *d3d8_shader;
        d3d8_shader = wined3d_shader_get_parent(object);
        *shader = d3d8_shader->handle;
    }
    else
    {
        *shader = 0;
    }
    wined3d_mutex_unlock();

    TRACE("Returning %#x.\n", *shader);

    return D3D_OK;
}

static HRESULT WINAPI d3d8_device_DeletePixelShader(IDirect3DDevice8 *iface, DWORD shader)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    struct d3d8_pixel_shader *shader_impl;

    TRACE("iface %p, shader %#x.\n", iface, shader);

    wined3d_mutex_lock();

    if (!(shader_impl = d3d8_free_handle(&device->handle_table, shader - (VS_HIGHESTFIXEDFXF + 1), D3D8_HANDLE_PS)))
    {
        WARN("Invalid handle (%#x) passed.\n", shader);
        wined3d_mutex_unlock();
        return D3DERR_INVALIDCALL;
    }

    if (wined3d_device_get_pixel_shader(device->wined3d_device) == shader_impl->wined3d_shader)
        IDirect3DDevice8_SetPixelShader(iface, 0);

    wined3d_mutex_unlock();

    d3d8_pixel_shader_destroy(shader_impl);

    return D3D_OK;
}

static HRESULT WINAPI d3d8_device_SetPixelShaderConstant(IDirect3DDevice8 *iface,
        DWORD start_register, const void *data, DWORD count)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    HRESULT hr;

    TRACE("iface %p, start_register %u, data %p, count %u.\n",
            iface, start_register, data, count);

    wined3d_mutex_lock();
    hr = wined3d_device_set_ps_consts_f(device->wined3d_device, start_register, data, count);
    wined3d_mutex_unlock();

    return hr;
}

static HRESULT WINAPI d3d8_device_GetPixelShaderConstant(IDirect3DDevice8 *iface,
        DWORD start_register, void *data, DWORD count)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    HRESULT hr;

    TRACE("iface %p, start_register %u, data %p, count %u.\n",
            iface, start_register, data, count);

    wined3d_mutex_lock();
    hr = wined3d_device_get_ps_consts_f(device->wined3d_device, start_register, data, count);
    wined3d_mutex_unlock();

    return hr;
}

static HRESULT WINAPI d3d8_device_GetPixelShaderFunction(IDirect3DDevice8 *iface,
        DWORD shader, void *data, DWORD *data_size)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    struct d3d8_pixel_shader *shader_impl = NULL;
    HRESULT hr;

    TRACE("iface %p, shader %#x, data %p, data_size %p.\n",
            iface, shader, data, data_size);

    wined3d_mutex_lock();
    if (!(shader_impl = d3d8_get_object(&device->handle_table, shader - (VS_HIGHESTFIXEDFXF + 1), D3D8_HANDLE_PS)))
    {
        WARN("Invalid handle (%#x) passed.\n", shader);
        wined3d_mutex_unlock();

        return D3DERR_INVALIDCALL;
    }

    hr = wined3d_shader_get_byte_code(shader_impl->wined3d_shader, data, data_size);
    wined3d_mutex_unlock();

    return hr;
}

static HRESULT WINAPI d3d8_device_DrawRectPatch(IDirect3DDevice8 *iface, UINT handle,
        const float *segment_count, const D3DRECTPATCH_INFO *patch_info)
{
    FIXME("iface %p, handle %#x, segment_count %p, patch_info %p unimplemented.\n",
            iface, handle, segment_count, patch_info);
    return D3D_OK;
}

static HRESULT WINAPI d3d8_device_DrawTriPatch(IDirect3DDevice8 *iface, UINT handle,
        const float *segment_count, const D3DTRIPATCH_INFO *patch_info)
{
    FIXME("iface %p, handle %#x, segment_count %p, patch_info %p unimplemented.\n",
            iface, handle, segment_count, patch_info);
    return D3D_OK;
}

static HRESULT WINAPI d3d8_device_DeletePatch(IDirect3DDevice8 *iface, UINT handle)
{
    FIXME("iface %p, handle %#x unimplemented.\n", iface, handle);
    return D3DERR_INVALIDCALL;
}

static HRESULT WINAPI d3d8_device_SetStreamSource(IDirect3DDevice8 *iface,
        UINT stream_idx, IDirect3DVertexBuffer8 *buffer, UINT stride)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    struct d3d8_vertexbuffer *buffer_impl = unsafe_impl_from_IDirect3DVertexBuffer8(buffer);
    HRESULT hr;

    TRACE("iface %p, stream_idx %u, buffer %p, stride %u.\n",
            iface, stream_idx, buffer, stride);

    wined3d_mutex_lock();
    hr = wined3d_device_set_stream_source(device->wined3d_device, stream_idx,
            buffer_impl ? buffer_impl->wined3d_buffer : NULL, 0, stride);
    wined3d_mutex_unlock();

    return hr;
}

static HRESULT WINAPI d3d8_device_GetStreamSource(IDirect3DDevice8 *iface,
        UINT stream_idx, IDirect3DVertexBuffer8 **buffer, UINT *stride)
{
    struct d3d8_device *device = impl_from_IDirect3DDevice8(iface);
    struct d3d8_vertexbuffer *buffer_impl;
    struct wined3d_buffer *wined3d_buffer = NULL;
    HRESULT hr;

    TRACE("iface %p, stream_idx %u, buffer %p, stride %p.\n",
            iface, stream_idx, buffer, stride);

    if (!buffer)
        return D3DERR_INVALIDCALL;

    wined3d_mutex_lock();
    hr = wined3d_device_get_stream_source(device->wined3d_device, stream_idx, &wined3d_buffer, 0, stride);
    if (SUCCEEDED(hr) && wined3d_buffer)
    {
        buffer_impl = wined3d_buffer_get_parent(wined3d_buffer);
        *buffer = &buffer_impl->IDirect3DVertexBuffer8_iface;
        IDirect3DVertexBuffer8_AddRef(*buffer);
    }
    else
    {
        if (FAILED(hr))
            ERR("Failed to get wined3d stream source, hr %#x.\n", hr);
        *buffer = NULL;
    }
    wined3d_mutex_unlock();

    return hr;
}

static const struct IDirect3DDevice8Vtbl d3d8_device_vtbl =
{
    d3d8_device_QueryInterface,
    d3d8_device_AddRef,
    d3d8_device_Release,
    d3d8_device_TestCooperativeLevel,
    d3d8_device_GetAvailableTextureMem,
    d3d8_device_ResourceManagerDiscardBytes,
    d3d8_device_GetDirect3D,
    d3d8_device_GetDeviceCaps,
    d3d8_device_GetDisplayMode,
    d3d8_device_GetCreationParameters,
    d3d8_device_SetCursorProperties,
    d3d8_device_SetCursorPosition,
    d3d8_device_ShowCursor,
    d3d8_device_CreateAdditionalSwapChain,
    d3d8_device_Reset,
    d3d8_device_Present,
    d3d8_device_GetBackBuffer,
    d3d8_device_GetRasterStatus,
    d3d8_device_SetGammaRamp,
    d3d8_device_GetGammaRamp,
    d3d8_device_CreateTexture,
    d3d8_device_CreateVolumeTexture,
    d3d8_device_CreateCubeTexture,
    d3d8_device_CreateVertexBuffer,
    d3d8_device_CreateIndexBuffer,
    d3d8_device_CreateRenderTarget,
    d3d8_device_CreateDepthStencilSurface,
    d3d8_device_CreateImageSurface,
    d3d8_device_CopyRects,
    d3d8_device_UpdateTexture,
    d3d8_device_GetFrontBuffer,
    d3d8_device_SetRenderTarget,
    d3d8_device_GetRenderTarget,
    d3d8_device_GetDepthStencilSurface,
    d3d8_device_BeginScene,
    d3d8_device_EndScene,
    d3d8_device_Clear,
    d3d8_device_SetTransform,
    d3d8_device_GetTransform,
    d3d8_device_MultiplyTransform,
    d3d8_device_SetViewport,
    d3d8_device_GetViewport,
    d3d8_device_SetMaterial,
    d3d8_device_GetMaterial,
    d3d8_device_SetLight,
    d3d8_device_GetLight,
    d3d8_device_LightEnable,
    d3d8_device_GetLightEnable,
    d3d8_device_SetClipPlane,
    d3d8_device_GetClipPlane,
    d3d8_device_SetRenderState,
    d3d8_device_GetRenderState,
    d3d8_device_BeginStateBlock,
    d3d8_device_EndStateBlock,
    d3d8_device_ApplyStateBlock,
    d3d8_device_CaptureStateBlock,
    d3d8_device_DeleteStateBlock,
    d3d8_device_CreateStateBlock,
    d3d8_device_SetClipStatus,
    d3d8_device_GetClipStatus,
    d3d8_device_GetTexture,
    d3d8_device_SetTexture,
    d3d8_device_GetTextureStageState,
    d3d8_device_SetTextureStageState,
    d3d8_device_ValidateDevice,
    d3d8_device_GetInfo,
    d3d8_device_SetPaletteEntries,
    d3d8_device_GetPaletteEntries,
    d3d8_device_SetCurrentTexturePalette,
    d3d8_device_GetCurrentTexturePalette,
    d3d8_device_DrawPrimitive,
    d3d8_device_DrawIndexedPrimitive,
    d3d8_device_DrawPrimitiveUP,
    d3d8_device_DrawIndexedPrimitiveUP,
    d3d8_device_ProcessVertices,
    d3d8_device_CreateVertexShader,
    d3d8_device_SetVertexShader,
    d3d8_device_GetVertexShader,
    d3d8_device_DeleteVertexShader,
    d3d8_device_SetVertexShaderConstant,
    d3d8_device_GetVertexShaderConstant,
    d3d8_device_GetVertexShaderDeclaration,
    d3d8_device_GetVertexShaderFunction,
    d3d8_device_SetStreamSource,
    d3d8_device_GetStreamSource,
    d3d8_device_SetIndices,
    d3d8_device_GetIndices,
    d3d8_device_CreatePixelShader,
    d3d8_device_SetPixelShader,
    d3d8_device_GetPixelShader,
    d3d8_device_DeletePixelShader,
    d3d8_device_SetPixelShaderConstant,
    d3d8_device_GetPixelShaderConstant,
    d3d8_device_GetPixelShaderFunction,
    d3d8_device_DrawRectPatch,
    d3d8_device_DrawTriPatch,
    d3d8_device_DeletePatch,
};

static inline struct d3d8_device *device_from_device_parent(struct wined3d_device_parent *device_parent)
{
    return CONTAINING_RECORD(device_parent, struct d3d8_device, device_parent);
}

static void CDECL device_parent_wined3d_device_created(struct wined3d_device_parent *device_parent,
        struct wined3d_device *device)
{
    TRACE("device_parent %p, device %p\n", device_parent, device);
}

static void CDECL device_parent_mode_changed(struct wined3d_device_parent *device_parent)
{
    TRACE("device_parent %p.\n", device_parent);
}

static void CDECL device_parent_activate(struct wined3d_device_parent *device_parent, BOOL activate)
{
    struct d3d8_device *device = device_from_device_parent(device_parent);

    TRACE("device_parent %p, activate %#x.\n", device_parent, activate);

    if (!activate)
        InterlockedCompareExchange(&device->device_state, D3D8_DEVICE_STATE_LOST, D3D8_DEVICE_STATE_OK);
    else
        InterlockedCompareExchange(&device->device_state, D3D8_DEVICE_STATE_NOT_RESET, D3D8_DEVICE_STATE_LOST);
}

static HRESULT CDECL device_parent_surface_created(struct wined3d_device_parent *device_parent,
        struct wined3d_texture *wined3d_texture, unsigned int sub_resource_idx, struct wined3d_surface *surface, void **parent,
        const struct wined3d_parent_ops **parent_ops)
{
    struct d3d8_surface *d3d_surface;

    TRACE("device_parent %p, wined3d_texture %p, sub_resource_idx %u, surface %p, parent %p, parent_ops %p.\n",
            device_parent, wined3d_texture, sub_resource_idx, surface, parent, parent_ops);

    if (!(d3d_surface = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*d3d_surface))))
        return E_OUTOFMEMORY;

    surface_init(d3d_surface, wined3d_texture, sub_resource_idx, parent_ops);
    *parent = d3d_surface;
    TRACE("Created surface %p.\n", d3d_surface);

    return D3D_OK;
}

static HRESULT CDECL device_parent_volume_created(struct wined3d_device_parent *device_parent,
        struct wined3d_texture *wined3d_texture, unsigned int sub_resource_idx,
        void **parent, const struct wined3d_parent_ops **parent_ops)
{
    struct d3d8_volume *d3d_volume;

    TRACE("device_parent %p, texture %p, sub_resource_idx %u, parent %p, parent_ops %p.\n",
            device_parent, wined3d_texture, sub_resource_idx, parent, parent_ops);

    if (!(d3d_volume = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*d3d_volume))))
        return E_OUTOFMEMORY;

    volume_init(d3d_volume, wined3d_texture, sub_resource_idx, parent_ops);
    *parent = d3d_volume;
    TRACE("Created volume %p.\n", d3d_volume);

    return D3D_OK;
}

static HRESULT CDECL device_parent_create_swapchain_texture(struct wined3d_device_parent *device_parent,
        void *container_parent, const struct wined3d_resource_desc *desc, struct wined3d_texture **texture)
{
    struct d3d8_device *device = device_from_device_parent(device_parent);
    struct d3d8_surface *d3d_surface;
    HRESULT hr;

    TRACE("device_parent %p, container_parent %p, desc %p, texture %p.\n",
            device_parent, container_parent, desc, texture);

    if (FAILED(hr = wined3d_texture_create(device->wined3d_device, desc, 1,
            WINED3D_SURFACE_MAPPABLE, NULL, &device->IDirect3DDevice8_iface, &d3d8_null_wined3d_parent_ops, texture)))
    {
        WARN("Failed to create texture, hr %#x.\n", hr);
        return hr;
    }

    d3d_surface = wined3d_resource_get_parent(wined3d_texture_get_sub_resource(*texture, 0));
    d3d_surface->parent_device = &device->IDirect3DDevice8_iface;

    return hr;
}

static HRESULT CDECL device_parent_create_swapchain(struct wined3d_device_parent *device_parent,
        struct wined3d_swapchain_desc *desc, struct wined3d_swapchain **swapchain)
{
    struct d3d8_device *device = device_from_device_parent(device_parent);
    struct d3d8_swapchain *d3d_swapchain;
    HRESULT hr;

    TRACE("device_parent %p, desc %p, swapchain %p.\n", device_parent, desc, swapchain);

    if (FAILED(hr = d3d8_swapchain_create(device, desc, &d3d_swapchain)))
    {
        WARN("Failed to create swapchain, hr %#x.\n", hr);
        *swapchain = NULL;
        return hr;
    }

    *swapchain = d3d_swapchain->wined3d_swapchain;
    wined3d_swapchain_incref(*swapchain);
    IDirect3DSwapChain8_Release(&d3d_swapchain->IDirect3DSwapChain8_iface);

    return hr;
}

static const struct wined3d_device_parent_ops d3d8_wined3d_device_parent_ops =
{
    device_parent_wined3d_device_created,
    device_parent_mode_changed,
    device_parent_activate,
    device_parent_surface_created,
    device_parent_volume_created,
    device_parent_create_swapchain_texture,
    device_parent_create_swapchain,
};

static void setup_fpu(void)
{
#if defined(__GNUC__) && (defined(__i386__) || defined(__x86_64__))
    WORD cw;
    __asm__ volatile ("fnstcw %0" : "=m" (cw));
    cw = (cw & ~0xf3f) | 0x3f;
    __asm__ volatile ("fldcw %0" : : "m" (cw));
#elif defined(__i386__) && defined(_MSC_VER)
    WORD cw;
    __asm fnstcw cw;
    cw = (cw & ~0xf3f) | 0x3f;
    __asm fldcw cw;
#else
    FIXME("FPU setup not implemented for this platform.\n");
#endif
}

HRESULT device_init(struct d3d8_device *device, struct d3d8 *parent, struct wined3d *wined3d, UINT adapter,
        D3DDEVTYPE device_type, HWND focus_window, DWORD flags, D3DPRESENT_PARAMETERS *parameters)
{
    struct wined3d_swapchain_desc swapchain_desc;
    struct wined3d_swapchain *wined3d_swapchain;
    HRESULT hr;

    device->IDirect3DDevice8_iface.lpVtbl = &d3d8_device_vtbl;
    device->device_parent.ops = &d3d8_wined3d_device_parent_ops;
    device->ref = 1;
    device->handle_table.entries = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
            D3D8_INITIAL_HANDLE_TABLE_SIZE * sizeof(*device->handle_table.entries));
    if (!device->handle_table.entries)
    {
        ERR("Failed to allocate handle table memory.\n");
        return E_OUTOFMEMORY;
    }
    device->handle_table.table_size = D3D8_INITIAL_HANDLE_TABLE_SIZE;

    if (!(flags & D3DCREATE_FPU_PRESERVE)) setup_fpu();

    wined3d_mutex_lock();
    hr = wined3d_device_create(wined3d, adapter, device_type, focus_window, flags, 4,
            &device->device_parent, &device->wined3d_device);
    if (FAILED(hr))
    {
        WARN("Failed to create wined3d device, hr %#x.\n", hr);
        wined3d_mutex_unlock();
        HeapFree(GetProcessHeap(), 0, device->handle_table.entries);
        return hr;
    }

    if (!parameters->Windowed)
    {
        HWND device_window = parameters->hDeviceWindow;

        if (!focus_window)
            focus_window = device_window;
        if (FAILED(hr = wined3d_device_acquire_focus_window(device->wined3d_device, focus_window)))
        {
            ERR("Failed to acquire focus window, hr %#x.\n", hr);
            wined3d_device_decref(device->wined3d_device);
            wined3d_mutex_unlock();
            HeapFree(GetProcessHeap(), 0, device->handle_table.entries);
            return hr;
        }

        if (!device_window)
            device_window = focus_window;
        wined3d_device_setup_fullscreen_window(device->wined3d_device, device_window,
                parameters->BackBufferWidth,
                parameters->BackBufferHeight);
    }

    if (flags & D3DCREATE_MULTITHREADED)
        wined3d_device_set_multithreaded(device->wined3d_device);

    if (!wined3d_swapchain_desc_from_present_parameters(&swapchain_desc, parameters))
    {
        wined3d_device_release_focus_window(device->wined3d_device);
        wined3d_device_decref(device->wined3d_device);
        wined3d_mutex_unlock();
        HeapFree(GetProcessHeap(), 0, device->handle_table.entries);
        return D3DERR_INVALIDCALL;
    }

    hr = wined3d_device_init_3d(device->wined3d_device, &swapchain_desc);
    if (FAILED(hr))
    {
        WARN("Failed to initialize 3D, hr %#x.\n", hr);
        wined3d_device_release_focus_window(device->wined3d_device);
        wined3d_device_decref(device->wined3d_device);
        wined3d_mutex_unlock();
        HeapFree(GetProcessHeap(), 0, device->handle_table.entries);
        return hr;
    }

    wined3d_device_set_render_state(device->wined3d_device, WINED3D_RS_POINTSIZE_MIN, 0);
    wined3d_mutex_unlock();

    present_parameters_from_wined3d_swapchain_desc(parameters, &swapchain_desc);

    device->declArraySize = 16;
    device->decls = HeapAlloc(GetProcessHeap(), 0, device->declArraySize * sizeof(*device->decls));
    if (!device->decls)
    {
        ERR("Failed to allocate FVF vertex declaration map memory.\n");
        hr = E_OUTOFMEMORY;
        goto err;
    }

    wined3d_swapchain = wined3d_device_get_swapchain(device->wined3d_device, 0);
    device->implicit_swapchain = wined3d_swapchain_get_parent(wined3d_swapchain);

    device->d3d_parent = &parent->IDirect3D8_iface;
    IDirect3D8_AddRef(device->d3d_parent);

    return D3D_OK;

err:
    wined3d_mutex_lock();
    wined3d_device_uninit_3d(device->wined3d_device);
    wined3d_device_release_focus_window(device->wined3d_device);
    wined3d_device_decref(device->wined3d_device);
    wined3d_mutex_unlock();
    HeapFree(GetProcessHeap(), 0, device->handle_table.entries);
    return hr;
}
