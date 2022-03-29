/*
 * Crypto Shell Extensions
 *
 * Copyright 2014 Austin English
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

#include "windef.h"
#include "winbase.h"
#include "winnls.h"
#include "wincrypt.h"
#include "winuser.h"
#include "cryptuiapi.h"

#include "wine/heap.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(cryptext);

<<<<<<< HEAD
static WCHAR *heap_strdupAtoW(const char *str)
{
    WCHAR *ret;
    INT len;

    if (!str) return NULL;
    len = MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, 0);
    ret = heap_alloc(len * sizeof(WCHAR));
    if (ret)
        MultiByteToWideChar(CP_ACP, 0, str, -1, ret, len);
    return ret;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    TRACE("(%p, %u, %p)\n", instance, reason, reserved);

    switch (reason)
    {
        case DLL_WINE_PREATTACH:
            return FALSE;    /* prefer native version */
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(instance);
            break;
    }

    return TRUE;
}

=======
>>>>>>> github-desktop-wine-mirror/master
/***********************************************************************
 * CryptExtAddPFX (CRYPTEXT.@)
 */
HRESULT WINAPI CryptExtAddPFX(LPCSTR filename)
{
    FIXME("stub: %s\n", debugstr_a(filename));
    return E_NOTIMPL;
}

/***********************************************************************
 * CryptExtAddPFXW (CRYPTEXT.@)
 */
HRESULT WINAPI CryptExtAddPFXW(LPCWSTR filename)
{
    FIXME("stub: %s\n", debugstr_w(filename));
    return E_NOTIMPL;
}

/***********************************************************************
 * CryptExtOpenCERW (CRYPTEXT.@)
 */
HRESULT WINAPI CryptExtOpenCERW(HWND hwnd, HINSTANCE hinst, LPCWSTR filename, DWORD showcmd)
{
    PCCERT_CONTEXT ctx;
    CRYPTUI_VIEWCERTIFICATE_STRUCTW info;

    TRACE("(%p, %p, %s, %u)\n", hwnd, hinst, debugstr_w(filename), showcmd);

    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, filename, CERT_QUERY_CONTENT_FLAG_CERT,
                          CERT_QUERY_FORMAT_FLAG_ALL, 0, NULL, NULL, NULL, NULL, NULL,
                          (const void **)&ctx))
    {
        /* FIXME: move to the resources */
        static const WCHAR msg[] = {'T','h','i','s',' ','i','s',' ','n','o','t',' ','a',' ','v','a','l','i','d',' ','c','e','r','t','i','f','i','c','a','t','e',0};
        MessageBoxW(NULL, msg, filename, MB_OK | MB_ICONERROR);
        return S_OK; /* according to the tests */
    }

    memset(&info, 0, sizeof(info));
    info.dwSize = sizeof(info);
    info.pCertContext = ctx;
    CryptUIDlgViewCertificateW(&info, NULL);
    CertFreeCertificateContext(ctx);

    return S_OK;
}

/***********************************************************************
 * CryptExtOpenCER (CRYPTEXT.@)
 */
HRESULT WINAPI CryptExtOpenCER(HWND hwnd, HINSTANCE hinst, LPCSTR filename, DWORD showcmd)
{
    HRESULT hr;
    LPWSTR filenameW;

    TRACE("(%p, %p, %s, %u)\n", hwnd, hinst, debugstr_a(filename), showcmd);

    filenameW = heap_strdupAtoW(filename);
    hr = CryptExtOpenCERW(hwnd, hinst, filenameW, showcmd);
    heap_free(filenameW);
    return hr;
}
