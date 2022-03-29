/*
 * Copyright 2009 Jeremy White <jwhite@codeweavers.com> for CodeWeavers
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
#include <stdlib.h>
#include "windef.h"
#include "winbase.h"
#include "winnls.h"
#include "sane_i.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(twain);

TW_UINT16 sane_option_get_value( int optno, void *val )
{
    struct option_get_value_params params = { optno, val };

    return SANE_CALL( option_get_value, &params );
}

TW_UINT16 sane_option_set_value( int optno, void *val, BOOL *reload )
{
    struct option_set_value_params params = { optno, val, reload };

    return SANE_CALL( option_set_value, &params );
}

static TW_UINT16 sane_find_option( const char *name, int type, struct option_descriptor *descr )
{
    struct option_find_descriptor_params params = { name, type, descr };
    return SANE_CALL( option_find_descriptor, &params ) ? TWCC_CAPUNSUPPORTED : TWCC_SUCCESS;
}

TW_UINT16 sane_option_get_int(const char *option_name, int *val)
{
    struct option_descriptor opt;
    TW_UINT16 rc = sane_find_option(option_name, TYPE_INT, &opt);

    if (rc == TWCC_SUCCESS) rc = sane_option_get_value( opt.optno, val );
    return rc;
}

TW_UINT16 sane_option_set_int(const char *option_name, int val, BOOL *needs_reload )
{
    struct option_descriptor opt;
    TW_UINT16 rc = sane_find_option(option_name, TYPE_INT, &opt);

    if (rc == TWCC_SUCCESS) rc = sane_option_set_value( opt.optno, &val, needs_reload );
    return rc;
}

TW_UINT16 sane_option_get_bool(const char *option_name, int *val)
{
    struct option_descriptor opt;
    TW_UINT16 rc = sane_find_option(option_name, TYPE_BOOL, &opt);

    if (rc == TWCC_SUCCESS) rc = sane_option_get_value( opt.optno, val );
    return rc;
}

TW_UINT16 sane_option_set_bool(const char *option_name, int val )
{
    struct option_descriptor opt;
    TW_UINT16 rc = sane_find_option(option_name, TYPE_BOOL, &opt);

    if (rc == TWCC_SUCCESS) rc = sane_option_set_value( opt.optno, &val, NULL );
    return rc;
}

TW_UINT16 sane_option_get_str(const char *option_name, char *val, int len)
{
    struct option_descriptor opt;
    TW_UINT16 rc = sane_find_option(option_name, TYPE_STRING, &opt);

    if (rc == TWCC_SUCCESS)
    {
        if (opt.size < len)
            rc = sane_option_get_value( opt.optno, val );
        else
            rc = TWCC_BADVALUE;
    }
    return rc;
}

/* Important:  SANE has the side effect of overwriting val with the returned value */
TW_UINT16 sane_option_set_str(const char *option_name, char *val, BOOL *needs_reload)
{
    struct option_descriptor opt;
    TW_UINT16 rc = sane_find_option(option_name, TYPE_STRING, &opt);

    if (rc == TWCC_SUCCESS) rc = sane_option_set_value( opt.optno, &val, needs_reload );
    return rc;
}

TW_UINT16 sane_option_probe_resolution(const char *option_name, int *minval, int *maxval, int *quant)
{
    struct option_descriptor opt;
    TW_UINT16 rc = sane_find_option(option_name, TYPE_INT, &opt);

    if (rc != TWCC_SUCCESS) return rc;
    if (opt.constraint_type != CONSTRAINT_RANGE) return TWCC_CAPUNSUPPORTED;

    *minval = opt.constraint.range.min;
    *maxval = opt.constraint.range.max;
    *quant  = opt.constraint.range.quant;
    return rc;
}

TW_UINT16 sane_option_probe_mode(TW_UINT16 *current, TW_UINT32 *choices, int *count)
{
    WCHAR *p;
    char buffer[256];
    struct option_descriptor opt;
    TW_UINT16 rc = sane_find_option("mode", TYPE_STRING, &opt);

    if (rc != TWCC_SUCCESS) return rc;
    if (opt.size > sizeof(buffer)) return TWCC_BADVALUE;
    rc = sane_option_get_value( opt.optno, buffer );
    if (rc != TWCC_SUCCESS) return rc;

    if (!strcmp( buffer, "Lineart" )) *current = TWPT_BW;
    else if (!strcmp( buffer, "Color" )) *current = TWPT_RGB;
    else if (!strncmp( buffer, "Gray", 4 )) *current = TWPT_GRAY;

    *count = 0;
    if (opt.constraint_type == CONSTRAINT_STRING_LIST)
    {
        for (p = opt.constraint.strings; *p; p += lstrlenW(p) + 1)
        {
            if (!wcscmp( p, L"Lineart" )) choices[(*count)++] = TWPT_BW;
            else if (!wcscmp( p, L"Color" )) choices[(*count)++] = TWPT_RGB;
            else if (!wcsncmp( p, L"Gray", 4 )) choices[(*count)++] = TWPT_GRAY;
        }
    }
    return rc;
}

TW_UINT16 sane_option_get_scan_area( int *tlx, int *tly, int *brx, int *bry )
{
    TW_UINT16 rc;
    struct option_descriptor opt;

    if ((rc = sane_find_option( "tl-x", TYPE_FIXED, &opt )) != TWCC_SUCCESS) return rc;
    if ((rc = sane_option_get_value( opt.optno, tlx )) != TWCC_SUCCESS) return rc;
    if ((rc = sane_find_option( "tl-y", TYPE_FIXED, &opt )) != TWCC_SUCCESS) return rc;
    if ((rc = sane_option_get_value( opt.optno, tly )) != TWCC_SUCCESS) return rc;
    if ((rc = sane_find_option( "br-x", TYPE_FIXED, &opt )) != TWCC_SUCCESS) return rc;
    if ((rc = sane_option_get_value( opt.optno, brx )) != TWCC_SUCCESS) return rc;
    if ((rc = sane_find_option( "br-y", TYPE_FIXED, &opt )) != TWCC_SUCCESS) return rc;
    if ((rc = sane_option_get_value( opt.optno, bry )) != TWCC_SUCCESS) return rc;
    if (opt.unit != UNIT_MM) FIXME( "unsupported unit %u\n", opt.unit );
    return rc;
}

TW_UINT16 sane_option_get_max_scan_area( int *tlx, int *tly, int *brx, int *bry )
{
    TW_UINT16 rc;
    struct option_descriptor opt;

    if ((rc = sane_find_option( "tl-x", TYPE_FIXED, &opt )) != TWCC_SUCCESS) return rc;
    *tlx = opt.constraint.range.min;
    if ((rc = sane_find_option( "tl-y", TYPE_FIXED, &opt )) != TWCC_SUCCESS) return rc;
    *tly = opt.constraint.range.min;
    if ((rc = sane_find_option( "br-x", TYPE_FIXED, &opt )) != TWCC_SUCCESS) return rc;
    *brx = opt.constraint.range.max;
    if ((rc = sane_find_option( "br-y", TYPE_FIXED, &opt )) != TWCC_SUCCESS) return rc;
    *bry = opt.constraint.range.max;
    if (opt.unit != UNIT_MM) FIXME( "unsupported unit %u\n", opt.unit );
    return rc;
}

TW_UINT16 sane_option_set_scan_area( int tlx, int tly, int brx, int bry, BOOL *reload )
{
    TW_UINT16 rc;
    struct option_descriptor opt;

    if ((rc = sane_find_option( "tl-x", TYPE_FIXED, &opt )) != TWCC_SUCCESS) return rc;
    if ((rc = sane_option_set_value( opt.optno, &tlx, reload )) != TWCC_SUCCESS) return rc;
    if ((rc = sane_find_option( "tl-y", TYPE_FIXED, &opt )) != TWCC_SUCCESS) return rc;
    if ((rc = sane_option_set_value( opt.optno, &tly, reload )) != TWCC_SUCCESS) return rc;
    if ((rc = sane_find_option( "br-x", TYPE_FIXED, &opt )) != TWCC_SUCCESS) return rc;
    if ((rc = sane_option_set_value( opt.optno, &brx, reload )) != TWCC_SUCCESS) return rc;
    if ((rc = sane_find_option( "br-y", TYPE_FIXED, &opt )) != TWCC_SUCCESS) return rc;
    if ((rc = sane_option_set_value( opt.optno, &bry, reload )) != TWCC_SUCCESS) return rc;
    return rc;
}

TW_FIX32 convert_sane_res_to_twain(int res)
{
    TW_FIX32 value;
    res = MulDiv( res, 10, 254 );  /* mm -> inch */
    value.Whole = res / 65536;
    value.Frac  = res & 0xffff;
    return value;
}

TW_UINT16 get_sane_params( struct frame_parameters *params )
{
    return SANE_CALL( get_params, params );
}
