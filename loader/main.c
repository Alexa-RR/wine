/*
 * Emulator initialisation code
 *
 * Copyright 2000 Alexandre Julliard
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

#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dlfcn.h>
#include <limits.h>
#ifdef HAVE_SYS_SYSCTL_H
# include <sys/sysctl.h>
#endif
#ifdef HAVE_DLADDR
# include <dlfcn.h>
#endif
#ifdef HAVE_LINK_H
# include <link.h>
#endif

#include "main.h"

extern char **environ;

/* the preloader will set this variable */
const struct wine_preload_info *wine_main_preload_info = NULL;

<<<<<<< HEAD
#ifdef __APPLE__
#include <mach-o/dyld.h>

static const char *get_macho_library_path( const char *libname )
{
    unsigned int path_len, libname_len = strlen( libname );
    uint32_t i, count = _dyld_image_count();

    for (i = 0; i < count; i++)
    {
       const char *path = _dyld_get_image_name( i );
        if (!path) continue;

        path_len = strlen( path );
        if (path_len < libname_len + 1) continue;
        if (path[path_len - libname_len - 1] != '/') continue;
        if (strcmp( path + path_len - libname_len, libname )) continue;

        return path;
    }
    return NULL;
}
#endif

/***********************************************************************
 *           check_command_line
 *
 * Check if command line is one that needs to be handled specially.
 */
static void check_command_line( int argc, char *argv[] )
{
    static const char usage[] =
        "Usage: wine PROGRAM [ARGUMENTS...]   Run the specified program\n"
        "       wine --help                   Display this help and exit\n"
        "       wine --version                Output version information and exit\n"
        "       wine --patches                Output patch information and exit\n"
        "       wine --check-libs             Checks if shared libs are installed";
=======
/* canonicalize path and return its directory name */
static char *realpath_dirname( const char *name )
{
    char *p, *fullpath = realpath( name, NULL );
>>>>>>> github-desktop-wine-mirror/master

    if (fullpath)
    {
        p = strrchr( fullpath, '/' );
        if (p == fullpath) p++;
        if (p) *p = 0;
    }
<<<<<<< HEAD
    if (!strcmp( argv[1], "--patches" ))
    {
        const struct
        {
            const char *author;
            const char *subject;
            int revision;
        }
        *next, *cur = wine_get_patches();

        if (!cur)
        {
            fprintf( stderr, "Patchlist not available.\n" );
            exit(1);
        }

        while (cur->author)
        {
            next = cur + 1;
            while (next->author)
            {
                if (strcmp( cur->author, next->author )) break;
                next++;
            }

            printf( "%s (%d):\n", cur->author, (int)(next - cur) );
            while (cur < next)
            {
                printf( "      %s", cur->subject );
                if (cur->revision != 1)
                    printf( " [rev %d]", cur->revision );
                printf( "\n" );
                cur++;
            }
            printf( "\n" );
        }

        exit(0);
    }
    if (!strcmp( argv[1], "--check-libs" ))
    {
        void* lib_handle;
        int ret = 0;
        const char **wine_libs = wine_get_libs();

        for(; *wine_libs; wine_libs++)
        {
            lib_handle = wine_dlopen( *wine_libs, RTLD_NOW, NULL, 0 );
            if (lib_handle)
            {
            #ifdef HAVE_DLADDR
                Dl_info libinfo;
                void* symbol;

            #ifdef HAVE_LINK_H
                struct link_map *lm = (struct link_map *)lib_handle;
                symbol = (void *)lm->l_addr;
            #else
                symbol = wine_dlsym( lib_handle, "_init", NULL, 0 );
            #endif
                if (symbol && wine_dladdr( symbol, &libinfo, NULL, 0 ))
                {
                    printf( "%s: %s\n", *wine_libs, libinfo.dli_fname );
                }
                else
            #endif
                {
                    const char *path = NULL;
                #ifdef __APPLE__
                    path = get_macho_library_path( *wine_libs );
                #endif
                    printf( "%s: %s\n", *wine_libs, path ? path : "found");
                }
                wine_dlclose( lib_handle, NULL, 0 );
            }
            else
            {
                printf( "%s: missing\n", *wine_libs );
                ret = 1;
            }
        }

        exit(ret);
    }
=======
    return fullpath;
>>>>>>> github-desktop-wine-mirror/master
}

/* if string ends with tail, remove it */
static char *remove_tail( const char *str, const char *tail )
{
    size_t len = strlen( str );
    size_t tail_len = strlen( tail );
    char *ret;

    if (len < tail_len) return NULL;
    if (strcmp( str + len - tail_len, tail )) return NULL;
    ret = malloc( len - tail_len + 1 );
    memcpy( ret, str, len - tail_len );
    ret[len - tail_len] = 0;
    return ret;
}

/* build a path from the specified dir and name */
static char *build_path( const char *dir, const char *name )
{
    size_t len = strlen( dir );
    char *ret = malloc( len + strlen( name ) + 2 );

    memcpy( ret, dir, len );
    if (len && ret[len - 1] != '/') ret[len++] = '/';
    strcpy( ret + len, name );
    return ret;
}

static const char *get_self_exe( char *argv0 )
{
#if defined(__linux__) || defined(__FreeBSD_kernel__) || defined(__NetBSD__)
    return "/proc/self/exe";
#elif defined (__FreeBSD__) || defined(__DragonFly__)
    static int pathname[] = { CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, -1 };
    size_t path_size = PATH_MAX;
    char *path = malloc( path_size );
    if (path && !sysctl( pathname, sizeof(pathname)/sizeof(pathname[0]), path, &path_size, NULL, 0 ))
        return path;
    free( path );
#endif

    if (!strchr( argv0, '/' )) /* search in PATH */
    {
        char *p, *path = getenv( "PATH" );

        if (!path || !(path = strdup(path))) return NULL;
        for (p = strtok( path, ":" ); p; p = strtok( NULL, ":" ))
        {
            char *name = build_path( p, argv0 );
            if (!access( name, X_OK ))
            {
                free( path );
                return name;
            }
            free( name );
        }
        free( path );
        return NULL;
    }
    return argv0;
}

static void *try_dlopen( const char *dir, const char *name )
{
    char *path = build_path( dir, name );
    void *handle = dlopen( path, RTLD_NOW );
    free( path );
    return handle;
}

static void *load_ntdll( char *argv0 )
{
#ifdef __i386__
#define SO_DIR "i386-unix/"
#elif defined(__x86_64__)
#define SO_DIR "x86_64-unix/"
#elif defined(__arm__)
#define SO_DIR "arm-unix/"
#elif defined(__aarch64__)
#define SO_DIR "aarch64-unix/"
#else
#define SO_DIR ""
#endif
    const char *self = get_self_exe( argv0 );
    char *path, *p;
    void *handle = NULL;

    if (self && ((path = realpath_dirname( self ))))
    {
        if ((p = remove_tail( path, "/loader" )))
        {
            handle = try_dlopen( p, "dlls/ntdll/ntdll.so" );
            free( p );
        }
        else handle = try_dlopen( path, BIN_TO_DLLDIR "/" SO_DIR "ntdll.so" );
        free( path );
    }

    if (!handle && (path = getenv( "WINEDLLPATH" )))
    {
        path = strdup( path );
        for (p = strtok( path, ":" ); p; p = strtok( NULL, ":" ))
        {
            handle = try_dlopen( p, SO_DIR "ntdll.so" );
            if (!handle) handle = try_dlopen( p, "ntdll.so" );
            if (handle) break;
        }
        free( path );
    }

    if (!handle && !self) handle = try_dlopen( DLLDIR, SO_DIR "ntdll.so" );

    return handle;
}


/**********************************************************************
 *           main
 */
int main( int argc, char *argv[] )
{
    void *handle;

    if ((handle = load_ntdll( argv[0] )))
    {
        void (*init_func)(int, char **, char **) = dlsym( handle, "__wine_main" );
        if (init_func) init_func( argc, argv, environ );
        fprintf( stderr, "wine: __wine_main function not found in ntdll.so\n" );
        exit(1);
    }

    fprintf( stderr, "wine: could not load ntdll.so: %s\n", dlerror() );
    pthread_detach( pthread_self() );  /* force importing libpthread for OpenGL */
    exit(1);
}
