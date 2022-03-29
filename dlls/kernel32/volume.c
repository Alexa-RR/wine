/*
 * Volume management functions
 *
 * Copyright 1993 Erik Bos
 * Copyright 1996, 2004 Alexandre Julliard
 * Copyright 1999 Petr Tomasek
 * Copyright 2000 Andreas Mohr
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
 */

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winnls.h"
#include "winternl.h"
#include "winioctl.h"
#include "ntddcdrm.h"
#include "ddk/wdm.h"
#include "kernel_private.h"
#include "wine/debug.h"

#ifdef HAVE_SYS_MOUNT_H
# include <sys/mount.h>
#endif
#ifdef HAVE_SYS_STATFS_H
# include <sys/statfs.h>
#endif
#ifdef HAVE_SYS_SYSCALL_H
# include <sys/syscall.h>
#endif
#ifdef HAVE_SYS_VFS_H
# include <sys/vfs.h>
#endif

WINE_DEFAULT_DEBUG_CHANNEL(volume);

#define BLOCK_SIZE 2048
#define SUPERBLOCK_SIZE BLOCK_SIZE

#define GETWORD(buf,off)  MAKEWORD(buf[(off)],buf[(off+1)])
#define GETLONG(buf,off)  MAKELONG(GETWORD(buf,off),GETWORD(buf,off+2))

enum fs_type
{
    FS_ERROR,    /* error accessing the device */
    FS_UNKNOWN,  /* unknown file system */
    FS_FAT1216,
    FS_FAT32,
    FS_ISO9660,
    FS_UDF       /* For reference [E] = Ecma-167.pdf, [U] = udf260.pdf */
};

/******************************************************************
 *		VOLUME_FindCdRomDataBestVoldesc
 */
static DWORD VOLUME_FindCdRomDataBestVoldesc( HANDLE handle )
{
    BYTE cur_vd_type, max_vd_type = 0;
    BYTE buffer[0x800];
    DWORD size, offs, best_offs = 0, extra_offs = 0;

    for (offs = 0x8000; offs <= 0x9800; offs += 0x800)
    {
        /* if 'CDROM' occurs at position 8, this is a pre-iso9660 cd, and
         * the volume label is displaced forward by 8
         */
        if (SetFilePointer( handle, offs, NULL, FILE_BEGIN ) != offs) break;
        if (!ReadFile( handle, buffer, sizeof(buffer), &size, NULL )) break;
        if (size != sizeof(buffer)) break;
        /* check for non-ISO9660 signature */
        if (!memcmp( buffer + 11, "ROM", 3 )) extra_offs = 8;
        cur_vd_type = buffer[extra_offs];
        if (cur_vd_type == 0xff) /* voldesc set terminator */
            break;
        if (cur_vd_type > max_vd_type)
        {
            max_vd_type = cur_vd_type;
            best_offs = offs + extra_offs;
        }
    }
    return best_offs;
}


/***********************************************************************
 *           VOLUME_ReadFATSuperblock
 */
static enum fs_type VOLUME_ReadFATSuperblock( HANDLE handle, BYTE *buff )
{
    DWORD size;

    /* try a fixed disk, with a FAT partition */
    if (SetFilePointer( handle, 0, NULL, FILE_BEGIN ) != 0 ||
        !ReadFile( handle, buff, SUPERBLOCK_SIZE, &size, NULL ))
    {
        if (GetLastError() == ERROR_BAD_DEV_TYPE) return FS_UNKNOWN;  /* not a real device */
        return FS_ERROR;
    }

    if (size < SUPERBLOCK_SIZE) return FS_UNKNOWN;

    /* FIXME: do really all FAT have their name beginning with
     * "FAT" ? (At least FAT12, FAT16 and FAT32 have :)
     */
    if (!memcmp(buff+0x36, "FAT", 3) || !memcmp(buff+0x52, "FAT", 3))
    {
        /* guess which type of FAT we have */
        int reasonable;
        unsigned int sectors,
                     sect_per_fat,
                     total_sectors,
                     num_boot_sectors,
                     num_fats,
                     num_root_dir_ents,
                     bytes_per_sector,
                     sectors_per_cluster,
                     nclust;
        sect_per_fat = GETWORD(buff, 0x16);
        if (!sect_per_fat) sect_per_fat = GETLONG(buff, 0x24);
        total_sectors = GETWORD(buff, 0x13);
        if (!total_sectors)
            total_sectors = GETLONG(buff, 0x20);
        num_boot_sectors = GETWORD(buff, 0x0e);
        num_fats =  buff[0x10];
        num_root_dir_ents = GETWORD(buff, 0x11);
        bytes_per_sector = GETWORD(buff, 0x0b);
        sectors_per_cluster = buff[0x0d];
        /* check if the parameters are reasonable and will not cause
         * arithmetic errors in the calculation */
        reasonable = num_boot_sectors < total_sectors &&
                     num_fats < 16 &&
                     bytes_per_sector >= 512 && bytes_per_sector % 512 == 0 &&
                     sectors_per_cluster >= 1;
        if (!reasonable) return FS_UNKNOWN;
        sectors =  total_sectors - num_boot_sectors - num_fats * sect_per_fat -
            (num_root_dir_ents * 32 + bytes_per_sector - 1) / bytes_per_sector;
        nclust = sectors / sectors_per_cluster;
        if ((buff[0x42] == 0x28 || buff[0x42] == 0x29) &&
                !memcmp(buff+0x52, "FAT", 3)) return FS_FAT32;
        if (nclust < 65525)
        {
            if ((buff[0x26] == 0x28 || buff[0x26] == 0x29) &&
                    !memcmp(buff+0x36, "FAT", 3))
                return FS_FAT1216;
        }
    }
    return FS_UNKNOWN;
}


/***********************************************************************
 *           VOLUME_ReadCDBlock
 */
static BOOL VOLUME_ReadCDBlock( HANDLE handle, BYTE *buff, INT offs )
{
    DWORD size, whence = offs >= 0 ? FILE_BEGIN : FILE_END;

    if (SetFilePointer( handle, offs, NULL, whence ) != offs ||
        !ReadFile( handle, buff, SUPERBLOCK_SIZE, &size, NULL ) ||
        size != SUPERBLOCK_SIZE)
        return FALSE;

    return TRUE;
}


/***********************************************************************
 *           VOLUME_ReadCDSuperblock
 */
static enum fs_type VOLUME_ReadCDSuperblock( HANDLE handle, BYTE *buff )
{
    int i;
    DWORD offs;

    /* Check UDF first as UDF and ISO9660 structures can coexist on the same medium
     *  Starting from sector 16, we may find :
     *  - a CD-ROM Volume Descriptor Set (ISO9660) containing one or more Volume Descriptors
     *  - an Extended Area (UDF) -- [E] 2/8.3.1 and [U] 2.1.7
     *  There is no explicit end so read 16 sectors and then give up */
    for( i=16; i<16+16; i++)
    {
        if (!VOLUME_ReadCDBlock(handle, buff, i*BLOCK_SIZE))
            continue;

        /* We are supposed to check "BEA01", "NSR0x" and "TEA01" IDs + verify tag checksum
         *  but we assume the volume is well-formatted */
        if (!memcmp(&buff[1], "BEA01", 5)) return FS_UDF;
    }

    offs = VOLUME_FindCdRomDataBestVoldesc( handle );
    if (!offs) return FS_UNKNOWN;

    if (!VOLUME_ReadCDBlock(handle, buff, offs))
        return FS_ERROR;

    /* check for the iso9660 identifier */
    if (!memcmp(&buff[1], "CD001", 5)) return FS_ISO9660;
    return FS_UNKNOWN;
}


<<<<<<< HEAD
/**************************************************************************
 *                        UDF_Find_PVD
 * Find the Primary Volume Descriptor
 */
static BOOL UDF_Find_PVD( HANDLE handle, BYTE pvd[] )
{
    unsigned int i;
    DWORD offset;
    INT locations[] = { 256, -1, -257, 512 };

    for(i=0; i<ARRAY_SIZE(locations); i++)
    {
        if (!VOLUME_ReadCDBlock(handle, pvd, locations[i]*BLOCK_SIZE))
            return FALSE;

        /* Tag Identifier of Anchor Volume Descriptor Pointer is 2 -- [E] 3/10.2.1 */
        if (pvd[0]==2 && pvd[1]==0)
        {
            /* Tag location (Uint32) at offset 12, little-endian */
            offset  = pvd[20 + 0];
            offset |= pvd[20 + 1] << 8;
            offset |= pvd[20 + 2] << 16;
            offset |= pvd[20 + 3] << 24;
            offset *= BLOCK_SIZE;

            if (!VOLUME_ReadCDBlock(handle, pvd, offset))
                return FALSE;

            /* Check for the Primary Volume Descriptor Tag Id -- [E] 3/10.1.1 */
            if (pvd[0]!=1 || pvd[1]!=0)
                return FALSE;

            /* 8 or 16 bits per character -- [U] 2.1.1 */
            if (!(pvd[24]==8 || pvd[24]==16))
                return FALSE;

            return TRUE;
        }
    }

    return FALSE;
}


/**************************************************************************
 *                              VOLUME_GetSuperblockLabel
 */
static void VOLUME_GetSuperblockLabel( const UNICODE_STRING *device, HANDLE handle,
                                       enum fs_type type, const BYTE *superblock,
                                       WCHAR *label, DWORD len )
{
    const BYTE *label_ptr = NULL;
    DWORD label_len;

    switch(type)
    {
    case FS_ERROR:
        label_len = 0;
        break;
    case FS_UNKNOWN:
        get_filesystem_label( device, label, len );
        return;
    case FS_FAT1216:
        label_ptr = superblock + 0x2b;
        label_len = 11;
        break;
    case FS_FAT32:
        label_ptr = superblock + 0x47;
        label_len = 11;
        break;
    case FS_ISO9660:
        {
            BYTE ver = superblock[0x5a];

            if (superblock[0x58] == 0x25 && superblock[0x59] == 0x2f &&  /* Unicode ID */
                ((ver == 0x40) || (ver == 0x43) || (ver == 0x45)))
            { /* yippee, unicode */
                unsigned int i;

                if (len > 17) len = 17;
                for (i = 0; i < len-1; i++)
                    label[i] = (superblock[40+2*i] << 8) | superblock[41+2*i];
                label[i] = 0;
                while (i && label[i-1] == ' ') label[--i] = 0;
                return;
            }
            label_ptr = superblock + 40;
            label_len = 32;
            break;
        }
    case FS_UDF:
        {
            BYTE pvd[BLOCK_SIZE];

            if(!UDF_Find_PVD(handle, pvd))
            {
                label_len = 0;
                break;
            }

            /* [E] 3/10.1.4 and [U] 2.1.1 */
            if(pvd[24]==8)
            {
                label_ptr = pvd + 24 + 1;
                label_len = pvd[24+32-1];
                break;
            }
            else
            {
                unsigned int i;

                label_len = 1 + pvd[24+32-1];
                for(i=0; i<label_len && i<len; i+=2)
                    label[i/2]  = (pvd[24+1 +i] << 8) | pvd[24+1 +i+1];
                label[label_len] = 0;
                return;
            }
        }
    }
    if (label_len) RtlMultiByteToUnicodeN( label, (len-1) * sizeof(WCHAR),
                                           &label_len, (LPCSTR)label_ptr, label_len );
    label_len /= sizeof(WCHAR);
    label[label_len] = 0;
    while (label_len && label[label_len-1] == ' ') label[--label_len] = 0;
}


/**************************************************************************
 *                              UDF_Find_FSD_Sector
 * Find the File Set Descriptor used to compute the serial of a UDF volume
 */
static int UDF_Find_FSD_Sector( HANDLE handle, BYTE block[] )
{
    int i, PVD_sector, PD_sector, PD_length;

    if(!UDF_Find_PVD(handle,block))
        goto default_sector;

    /* Retrieve the tag location of the PVD -- [E] 3/7.2 */
    PVD_sector  = block[12 + 0];
    PVD_sector |= block[12 + 1] << 8;
    PVD_sector |= block[12 + 2] << 16;
    PVD_sector |= block[12 + 3] << 24;

    /* Find the Partition Descriptor */
    for(i=PVD_sector+1; ; i++)
    {
        if(!VOLUME_ReadCDBlock(handle, block, i*BLOCK_SIZE))
            goto default_sector;

        /* Partition Descriptor Tag Id -- [E] 3/10.5.1 */
        if(block[0]==5 && block[1]==0)
            break;

        /* Terminating Descriptor Tag Id -- [E] 3/10.9.1 */
        if(block[0]==8 && block[1]==0)
            goto default_sector;
    }

    /* Find the partition starting location -- [E] 3/10.5.8 */
    PD_sector  = block[188 + 0];
    PD_sector |= block[188 + 1] << 8;
    PD_sector |= block[188 + 2] << 16;
    PD_sector |= block[188 + 3] << 24;

    /* Find the partition length -- [E] 3/10.5.9 */
    PD_length  = block[192 + 0];
    PD_length |= block[192 + 1] << 8;
    PD_length |= block[192 + 2] << 16;
    PD_length |= block[192 + 3] << 24;

    for(i=PD_sector; i<PD_sector+PD_length; i++)
    {
        if(!VOLUME_ReadCDBlock(handle, block, i*BLOCK_SIZE))
            goto default_sector;

        /* File Set Descriptor Tag Id -- [E] 3/14.1.1 */
        if(block[0]==0 && block[1]==1)
            return i;
    }

default_sector:
    WARN("FSD sector not found, serial may be incorrect\n");
    return 257;
}


/**************************************************************************
 *                              VOLUME_GetSuperblockSerial
 */
static DWORD VOLUME_GetSuperblockSerial( const UNICODE_STRING *device, HANDLE handle,
                                         enum fs_type type, const BYTE *superblock )
{
    int FSD_sector;
    BYTE block[BLOCK_SIZE];

    switch(type)
    {
    case FS_ERROR:
        break;
    case FS_UNKNOWN:
        return get_filesystem_serial( device );
    case FS_FAT1216:
        return GETLONG( superblock, 0x27 );
    case FS_FAT32:
        return GETLONG( superblock, 0x33 );
    case FS_UDF:
        FSD_sector = UDF_Find_FSD_Sector(handle, block);
        if (!VOLUME_ReadCDBlock(handle, block, FSD_sector*BLOCK_SIZE))
            break;
        superblock = block;
        /* fallthrough */
    case FS_ISO9660:
        {
            BYTE sum[4];
            int i;

            sum[0] = sum[1] = sum[2] = sum[3] = 0;
            for (i = 0; i < 2048; i += 4)
            {
                /* DON'T optimize this into DWORD !! (breaks overflow) */
                sum[0] += superblock[i+0];
                sum[1] += superblock[i+1];
                sum[2] += superblock[i+2];
                sum[3] += superblock[i+3];
            }
            /*
             * OK, another braindead one... argh. Just believe it.
             * Me$$ysoft chose to reverse the serial number in NT4/W2K.
             * It's true and nobody will ever be able to change it.
             */
            if ((GetVersion() & 0x80000000) || type == FS_UDF)
                return (sum[3] << 24) | (sum[2] << 16) | (sum[1] << 8) | sum[0];
            else
                return (sum[0] << 24) | (sum[1] << 16) | (sum[2] << 8) | sum[3];
        }
    }
    return 0;
}


/**************************************************************************
 *                              VOLUME_GetAudioCDSerial
 */
static DWORD VOLUME_GetAudioCDSerial( const CDROM_TOC *toc )
{
    DWORD serial = 0;
    int i;

    for (i = 0; i <= toc->LastTrack - toc->FirstTrack; i++)
        serial += ((toc->TrackData[i].Address[1] << 16) |
                   (toc->TrackData[i].Address[2] << 8) |
                   toc->TrackData[i].Address[3]);

    /*
     * dwStart, dwEnd collect the beginning and end of the disc respectively, in
     * frames.
     * There it is collected for correcting the serial when there are less than
     * 3 tracks.
     */
    if (toc->LastTrack - toc->FirstTrack + 1 < 3)
    {
        DWORD dwStart = FRAME_OF_TOC(toc, toc->FirstTrack);
        DWORD dwEnd = FRAME_OF_TOC(toc, toc->LastTrack + 1);
        serial += dwEnd - dwStart;
    }
    return serial;
}


static DWORD WINAPI get_fs_flags( UNICODE_STRING *nt_name )
{
#if defined(__NR_renameat2) || defined(RENAME_SWAP)
    ANSI_STRING unix_name;
#if defined(HAVE_FSTATFS)
    struct statfs stfs;
#elif defined(HAVE_FSTATVFS)
    struct statvfs stfs;
#endif
    NTSTATUS status;
    DWORD flags = 0;

    status = wine_nt_to_unix_file_name( nt_name, &unix_name, FILE_OPEN, FALSE );
    if (status != STATUS_SUCCESS)
        return flags;
#if defined(HAVE_FSTATFS)
    if (statfs(unix_name.Buffer, &stfs))
        return flags;
#elif defined(HAVE_FSTATVFS)
    if (statvfs(unix_name.Buffer, &stfs))
        return flags;
#endif
#if defined(HAVE_FSTATFS) && defined(linux)
    switch (stfs.f_type)
    {
    case 0x6969:      /* nfs */
    case 0xff534d42:  /* cifs */
    case 0x564c:      /* ncpfs */
    case 0x01021994:  /* tmpfs */
    case 0x28cd3d45:  /* cramfs */
    case 0x1373:      /* devfs */
    case 0x9fa0:      /* procfs */
    case 0xef51:      /* old ext2 */
    case 0xef53:      /* ext2/3/4 */
    case 0x4244:      /* hfs */
    case 0xf995e849:  /* hpfs */
    case 0x5346544e:  /* ntfs */
        flags |= FILE_SUPPORTS_REPARSE_POINTS;
        break;
    default:
        break;
    }
#elif defined(__FreeBSD__) || defined(__FreeBSD_kernel__) || defined(__OpenBSD__) || defined(__DragonFly__) || defined(__APPLE__) || defined(__NetBSD__)
    if (!strcmp("apfs", stfs.f_fstypename) ||
        !strcmp("nfs", stfs.f_fstypename) ||
        !strcmp("cifs", stfs.f_fstypename) ||
        !strcmp("ncpfs", stfs.f_fstypename) ||
        !strcmp("tmpfs", stfs.f_fstypename) ||
        !strcmp("cramfs", stfs.f_fstypename) ||
        !strcmp("devfs", stfs.f_fstypename) ||
        !strcmp("procfs", stfs.f_fstypename) ||
        !strcmp("ext2", stfs.f_fstypename) ||
        !strcmp("ext3", stfs.f_fstypename) ||
        !strcmp("ext4", stfs.f_fstypename) ||
        !strcmp("hfs", stfs.f_fstypename) ||
        !strcmp("hpfs", stfs.f_fstypename) ||
        !strcmp("ntfs", stfs.f_fstypename))
    {
        flags |= FILE_SUPPORTS_REPARSE_POINTS;
    }
#endif
    RtlFreeAnsiString( &unix_name );
    return flags;
#else
    return 0;
#endif
}


/***********************************************************************
 *           GetVolumeInformationW   (KERNEL32.@)
 */
BOOL WINAPI GetVolumeInformationW( LPCWSTR root, LPWSTR label, DWORD label_len,
                                   DWORD *serial, DWORD *filename_len, DWORD *flags,
                                   LPWSTR fsname, DWORD fsname_len )
{
    static const WCHAR audiocdW[] = {'A','u','d','i','o',' ','C','D',0};
    static const WCHAR fatW[] = {'F','A','T',0};
    static const WCHAR fat32W[] = {'F','A','T','3','2',0};
    static const WCHAR ntfsW[] = {'N','T','F','S',0};
    static const WCHAR cdfsW[] = {'C','D','F','S',0};
    static const WCHAR udfW[] = {'U','D','F',0};
    static const WCHAR default_rootW[] = {'\\',0};

    HANDLE handle;
    NTSTATUS status;
    UNICODE_STRING nt_name;
    IO_STATUS_BLOCK io;
    OBJECT_ATTRIBUTES attr;
    FILE_FS_DEVICE_INFORMATION info;
    unsigned int i;
    enum fs_type type = FS_UNKNOWN;
    BOOL ret = FALSE;

    if (!root) root = default_rootW;
    if (!RtlDosPathNameToNtPathName_U( root, &nt_name, NULL, NULL ))
    {
        SetLastError( ERROR_PATH_NOT_FOUND );
        return FALSE;
    }
    /* there must be exactly one backslash in the name, at the end */
    for (i = 4; i < nt_name.Length / sizeof(WCHAR); i++) if (nt_name.Buffer[i] == '\\') break;
    if (i != nt_name.Length / sizeof(WCHAR) - 1)
    {
        /* check if root contains an explicit subdir */
        if (root[0] && root[1] == ':') root += 2;
        while (*root == '\\') root++;
        if (strchrW( root, '\\' ))
            SetLastError( ERROR_DIR_NOT_ROOT );
        else
            SetLastError( ERROR_INVALID_NAME );
        goto done;
    }

    /* try to open the device */

    attr.Length = sizeof(attr);
    attr.RootDirectory = 0;
    attr.Attributes = OBJ_CASE_INSENSITIVE;
    attr.ObjectName = &nt_name;
    attr.SecurityDescriptor = NULL;
    attr.SecurityQualityOfService = NULL;

    nt_name.Length -= sizeof(WCHAR);  /* without trailing slash */
    status = NtOpenFile( &handle, GENERIC_READ | SYNCHRONIZE, &attr, &io, FILE_SHARE_READ | FILE_SHARE_WRITE,
                         FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT );
    nt_name.Length += sizeof(WCHAR);

    if (status == STATUS_SUCCESS)
    {
        BYTE superblock[SUPERBLOCK_SIZE];
        CDROM_TOC toc;
        DWORD br;

        /* check for audio CD */
        /* FIXME: we only check the first track for now */
        if (DeviceIoControl( handle, IOCTL_CDROM_READ_TOC, NULL, 0, &toc, sizeof(toc), &br, 0 ))
        {
            if (!(toc.TrackData[0].Control & 0x04))  /* audio track */
            {
                TRACE( "%s: found audio CD\n", debugstr_w(nt_name.Buffer) );
                if (label) lstrcpynW( label, audiocdW, label_len );
                if (serial) *serial = VOLUME_GetAudioCDSerial( &toc );
                CloseHandle( handle );
                type = FS_ISO9660;
                goto fill_fs_info;
            }
            type = VOLUME_ReadCDSuperblock( handle, superblock );
        }
        else
        {
            type = VOLUME_ReadFATSuperblock( handle, superblock );
            if (type == FS_UNKNOWN) type = VOLUME_ReadCDSuperblock( handle, superblock );
        }
        TRACE( "%s: found fs type %d\n", debugstr_w(nt_name.Buffer), type );
        if (type == FS_ERROR)
        {
            CloseHandle( handle );
            goto done;
        }

        if (label && label_len) VOLUME_GetSuperblockLabel( &nt_name, handle, type, superblock, label, label_len );
        if (serial) *serial = VOLUME_GetSuperblockSerial( &nt_name, handle, type, superblock );
        CloseHandle( handle );
        goto fill_fs_info;
    }
    else
    {
        TRACE( "cannot open device %s: %x\n", debugstr_w(nt_name.Buffer), status );
        if (status == STATUS_ACCESS_DENIED)
            MESSAGE( "wine: Read access denied for device %s, FS volume label and serial are not available.\n", debugstr_w(nt_name.Buffer) );
    }
    /* we couldn't open the device, fallback to default strategy */

    if (!set_ntstatus( NtOpenFile( &handle, SYNCHRONIZE, &attr, &io, 0,
                                   FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT )))
        goto done;

    status = NtQueryVolumeInformationFile( handle, &io, &info, sizeof(info), FileFsDeviceInformation );
    NtClose( handle );
    if (!set_ntstatus( status )) goto done;

    if (info.DeviceType == FILE_DEVICE_CD_ROM_FILE_SYSTEM) type = FS_ISO9660;

    if (label && label_len) get_filesystem_label( &nt_name, label, label_len );
    if (serial) *serial = get_filesystem_serial( &nt_name );

fill_fs_info:  /* now fill in the information that depends on the file system type */

    switch(type)
    {
    case FS_ISO9660:
        if (fsname) lstrcpynW( fsname, cdfsW, fsname_len );
        if (filename_len) *filename_len = 221;
        if (flags) *flags = FILE_READ_ONLY_VOLUME;
        break;
    case FS_UDF:
        if (fsname) lstrcpynW( fsname, udfW, fsname_len );
        if (filename_len) *filename_len = 255;
        if (flags)
            *flags = FILE_READ_ONLY_VOLUME | FILE_UNICODE_ON_DISK | FILE_CASE_SENSITIVE_SEARCH;
        break;
    case FS_FAT1216:
        if (fsname) lstrcpynW( fsname, fatW, fsname_len );
    case FS_FAT32:
        if (type == FS_FAT32 && fsname) lstrcpynW( fsname, fat32W, fsname_len );
        if (filename_len) *filename_len = 255;
        if (flags) *flags = FILE_CASE_PRESERVED_NAMES;  /* FIXME */
        break;
    default:
        if (fsname) lstrcpynW( fsname, ntfsW, fsname_len );
        if (filename_len) *filename_len = 255;
        if (flags) *flags = FILE_CASE_PRESERVED_NAMES | FILE_PERSISTENT_ACLS
                            | get_fs_flags( &nt_name );
        break;
    }
    ret = TRUE;

done:
    RtlFreeUnicodeString( &nt_name );
    return ret;
}


/***********************************************************************
 *           GetVolumeInformationA   (KERNEL32.@)
 */
BOOL WINAPI GetVolumeInformationA( LPCSTR root, LPSTR label,
                                   DWORD label_len, DWORD *serial,
                                   DWORD *filename_len, DWORD *flags,
                                   LPSTR fsname, DWORD fsname_len )
{
    WCHAR *rootW = NULL;
    LPWSTR labelW, fsnameW;
    BOOL ret;

    if (root && !(rootW = FILE_name_AtoW( root, FALSE ))) return FALSE;

    labelW = label ? HeapAlloc(GetProcessHeap(), 0, label_len * sizeof(WCHAR)) : NULL;
    fsnameW = fsname ? HeapAlloc(GetProcessHeap(), 0, fsname_len * sizeof(WCHAR)) : NULL;

    if ((ret = GetVolumeInformationW(rootW, labelW, label_len, serial,
                                    filename_len, flags, fsnameW, fsname_len)))
    {
        if (label) FILE_name_WtoA( labelW, -1, label, label_len );
        if (fsname) FILE_name_WtoA( fsnameW, -1, fsname, fsname_len );
    }

    HeapFree( GetProcessHeap(), 0, labelW );
    HeapFree( GetProcessHeap(), 0, fsnameW );
    return ret;
}



=======
>>>>>>> master
/***********************************************************************
 *           SetVolumeLabelW   (KERNEL32.@)
 */
BOOL WINAPI SetVolumeLabelW( LPCWSTR root, LPCWSTR label )
{
    WCHAR device[] = L"\\\\.\\A:";
    HANDLE handle;
    enum fs_type type = FS_UNKNOWN;

    if (!root)
    {
        WCHAR path[MAX_PATH];
        GetCurrentDirectoryW( MAX_PATH, path );
        device[4] = path[0];
    }
    else
    {
        if (!root[0] || root[1] != ':')
        {
            SetLastError( ERROR_INVALID_NAME );
            return FALSE;
        }
        device[4] = root[0];
    }

    /* try to open the device */

    handle = CreateFileW( device, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE,
                          NULL, OPEN_EXISTING, 0, 0 );
    if (handle != INVALID_HANDLE_VALUE)
    {
        BYTE superblock[SUPERBLOCK_SIZE];

        type = VOLUME_ReadFATSuperblock( handle, superblock );
        if (type == FS_UNKNOWN) type = VOLUME_ReadCDSuperblock( handle, superblock );
        CloseHandle( handle );
        if (type != FS_UNKNOWN)
        {
            /* we can't set the label on FAT or CDROM file systems */
            TRACE( "cannot set label on device %s type %d\n", debugstr_w(device), type );
            SetLastError( ERROR_ACCESS_DENIED );
            return FALSE;
        }
    }
    else
    {
        TRACE( "cannot open device %s: err %ld\n", debugstr_w(device), GetLastError() );
        if (GetLastError() == ERROR_ACCESS_DENIED) return FALSE;
    }

    /* we couldn't open the device, fallback to default strategy */

    switch(GetDriveTypeW( root ))
    {
    case DRIVE_UNKNOWN:
    case DRIVE_NO_ROOT_DIR:
        SetLastError( ERROR_NOT_READY );
        break;
    case DRIVE_REMOVABLE:
    case DRIVE_FIXED:
        {
            WCHAR labelW[] = L"A:\\.windows-label";

            labelW[0] = device[4];

            if (!label[0])  /* delete label file when setting an empty label */
                return DeleteFileW( labelW ) || GetLastError() == ERROR_FILE_NOT_FOUND;

            handle = CreateFileW( labelW, GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL,
                                  CREATE_ALWAYS, 0, 0 );
            if (handle != INVALID_HANDLE_VALUE)
            {
                char buffer[64];
                DWORD size;

                if (!WideCharToMultiByte( CP_UNIXCP, 0, label, -1, buffer, sizeof(buffer)-1, NULL, NULL ))
                    buffer[sizeof(buffer)-2] = 0;
                strcat( buffer, "\n" );
                WriteFile( handle, buffer, strlen(buffer), &size, NULL );
                CloseHandle( handle );
                return TRUE;
            }
            break;
        }
    case DRIVE_REMOTE:
    case DRIVE_RAMDISK:
    case DRIVE_CDROM:
        SetLastError( ERROR_ACCESS_DENIED );
        break;
    }
    return FALSE;
}

/***********************************************************************
 *           SetVolumeLabelA   (KERNEL32.@)
 */
BOOL WINAPI SetVolumeLabelA(LPCSTR root, LPCSTR volname)
{
    WCHAR *rootW = NULL, *volnameW = NULL;
    BOOL ret;

    if (root && !(rootW = FILE_name_AtoW( root, FALSE ))) return FALSE;
    if (volname && !(volnameW = FILE_name_AtoW( volname, TRUE ))) return FALSE;
    ret = SetVolumeLabelW( rootW, volnameW );
    HeapFree( GetProcessHeap(), 0, volnameW );
    return ret;
}


/***********************************************************************
 *           GetVolumeNameForVolumeMountPointA   (KERNEL32.@)
 */
BOOL WINAPI GetVolumeNameForVolumeMountPointA( LPCSTR path, LPSTR volume, DWORD size )
{
    BOOL ret;
    WCHAR volumeW[50], *pathW = NULL;
    DWORD len = min(ARRAY_SIZE(volumeW), size );

    TRACE("(%s, %p, %lx)\n", debugstr_a(path), volume, size);

    if (!path || !(pathW = FILE_name_AtoW( path, TRUE )))
        return FALSE;

    if ((ret = GetVolumeNameForVolumeMountPointW( pathW, volumeW, len )))
        FILE_name_WtoA( volumeW, -1, volume, len );

    HeapFree( GetProcessHeap(), 0, pathW );
    return ret;
}


/***********************************************************************
 *           DefineDosDeviceA       (KERNEL32.@)
 */
BOOL WINAPI DefineDosDeviceA(DWORD flags, LPCSTR devname, LPCSTR targetpath)
{
    WCHAR *devW, *targetW = NULL;
    BOOL ret;

    if (!(devW = FILE_name_AtoW( devname, FALSE ))) return FALSE;
    if (targetpath && !(targetW = FILE_name_AtoW( targetpath, TRUE ))) return FALSE;
    ret = DefineDosDeviceW(flags, devW, targetW);
    HeapFree( GetProcessHeap(), 0, targetW );
    return ret;
}


/***********************************************************************
 *           QueryDosDeviceA   (KERNEL32.@)
 *
 * returns array of strings terminated by \0, terminated by \0
 */
DWORD WINAPI QueryDosDeviceA( LPCSTR devname, LPSTR target, DWORD bufsize )
{
    DWORD ret = 0, retW;
    WCHAR *devnameW = NULL;
    LPWSTR targetW;

    if (devname && !(devnameW = FILE_name_AtoW( devname, FALSE ))) return 0;

    targetW = HeapAlloc( GetProcessHeap(),0, bufsize * sizeof(WCHAR) );
    if (!targetW)
    {
        SetLastError( ERROR_NOT_ENOUGH_MEMORY );
        return 0;
    }

    retW = QueryDosDeviceW(devnameW, targetW, bufsize);

    ret = FILE_name_WtoA( targetW, retW, target, bufsize );

    HeapFree(GetProcessHeap(), 0, targetW);
    return ret;
}


/***********************************************************************
 *           GetLogicalDriveStringsA   (KERNEL32.@)
 */
UINT WINAPI GetLogicalDriveStringsA( UINT len, LPSTR buffer )
{
    DWORD drives = GetLogicalDrives();
    UINT drive, count;

    for (drive = count = 0; drive < 26; drive++) if (drives & (1 << drive)) count++;
    if ((count * 4) + 1 > len) return count * 4 + 1;

    for (drive = 0; drive < 26; drive++)
    {
        if (drives & (1 << drive))
        {
            *buffer++ = 'A' + drive;
            *buffer++ = ':';
            *buffer++ = '\\';
            *buffer++ = 0;
        }
    }
    *buffer = 0;
    return count * 4;
}


/***********************************************************************
 *           GetVolumePathNameA   (KERNEL32.@)
 */
BOOL WINAPI GetVolumePathNameA(LPCSTR filename, LPSTR volumepathname, DWORD buflen)
{
    BOOL ret;
    WCHAR *filenameW = NULL, *volumeW = NULL;

    TRACE("(%s, %p, %ld)\n", debugstr_a(filename), volumepathname, buflen);

    if (filename && !(filenameW = FILE_name_AtoW( filename, FALSE )))
        return FALSE;
    if (volumepathname && !(volumeW = HeapAlloc( GetProcessHeap(), 0, buflen * sizeof(WCHAR) )))
        return FALSE;

    if ((ret = GetVolumePathNameW( filenameW, volumeW, buflen )))
        FILE_name_WtoA( volumeW, -1, volumepathname, buflen );

    HeapFree( GetProcessHeap(), 0, volumeW );
    return ret;
}


/***********************************************************************
 *           GetVolumePathNamesForVolumeNameA   (KERNEL32.@)
 */
BOOL WINAPI GetVolumePathNamesForVolumeNameA(LPCSTR volumename, LPSTR volumepathname, DWORD buflen, PDWORD returnlen)
{
    BOOL ret;
    WCHAR *volumenameW = NULL, *volumepathnameW;

    if (volumename && !(volumenameW = FILE_name_AtoW( volumename, TRUE ))) return FALSE;
    if (!(volumepathnameW = HeapAlloc( GetProcessHeap(), 0, buflen * sizeof(WCHAR) )))
    {
        HeapFree( GetProcessHeap(), 0, volumenameW );
        return FALSE;
    }
    if ((ret = GetVolumePathNamesForVolumeNameW( volumenameW, volumepathnameW, buflen, returnlen )))
    {
        char *path = volumepathname;
        const WCHAR *pathW = volumepathnameW;

        while (*pathW)
        {
            int len = lstrlenW( pathW ) + 1;
            FILE_name_WtoA( pathW, len, path, buflen );
            buflen -= len;
            pathW += len;
            path += len;
        }
        path[0] = 0;
    }
    HeapFree( GetProcessHeap(), 0, volumenameW );
    HeapFree( GetProcessHeap(), 0, volumepathnameW );
    return ret;
}


/***********************************************************************
 *           FindFirstVolumeA   (KERNEL32.@)
 */
HANDLE WINAPI FindFirstVolumeA(LPSTR volume, DWORD len)
{
    WCHAR *buffer = HeapAlloc( GetProcessHeap(), 0, len * sizeof(WCHAR) );
    HANDLE handle = FindFirstVolumeW( buffer, len );

    if (handle != INVALID_HANDLE_VALUE)
    {
        if (!WideCharToMultiByte( CP_ACP, 0, buffer, -1, volume, len, NULL, NULL ))
        {
            FindVolumeClose( handle );
            handle = INVALID_HANDLE_VALUE;
        }
    }
    HeapFree( GetProcessHeap(), 0, buffer );
    return handle;
}

/***********************************************************************
 *           FindNextVolumeA   (KERNEL32.@)
 */
BOOL WINAPI FindNextVolumeA( HANDLE handle, LPSTR volume, DWORD len )
{
    WCHAR *buffer = HeapAlloc( GetProcessHeap(), 0, len * sizeof(WCHAR) );
    BOOL ret;

    if ((ret = FindNextVolumeW( handle, buffer, len )))
    {
        if (!WideCharToMultiByte( CP_ACP, 0, buffer, -1, volume, len, NULL, NULL )) ret = FALSE;
    }
    HeapFree( GetProcessHeap(), 0, buffer );
    return ret;
}

/***********************************************************************
 *           FindFirstVolumeMountPointA   (KERNEL32.@)
 */
HANDLE WINAPI FindFirstVolumeMountPointA(LPCSTR root, LPSTR mount_point, DWORD len)
{
    FIXME("(%s, %p, %ld), stub!\n", debugstr_a(root), mount_point, len);
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return INVALID_HANDLE_VALUE;
}

/***********************************************************************
 *           FindFirstVolumeMountPointW   (KERNEL32.@)
 */
HANDLE WINAPI FindFirstVolumeMountPointW(LPCWSTR root, LPWSTR mount_point, DWORD len)
{
    FIXME("(%s, %p, %ld), stub!\n", debugstr_w(root), mount_point, len);
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return INVALID_HANDLE_VALUE;
}

/***********************************************************************
 *           FindVolumeMountPointClose   (KERNEL32.@)
 */
BOOL WINAPI FindVolumeMountPointClose(HANDLE h)
{
    FIXME("(%p), stub!\n", h);
    return FALSE;
}

/***********************************************************************
 *           DeleteVolumeMountPointA   (KERNEL32.@)
 */
BOOL WINAPI DeleteVolumeMountPointA(LPCSTR mountpoint)
{
    FIXME("(%s), stub!\n", debugstr_a(mountpoint));
    return FALSE;
}

/***********************************************************************
 *           SetVolumeMountPointA (KERNEL32.@)
 */
BOOL WINAPI SetVolumeMountPointA(LPCSTR path, LPCSTR volume)
{
    FIXME("(%s, %s), stub!\n", debugstr_a(path), debugstr_a(volume));
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

/***********************************************************************
 *           SetVolumeMountPointW (KERNEL32.@)
 */
BOOL WINAPI SetVolumeMountPointW(LPCWSTR path, LPCWSTR volume)
{
    FIXME("(%s, %s), stub!\n", debugstr_w(path), debugstr_w(volume));
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}
