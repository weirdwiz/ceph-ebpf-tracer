/* SPDX-License-Identifier: GPL-2.0 */
/* Minimal vmlinux.h for BPF CO-RE compilation.
 * In production builds, replace with bpftool btf dump output. */

#ifndef __VMLINUX_H__
#define __VMLINUX_H__

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef short __s16;
typedef int __s32;
typedef long long __s64;

typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef __s8 s8;
typedef __s16 s16;
typedef __s32 s32;
typedef __s64 s64;

typedef u32 dev_t;
typedef u64 sector_t;

/* BPF map/section macros are provided by bpf_helpers.h */

#endif /* __VMLINUX_H__ */
