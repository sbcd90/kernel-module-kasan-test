// SPDX-License-Identifier: GPL-2.0-only
/*
 *
 * Copyright (c) 2014 Samsung Electronics Co., Ltd.
 * Author: Andrey Ryabinin <a.ryabinin@samsung.com>
 */

#define pr_fmt(fmt) "kasan test: %s " fmt, __func__

#include <linux/mman.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "linux/kasan.h"

static struct test_kasan_info {
	int i;
};

static noinline void free_ptr(struct test_kasan_info *ptr) {
	kfree(ptr);
}

static noinline void access_ptr(struct test_kasan_info *ptr) {
	((volatile struct test_kasan_info *)ptr)->i;
}

static noinline struct test_kasan_info* create_ptr(void)
{
	struct test_kasan_info *ptr;

	
	ptr = kmalloc(sizeof(struct test_kasan_info), GFP_KERNEL);
	if (!ptr) {
		pr_err("Allocation failed\n");
		return NULL;
	}
	return ptr;
}

static int __init test_kasan_module_init(void)
{
	/*
	 * Temporarily enable multi-shot mode. Otherwise, KASAN would only
	 * report the first detected bug and panic the kernel if panic_on_warn
	 * is enabled.
	 */
	bool multishot = kasan_save_enable_multi_shot();

	/**
	 * create & return ptr
	 */
	struct test_kasan_info *ptr = create_ptr();
	/**
	 * free ptr
	 */ 
	free_ptr(ptr);
	/**
	 * access ptr, use after ptr is freed
	 */ 
	access_ptr(ptr);

	kasan_restore_multi_shot(multishot);
	return -EAGAIN;
}

module_init(test_kasan_module_init);
MODULE_LICENSE("GPL");
