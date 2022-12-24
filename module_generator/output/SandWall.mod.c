#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0xf704969, "module_layout" },
	{ 0xc946dda0, "cdev_del" },
	{ 0x82e7bb9c, "device_destroy" },
	{ 0x36c20549, "nf_unregister_net_hook" },
	{ 0x92997ed8, "_printk" },
	{ 0x933c4a18, "class_destroy" },
	{ 0x6091b333, "unregister_chrdev_region" },
	{ 0x986a7ce3, "nf_register_net_hook" },
	{ 0xa21071e2, "init_net" },
	{ 0xefc94da8, "device_create" },
	{ 0xc378cea7, "cdev_add" },
	{ 0x2d725fd4, "cdev_init" },
	{ 0x325cb5cb, "__class_create" },
	{ 0xe3ec2f2b, "alloc_chrdev_region" },
	{ 0x37a0cba, "kfree" },
	{ 0xd0da656b, "__stack_chk_fail" },
	{ 0x96b29254, "strncasecmp" },
	{ 0x656e4a6e, "snprintf" },
	{ 0x87a21cb3, "__ubsan_handle_out_of_bounds" },
	{ 0x1e6d26a8, "strstr" },
	{ 0x13c49cc2, "_copy_from_user" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0xbdfb6dbb, "__fentry__" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "9914A4AECAA73D80FD8F16A");
