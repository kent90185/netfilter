#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x551a9e15, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0x45c49cd8, __VMLINUX_SYMBOL_STR(debugfs_create_dir) },
	{ 0x43a53735, __VMLINUX_SYMBOL_STR(__alloc_workqueue_key) },
	{ 0x6caefb2b, __VMLINUX_SYMBOL_STR(seq_open) },
	{ 0x56d4ca56, __VMLINUX_SYMBOL_STR(seq_printf) },
	{ 0x6d2a27, __VMLINUX_SYMBOL_STR(nf_register_hook) },
	{ 0xace44780, __VMLINUX_SYMBOL_STR(debugfs_create_file) },
	{ 0x3b416efd, __VMLINUX_SYMBOL_STR(debugfs_remove_recursive) },
	{ 0x6be08290, __VMLINUX_SYMBOL_STR(seq_read) },
	{ 0x356461c8, __VMLINUX_SYMBOL_STR(rtc_time64_to_tm) },
	{ 0x1916e38c, __VMLINUX_SYMBOL_STR(_raw_spin_unlock_irqrestore) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0x20c55ae0, __VMLINUX_SYMBOL_STR(sscanf) },
	{ 0x8c03d20c, __VMLINUX_SYMBOL_STR(destroy_workqueue) },
	{ 0x42160169, __VMLINUX_SYMBOL_STR(flush_workqueue) },
	{ 0xfe5d4bb2, __VMLINUX_SYMBOL_STR(sys_tz) },
	{ 0xdb7305a1, __VMLINUX_SYMBOL_STR(__stack_chk_fail) },
	{ 0xbdfb6dbb, __VMLINUX_SYMBOL_STR(__fentry__) },
	{ 0x680ec266, __VMLINUX_SYMBOL_STR(_raw_spin_lock_irqsave) },
	{ 0x4f68e5c9, __VMLINUX_SYMBOL_STR(do_gettimeofday) },
	{ 0x6d3aeeaa, __VMLINUX_SYMBOL_STR(nf_unregister_hook) },
	{ 0x3317697, __VMLINUX_SYMBOL_STR(seq_lseek) },
	{ 0x2e0d2f7f, __VMLINUX_SYMBOL_STR(queue_work_on) },
	{ 0x55a88a22, __VMLINUX_SYMBOL_STR(seq_release) },
	{ 0x4f6b400b, __VMLINUX_SYMBOL_STR(_copy_from_user) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "376FB8E83F3E5CBE28CAA7C");
