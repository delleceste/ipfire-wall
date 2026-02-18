#include <linux/module.h>
#include <linux/export-internal.h>
#include <linux/compiler.h>

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

KSYMTAB_FUNC(packet_suitable_for_mss_change, "", "");
KSYMTAB_FUNC(tcpmss_mangle_packet, "", "");

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "6ACB28C74605196F42CCE57");
