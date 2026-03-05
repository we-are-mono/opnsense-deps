/* * Automatically @generated */
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/linker.h>
#include <sys/firmware.h>
#include <sys/systm.h>

extern char _binary_pcieuart9098_combo_v1_bin_start[], _binary_pcieuart9098_combo_v1_bin_end[];

static int
mwifiex_fw_modevent(module_t mod, int type, void *unused){	const struct firmware *fp;
	int error;	switch (type) {	case MOD_LOAD:

		fp = firmware_register("mwifiex_9098_pcie_fw", _binary_pcieuart9098_combo_v1_bin_start , (size_t)(_binary_pcieuart9098_combo_v1_bin_end - _binary_pcieuart9098_combo_v1_bin_start), 1, NULL);
		if (fp == NULL)
			goto fail_0;
		return (0);
	fail_0:
		return (ENXIO);
	case MOD_UNLOAD:
		error = firmware_unregister("mwifiex_9098_pcie_fw");
		return (error);	}	return (EINVAL);}static moduledata_t mwifiex_fw_mod = {        "mwifiex_fw",        mwifiex_fw_modevent,        0};DECLARE_MODULE(mwifiex_fw, mwifiex_fw_mod, SI_SUB_DRIVERS, SI_ORDER_FIRST);MODULE_VERSION(mwifiex_fw, 1);MODULE_DEPEND(mwifiex_fw, firmware, 1, 1, 1);
