#ifdef VENDOR_EDIT
obj-$(CONFIG_OPLUS_SYSTEM_KERNEL)    += system/
#endif /* VENDOR_EDIT */

#ifdef OPLUS_FEATURE_MEMLEAK_DETECT
#Add for svelte logging
obj-$(CONFIG_SVELTE)     +=  svelte/
#endif /* OPLUS_FEATURE_MEMLEAK_DETECT */

obj-$(CONFIG_OPLUS_COMMON_SOFT)	+=  device_info/


#ifdefine OPLUS_ARCH_EXTENDS
obj-y +=  oplus_kevent_feedback/
#endif /* OPLUS_ARCH_EXTENDS */
