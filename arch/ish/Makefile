ifneq ($(wildcard $(objtree)/meson_vars.mk),)
	include $(objtree)/meson_vars.mk
else
	export ISH_SRC = ../..
	export ISH_BUILD = $(ISH_SRC)/build
endif
export ISH_CFLAGS = -I$(ISH_SRC)
export LIB_ISH_EMU = $(ISH_BUILD)/libish_emu.a

ifdef CONFIG_ISH_EMULATOR_ISHEMU
	EMU_DIR = arch/ish/emu/ishemu
endif
export EMU_DIR

KBUILD_DEFCONFIG := ish_defconfig

KBUILD_CFLAGS += -ffreestanding -fPIE

ifdef CONFIG_HOST_DARWIN
	KBUILD_CFLAGS += -U__weak -Wno-incompatible-library-redeclaration
	KBUILD_HOSTCPPFLAGS += -I$(srctree)arch/ish/include-darwin -I$(objtree)arch/ish/include/generated/uapi -I$(srctree)include/uapi
	KBUILD_HOSTCPPFLAGS += -D__EXPORTED_HEADERS__
	KBUILD_LDFLAGS += -platform_version macos 10.15 10.15 -arch x86_64 # TODO
endif

USER_CFLAGS = -I$(srctree)/arch/ish/include
USER_CFLAGS += -DNR_CPUS=$(or $(CONFIG_NR_CPUS),1)
export USER_CFLAGS

core-y += arch/ish/kernel/ arch/ish/mm/ arch/ish/drivers/ arch/ish/net/
ifdef CONFIG_HOST_DARWIN
	head-y += arch/ish/kernel/sections.o
endif

core-y += $(EMU_DIR)/
KBUILD_CPPFLAGS += -I$(srctree)/$(EMU_DIR)/include
ifdef CONFIG_ISH_EMULATOR_ISHEMU
	KBUILD_CPPFLAGS += $(ISH_CFLAGS)
endif

include $(srctree)/arch/ish/Makefile.abi

export CFLAGS_vmlinux
export LIBS_vmlinux
ifdef CONFIG_HOST_DARWIN
	CFLAGS_vmlinux += $(LIB_ISH_EMU)
	CFLAGS_vmlinux += -sectalign __DATA __percpu_first 1000
	CFLAGS_vmlinux += -sectalign __DATA __tracepoints 20
endif
ifdef CONFIG_LINK_EXECUTABLE
	LIBS_vmlinux += -pthread -lm -ldl
endif
# TODO: flags on linux host
vmlinux: $(LIB_ISH_EMU)

# TODO: $(SUBARCH) doesn't work because it's x86_64
UTS_MACHINE := i686