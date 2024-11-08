UNICORN_CFLAGS = -I$(ISH_SRC)/deps/unicorn/include

USER_CFLAGS += $(UNICORN_CFLAGS) -I$(srctree)/$(EMU_DIR)/include

obj-y = unicorn.o unicorn_user.o

include arch/um/scripts/Makefile.rules