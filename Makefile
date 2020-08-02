# This file is Confidential Information of CUJO LLC.
# Copyright (c) 2020 CUJO LLC. All rights reserved.

ifndef BUILD_DIR
$(error BUILD_DIR is undefined, but required!)
endif
ifndef STAGING_ROOT
$(error STAGING_ROOT is undefined, but required!)
endif
ifndef INSTALL_ROOT
$(error INSTALL_ROOT is undefined, but required!)
endif
ifndef CUJO_PREFIX
$(error CUJO_PREFIX is undefined, but required!)
endif

STAGING_CUJO := $(STAGING_ROOT)$(CUJO_PREFIX)
INSTALL_CUJO := $(INSTALL_ROOT)$(CUJO_PREFIX)

LIBNAME ?= luamnl.so

all: | $(BUILD_DIR)
	$(CC) \
		$(LIBMNL_CFLAGS) $(LIBMNL_LIBS) \
		-I$(STAGING_CUJO)/include -L$(STAGING_CUJO)/lib \
		$(CFLAGS) $(LDFLAGS) $(LUA_CFLAGS) \
		"$(BUILD_DIR)"/luamnl.c \
		-std=c99 -D_GNU_SOURCE \
		-fPIC -shared -o "$(BUILD_DIR)/$(LIBNAME)"

install: all
	install -Dpm0755 \
		"$(BUILD_DIR)/$(LIBNAME)" \
		"$(INSTALL_CUJO)/$(LUA_LIBDIR)"/cujo/mnl.so

install-testless: install

clean:
	rm -rf "$(BUILD_DIR)" \
		"$(INSTALL_CUJO)/$(LUA_LIBDIR)"/cujo/mnl.so
