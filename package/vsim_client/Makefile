#
# Copyright (C) 2025 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=vsim_client
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_MAINTAINER:=OpenWrt Team
PKG_LICENSE:=GPL-2.0+

include $(INCLUDE_DIR)/package.mk

define Package/vsim_client
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=WWAN
  TITLE:=OpenWrt vSIM Client
  DEPENDS:=+python3 +python3-requests
  URL:=https://github.com/terminills/openwrt
endef

define Package/vsim_client/description
  OpenWrt vSIM client script that interacts with Flask CRM API endpoints
  for vSIM assignment, heartbeats, error reporting, command polling, and
  command acknowledgment. Provides periodic diagnostics and command execution.
endef

define Build/Compile
	# Nothing to compile for a Python script
endef

define Package/vsim_client/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/usr/bin/openwrt_vsim_client.py $(1)/usr/bin/openwrt_vsim_client.py
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/etc/config/vsim_client $(1)/etc/config/vsim_client
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/vsim_client $(1)/etc/init.d/vsim_client
endef

$(eval $(call BuildPackage,vsim_client))