# Copyright (c) 2015 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

AUTOMAKE_OPTIONS = foreign subdir-objects

AM_CFLAGS = -Wall -I@TOOLKIT_INCLUDE@ -lzmq

lib_LTLIBRARIES = oor_ctrl_plugin.la oor_ctrl_test_plugin.la
oor_ctrl_plugin_la_SOURCES = oor_ctrl/oor_ctrl.c oor_ctrl/node.c \
	oor_ctrl/oor_ctrl_plugin.api.h 
oor_ctrl_plugin_la_LDFLAGS = -module

BUILT_SOURCES = oor_ctrl/oor_ctrl.api.h

SUFFIXES = .api.h .api

%.api.h: %.api
	mkdir -p `dirname $@` ; \
	$(CC) $(CPPFLAGS) -E -P -C -x c $^ \
	| vppapigen --input - --output $@ --show-name $@

nobase_include_HEADERS =			\
  oor_ctrl/oor_ctrl_all_api_h.h			\
  oor_ctrl/oor_ctrl_msg_enum.h			\
  oor_ctrl/oor_ctrl.api.h

oor_ctrl_test_plugin_la_SOURCES = oor_ctrl/oor_ctrl_test.c oor_ctrl/oor_ctrl_plugin.api.h
oor_ctrl_test_plugin_la_LDFLAGS = -module

if WITH_PLUGIN_TOOLKIT
install-data-hook:
	mkdir /usr/lib/vpp_plugins || true
	mkdir /usr/lib/vpp_api_test_plugins || true
	cp -L $(prefix)/lib/oor_ctrl_plugin.so /usr/lib/vpp_plugins
	cp -L $(prefix)/lib/oor_ctrl_test_plugin.so /usr/lib/vpp_api_test_plugins
endif
