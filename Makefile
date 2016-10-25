VERSION = 0.0.1
MGR = billmgr
LANGS = en ru
PLUGIN = pmopenprovider
#XMLLIST += dist/etc/xml/billmgr_mod_pmopenprovider.xml
WRAPPER += pmopenprovider
CXXFLAGS += -I/usr/local/mgr5/include/billmgr
pmopenprovider_SOURCES = pmopenprovider.cpp
pmopenprovider_FOLDER = processing
pmopenprovider_LDADD = -lmgr -lmgrdb -lprocessingmodule -lprocessingssl -lprocessingdomain
LIB += pmopenprovider_plugin
pmopenprovider_plugin_SOURCES = pmopenprovider_plugin.cpp
SRCDIR=$(BUILD)
BASE ?= /usr/local/mgr5
include $(BASE)/src/isp.mk
