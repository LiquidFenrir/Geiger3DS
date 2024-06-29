#!/bin/bash
cd capstone
BUILDDIR=../capstone-build CAPSTONE_BUILD_CORE_ONLY=yes CAPSTONE_ARCHS="arm" CAPSTONE_USE_SYS_DYN_MEM=yes CAPSTONE_DIET=no CAPSTONE_STATIC=yes CAPSTONE_SHARED=no ./make.sh
cp -R ./include/. ../capstone-build/include
