#!/bin/bash
tar xvfz libressl-2.5.5.tar.gz
patch -p0 < cache-oper.patch
(cd libressl-2.5.5; cmake .; ./configure --prefix=`pwd -P`/local; make -j40 install)
