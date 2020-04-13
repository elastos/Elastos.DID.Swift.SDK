#!/bin/bash

SCRIPT_PATH="$(cd "$(dirname "$0")" && pwd -P )"
SCRIPT_DIRNAME="$(basename "${SCRIPT_PATH}")"

LIBPATH=${SCRIPT_PATH}/../Externals/HDKey
LIBPATHSPV=${SCRIPT_PATH}/../Externals/SPVWrapper/SPVWrapper
LIBPATTERN="/elastos.*ios_arm64.*zip"
LIBDIR="-iphoneos"

if [ $1 = "x64" ] ; then
    LIBPATTERN="/elastos.*ios_x64.*zip"
    LIBDIR="-iphonesimulator"
elif [ $1 = "macOS" ]; then
    LIBPATTERN="/elastos.*darwin_x64.*gz"
    LIBDIR="macosx"
fi

packageUrl=`curl https://github.com/elastos/Elastos.DID.Native.SDK/releases/tag/internal-test | grep -e $LIBPATTERN -o`
libPackageName=${packageUrl##*/}
echo $packageUrl

cd /tmp
echo "https://github.com"${packageUrl} >did_libs.txt

#remove old package
rm ${libPackageName}

wget -i did_libs.txt

cd ${LIBPATH}
mkdir lib

cd lib
mkdir -- ${LIBDIR}
tar --strip-components=1 -zxf /tmp/${libPackageName} -C ${LIBDIR}

