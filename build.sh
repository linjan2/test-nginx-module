#!/usr/bin/env bash

set -o nounset
set -o errexit

pushd "$(dirname $(readlink -f ${0}))" > /dev/null
BIN=${PWD}/bin
PREFIX=/tmp/nginx

function configure
{
  pushd nginx-1.18.0 > /dev/null
  ./configure \
    --add-module=../plugin \
    --build=custom-build \
    --with-cc-opt='-Wno-pointer-to-int-cast' \
    --with-ld-opt="-Wl,-z,origin,-rpath='\$\$ORIGIN/lib'" \
    --with-debug \
    --builddir=${BIN} \
    --prefix=${PREFIX} \
    --sbin-path=${PREFIX} \
    --conf-path=${PREFIX}/conf/nginx.conf \
    --pid-path=${PREFIX}/nginx.pid \
    --lock-path=${PREFIX}/lock \
    --modules-path=${PREFIX}/modules \
    --error-log-path=${PREFIX}/error.log \
    --http-log-path=${PREFIX}/access.log \
    --http-client-body-temp-path=${PREFIX}/tmp/client_body \
    --http-proxy-temp-path=${PREFIX}/tmp/proxy \
    --http-fastcgi-temp-path=${PREFIX}/tmp/fastcgi \
    --http-uwsgi-temp-path=${PREFIX}/tmp/uwsgi \
    --http-scgi-temp-path=${PREFIX}/tmp/scgi \
    --user='nobody' \
    --group='nobody' \
    --without-http_gzip_module \
    --without-http_rewrite_module
  cp -r ./conf ${BIN}/
  cp -r ./html ${BIN}/
  popd > /dev/null
  cp nginx.conf ${BIN}/conf
}

function build
{
  pushd nginx-1.18.0 > /dev/null
  make build
}

function copy
{
  cp ${BIN}/nginx ${PREFIX}/
  cp -r ${BIN}/conf ${PREFIX}/
  cp -r ${BIN}/html/ ${PREFIX}/
  mkdir -p ${PREFIX}/tmp || : 
}

function run
{
  ${PREFIX}/nginx -g "daemon off;" -c ${PREFIX}/conf/nginx.conf $*
}

function hup
{
  kill -s HUP $(cat ${PREFIX}/nginx.pid)
}

if [ $# -eq 0 ]
then
  build
else
  "$@"
fi
