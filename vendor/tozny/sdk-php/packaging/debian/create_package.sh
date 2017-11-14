#!/bin/bash

if [ $# -ne 2 ]; then
  echo "usage: $0 <output directory> <version>"
  exit 1;
fi

VERSION="$2"
SCRIPT_DIR=packaging/debian

API_CLIENT_DEB_DIR=/tmp/tozny-api-php-client

rm    -rf $API_CLIENT_DEB_DIR
mkdir -p  $API_CLIENT_DEB_DIR/DEBIAN
mkdir -p  $API_CLIENT_DEB_DIR/var/www/library/tozny_client

sed -e "s/@VERSION@/${VERSION}/g" < $SCRIPT_DIR/control.in > $API_CLIENT_DEB_DIR/DEBIAN/control
cp $SCRIPT_DIR/LICENSE $API_CLIENT_DEB_DIR/var/www/library/tozny_client
cp ./*.php             $API_CLIENT_DEB_DIR/var/www/library/tozny_client

fakeroot $SCRIPT_DIR/finish_package.sh $API_CLIENT_DEB_DIR $1
