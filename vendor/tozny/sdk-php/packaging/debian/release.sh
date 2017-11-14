#!/bin/bash

maintenance_release () {
  NEW_VERSION=`cat control | grep 'Version:' | sed 's/Version: \([0-9]\{1,2\}\)\.\([0-9]\{1,2\}\)\.\([0-9]\{1,2\}\)/\1 \2 \3/g' | awk '{print ($1)"."($2)"."($3+1)}'`
}

minor_release () {
  NEW_VERSION=`cat control | grep 'Version:' | sed 's/Version: \([0-9]\{1,2\}\)\.\([0-9]\{1,2\}\)\.\([0-9]\{1,2\}\)/\1 \2 \3/g' | awk '{print ($1)"."($2+1)".0"}'`
}

major_release () {
  NEW_VERSION=`cat control | grep 'Version:' | sed 's/Version: \([0-9]\{1,2\}\)\.\([0-9]\{1,2\}\)\.\([0-9]\{1,2\}\)/\1 \2 \3/g' | awk '{print ($1+1)".0.0"}'`
}

do_release () {
    sed -i 's/Version: \([0-9]\{1,2\}\)\.\([0-9]\{1,2\}\)\.\([0-9]\{1,2\}\)/Version: '$NEW_VERSION'/g' control
}

case "$1" in
  maint|maintenance)
    maintenance_release;
    do_release;
    ;;
  min|minor)
    minor_release;
    do_release;
    ;;
  maj|major)
    major_release
    do_release;
    ;;
  *)
    echo "Usage: $0 {maintenance|minor|major}" >&2
    exit 3
    ;;
esac

exit 0;
