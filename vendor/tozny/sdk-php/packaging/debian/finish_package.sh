# $1 is the debian directory
# $2 is the output directory

# adjust ownerships
chown -R root:root $1
chown -R www-data:www-data $1/var/www/library/tozny_client
chmod -R o+r $1/var/www/library/tozny_client

# finally build the package
dpkg-deb --build $1 $2
