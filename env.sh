#!/bin/sh

PREFIX=/etc/omobus-scgi.d/ddi
WWW=/var/www/htdocs
HTDOCS=$WWW/ddi
mkdir -m 755 -p $HTDOCS
cp -auvp $PREFIX/*.css $HTDOCS || :
cp -auvp $PREFIX/*.htm $HTDOCS || :
