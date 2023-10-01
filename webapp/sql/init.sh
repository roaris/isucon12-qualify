#!/bin/sh

set -ex
cd `dirname $0`

ISUCON_DB_PORT=${ISUCON_DB_PORT:-3306}
ISUCON_DB_USER=${ISUCON_DB_USER:-isucon}
ISUCON_DB_PASSWORD=${ISUCON_DB_PASSWORD:-isucon}
ISUCON_DB_NAME=${ISUCON_DB_NAME:-isuports}

# MySQLを初期化
mysql -u"$ISUCON_DB_USER" \
		-p"$ISUCON_DB_PASSWORD" \
		--host "$ISUCON_DB_HOST1" \
		--port "$ISUCON_DB_PORT" \
		"$ISUCON_DB_NAME" < init_admin.sql

mysql -u"$ISUCON_DB_USER" \
		-p"$ISUCON_DB_PASSWORD" \
		--host "$ISUCON_DB_HOST1" \
		--port "$ISUCON_DB_PORT" \
		"isuports_tenant" < init_tenant.sql

mysql -u"$ISUCON_DB_USER" \
		-p"$ISUCON_DB_PASSWORD" \
		--host "$ISUCON_DB_HOST2" \
		--port "$ISUCON_DB_PORT" \
		"isuports_tenant" < init_tenant.sql

# SQLiteのデータベースを初期化
rm -f ../tenant_db/*.db
rm -f ../tenant_db/*.lock
cp -r ../../initial_data/*.db ../tenant_db/
