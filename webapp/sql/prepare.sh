# SQLiteのデータをMySQLに移動させる
# ベンチのたびに毎回実行するのではなく、事前に一度だけ実行しておく
files=`find ../tenant_db -name *.db`
touch tmp.sql

for file in $files;
do
	cp /dev/null tmp.sql
	./sqlite3-to-sql $file > tmp.sql
	mysql -u"$ISUCON_DB_USER" \
		-p"$ISUCON_DB_PASSWORD" \
		--host "$ISUCON_DB_HOST" \
		--port "$ISUCON_DB_PORT" \
		"isuports_tenant" < tmp.sql
    echo "$file finished"
done
