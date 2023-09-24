# SQLiteのデータをMySQLに移動させる
# ベンチのたびに毎回実行するのではなく、事前に一度だけ実行しておく
files=`find ../tenant_db -name *.db`
i=0

for file in $files;
do
	./sqlite3-to-sql $file > before.sql
	go run process.go
	mysql -u"$ISUCON_DB_USER" \
		-p"$ISUCON_DB_PASSWORD" \
		--host "$ISUCON_DB_HOST" \
		--port "$ISUCON_DB_PORT" \
		"isuports_tenant" < after.sql
	i=$(($i+1))
	echo "$file finished ($i/100)"
done
