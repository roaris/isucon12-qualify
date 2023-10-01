# SQLiteのデータをMySQLに移動させる
# ベンチのたびに毎回実行するのではなく、事前に一度だけ実行しておく
files=`find ../tenant_db -name *.db | sort -n -t / -k 3` # sortコマンドで数字順に並び替える
i=0

for file in $files;
do
	./sqlite3-to-sql $file > before.sql
	go run process.go
	if [ $(( $i % 2 )) -eq 0 ]; then
		mysql -u"$ISUCON_DB_USER" \
			-p"$ISUCON_DB_PASSWORD" \
			--host "$ISUCON_DB_HOST1" \
			--port "$ISUCON_DB_PORT" \
			"isuports_tenant" < after.sql
	else
		mysql -u"$ISUCON_DB_USER" \
			-p"$ISUCON_DB_PASSWORD" \
			--host "$ISUCON_DB_HOST2" \
			--port "$ISUCON_DB_PORT" \
			"isuports_tenant" < after.sql
	fi
	i=$(($i+1))
	echo "$file finished ($i/100)"
done
