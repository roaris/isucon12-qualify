deploy:
	make -C webapp/go deploy

bench-prepare:
	sudo rm -f /var/log/nginx/access.log
	sudo systemctl reload nginx.service
	sudo rm -f /var/log/mysql/mysql-slow.log
	sudo systemctl restart mysql.service

bench-result:
	mkdir -p alp/dump
	cat /var/log/nginx/access.log \
	| alp ltsv -m '/api/organizer/player/[a-z0-9]+/disqualified,/api/organizer/competition/[a-z0-9]+/finish,/api/organizer/competition/[a-z0-9]+/score,/api/player/player/[a-z0-9]+,/api/player/competition/[a-z0-9]+/ranking' --sort avg -r --dump alp/dump/`git show --format='%h' --no-patch` > /dev/null

latest-alp:
	mkdir -p alp/result
	alp ltsv --load alp/dump/`git show --format='%h' --no-patch` > alp/result/`git show --format='%h' --no-patch`
	vim alp/result/`git show --format='%h' --no-patch`

show-slowlog:
	sudo mysqldumpslow /var/log/mysql/mysql-slow.log

show-applog:
	make -C webapp/go show-applog

enable-pprof:
	sed -i -e 's/PPROF=0/PPROF=1/' env.sh

disable-pprof:
	sed -i -e 's/PPROF=1/PPROF=0/' env.sh

start-pprof:
	docker compose -f=webapp/docker-compose-go.yml exec webapp go tool pprof -http=0.0.0.0:1080 main http://localhost:6060/debug/pprof/profile?seconds=70