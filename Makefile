all:
	gcc dump-sql.c -o dump-sql -lpcap -L/usr/lib/mysql -lmysqlclient
clean:
	rm -rf dump-sql