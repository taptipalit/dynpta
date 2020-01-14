
default:	build

clean:
	rm -rf Makefile objs

build:
	$(MAKE) -f objs/Makefile

install:
	$(MAKE) -f objs/Makefile install

modules:
	$(MAKE) -f objs/Makefile modules

upgrade:
	/mnt/Projects/LLVM-custom/test/sensitive-data/nginx/nginx-1.15.9/install/sbin/nginx -t

	kill -USR2 `cat /mnt/Projects/LLVM-custom/test/sensitive-data/nginx/nginx-1.15.9/install/logs/nginx.pid`
	sleep 1
	test -f /mnt/Projects/LLVM-custom/test/sensitive-data/nginx/nginx-1.15.9/install/logs/nginx.pid.oldbin

	kill -QUIT `cat /mnt/Projects/LLVM-custom/test/sensitive-data/nginx/nginx-1.15.9/install/logs/nginx.pid.oldbin`
