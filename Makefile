all:
	g++ -I /usr/include/bcc/compat icmp_logging.cc -lbcc -o icmp_logging