
all: capstat

vimtest: capstat
	tcpdump -vvv -e -n -r capture* | head -1000 | ./capstat --sizes
	####	tcpdump -vvv -e -n -r capture* | head -10000 | ./capstat
	# tcpdump -vvv -e -n -r capture* | head -100000 | ./capstat

capstat: capstat.cpp macaddr.h readline.h
	g++ -Wall -o capstat capstat.cpp
	# MacOS :  to dig out some bugs, the aithor sometime use this below instead :
	# g++ -stdlib=libstdc++ -Wall -o capstat capstat.cpp

clean:
	rm -f ./capstat

