
all: capstat


vimtest: capstat
	tcpdump -vvv -e -n -r ../Captures/capture* | head -1000 | ./capstat --sizes --fullview=full.bgp.txt
	####	tcpdump -vvv -e -n -r capture* | head -10000 | ./capstat
	# tcpdump -vvv -e -n -r capture* | head -100000 | ./capstat

capstat: capstat.cpp macaddr.h readline.h fmtstream.h
	g++ -Wall -o capstat capstat.cpp

capstat.macos: capstat.cpp macaddr.h readline.h fmtstream.h
	# MacOS :  to dig out some bugs, the author sometime use this below instead :
	g++ -stdlib=libstdc++ -Wall -o capstat capstat.cpp

testtabul: testtabul.cpp fmtstream.h
	g++ -Wall -o testtabul testtabul.cpp
	./testtabul

clean:
	rm -f capstat testtabul

