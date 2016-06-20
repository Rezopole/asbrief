
all: capstat oldcapstat


vimtest: capstat oldcapstat
	./capstat ~/Captures/capture_lyon_paris_20160603.pcap --count=100 --sizes --fullview=full.bgp.txt
	# ./capstat ~/Captures/capture_lyon_paris_20160603.pcap --capture=/users/jd/Captures/capture_lyon_paris_20160603.pcap --count=100 --frames --fullview=full.bgp.txt



capstat: capstat.cpp macaddr.h readline.h fmtstream.h ethertype.h level3addr.h
	g++ -Wall -o capstat capstat.cpp -lpcap

oldcapstat: oldcapstat.cpp macaddr.h readline.h fmtstream.h ethertype.h level3addr.h
	g++ -Wall -o oldcapstat oldcapstat.cpp

oldcapstat.macos: oldcapstat.cpp macaddr.h readline.h fmtstream.h
	# MacOS :  to dig out some bugs, the author sometime use this below instead :
	g++ -stdlib=libstdc++ -Wall -o oldcapstat oldcapstat.cpp

testtabul: testtabul.cpp fmtstream.h
	g++ -Wall -o testtabul testtabul.cpp
	./testtabul

clean:
	rm -f capstat oldcapstat

