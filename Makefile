
all: capstat full.bgp.txt


vimtest: capstat
	./capstat yol.pcap --count=100 --sizes
	# test with supplied full-view ...
	####./capstat yol.pcap --count=100 --sizes --fullview=full.bgp.txt
	#
	####   ./capstat ~/Captures/capture_lyon_paris_20160603.pcap --count=100 --sizes --fullview=full.bgp.txt
	# ./capstat ~/Captures/capture_lyon_paris_20160603.pcap --capture=/users/jd/Captures/capture_lyon_paris_20160603.pcap --count=100 --frames --fullview=full.bgp.txt

full.bgp.txt: full.bgp.txt.gz
	echo extracting full-view sample from archive
	gzip -dc full.bgp.txt.gz > full.bgp.txt

test: fullviewtest

.PHONY: fullviewtest
fullviewtest: full.bgp.txt capstat
	./capstat --fullview=full.bgp.txt --dumpfv
	mv fullfv_dump.txt fullfv_dump.bis.txt
	./capstat --fullview=fullfv_dump.bis.txt  --dumpfv
	diff fullfv_dump.bis.txt fullfv_dump.txt  && echo "      fullview re-reading test ok" && rm fullfv_dump.bis.txt

capstat: capstat.cpp macaddr.h readline.h fmtstream.h ethertype.h level3addr.h
	g++ -Wall -o capstat capstat.cpp -lpcap -lresolv

testtabul: testtabul.cpp fmtstream.h
	g++ -Wall -o testtabul testtabul.cpp
	./testtabul

clean:
	rm -f capstat testtabul full.bgp.txt fullfv_dump.txt fullfv_dump.bis.txt


