## {
##
##  capstat, renders a set of useful per-prefix, per-AS, etc, cross-repartitions. and more ....
##  Copyright (C) 2016-2020 Jean-Daniel Pauget <jdpauget@rezopole.net>
##  
##  This program is free software; you can redistribute it and/or
##  modify it under the terms of the GNU General Public License
##  as published by the Free Software Foundation; either version 2
##  of the License, or (at your option) any later version.
##  
##  This program is distributed in the hope that it will be useful,
##  but WITHOUT ANY WARRANTY; without even the implied warranty of
##  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
##  GNU General Public License for more details.
##  
##  You should have received a copy of the GNU General Public License
##  along with this program; if not, write to the Free Software
##  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
##
## }


ACLOCAL_AMFLAGS = -I m4

vimtest: capstat
	./capstat yol.pcap --count=100 --sizes
	## test with supplied full-view ...
	## ##./capstat yol.pcap --count=100 --sizes --fullview=full.bgp.txt
	##
	## ##   ./capstat ~/Captures/capture_lyon_paris_20160603.pcap --count=100 --sizes --fullview=full.bgp.txt
	## ./capstat ~/Captures/capture_lyon_paris_20160603.pcap --capture=/users/jd/Captures/capture_lyon_paris_20160603.pcap --count=100 --frames --fullview=full.bgp.txt

test: fullviewtest

.PHONY: fullviewtest
fullviewtest: full.bgp.txt capstat
	./capstat --fullview=full.bgp.txt --dumpfv
	mv fullfv_dump.txt fullfv_dump.bis.txt
	./capstat --fullview=fullfv_dump.bis.txt  --dumpfv
	diff fullfv_dump.bis.txt fullfv_dump.txt  && echo "      fullview re-reading test ok" && rm fullfv_dump.bis.txt

full.bgp.txt: full.bgp.txt.gz
	echo extracting full-view sample from archive
	gzip -dc full.bgp.txt.gz > full.bgp.txt

bin_PROGRAMS = capstat
man1_MANS = capstat.1

capstat_SOURCES = capstat.cpp macaddr.h readline.h fmtstream.h ethertype.h level3addr.h
capstat_CXXFLAGS = @CXXFLAGS@ @RESOLV_CXXFLAGS@ 
capstat_LDADD =  @RESOLV_LDFLAGS@ @LIBPCAPLDFLAGS@

clean-local:
	rm -f full.bgp.txt fullfv_dump.txt fullfv_dump.bis.txt

distclean-local:
	:
	rm -f m4/*.m4
	rm -f config.h.in~
	rm -rf debian
	rm -f Makefile
	rm -f asdig*.deb


