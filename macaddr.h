
// {
//
//  capstat, renders a set of useful per-prefix, per-AS, etc, cross-repartitions. and more ....
//  Copyright (C) 2016 Jean-Daniel Pauget <jdpauget@rezopole.net>
//  
//  This program is free software; you can redistribute it and/or
//  modify it under the terms of the GNU General Public License
//  as published by the Free Software Foundation; either version 2
//  of the License, or (at your option) any later version.
//  
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//  
//  You should have received a copy of the GNU General Public License
//  along with this program; if not, write to the Free Software
//  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//
// }




#ifndef RZPNETMACADDR
#define RZPNETMACADDR

#include <iostream>
#include <iomanip>

namespace rzpnet {

    using namespace std;

#include <net/ethernet.h>

// #include <string>

// #include <errno.h>

using namespace std;

typedef enum {
    PACKMAC,	    // 2975e099ad98
    CISCO4MAC,	    // 2975.e099.ad98
    REGULARMAC	    // 29:75:e0:99:ad:98
} Tmactype;

class MacAddr  {
  public:
    uint64_t addr;
    // 0123456789
    // b82a.72df.597b
    // 01201201201201201
    // b8:2a:72:df:59:7b
    MacAddr (void) : addr(0xffffffffffffffff) {}
    MacAddr (MacAddr const & o) : addr(o.addr) {}
    MacAddr (uint64_t addr) : addr(addr) {
    }
    inline MacAddr (const ether_addr * pether) : addr (0) {
	const u_char *s = (const u_char *) pether;
	size_t shift = 8*5;
	addr += ((uint64_t)(*s++)) << shift; shift-=8;
	addr += ((uint64_t)(*s++)) << shift; shift-=8;
	addr += ((uint64_t)(*s++)) << shift; shift-=8;
	addr += ((uint64_t)(*s++)) << shift; shift-=8;
	addr += ((uint64_t)(*s++)) << shift; shift-=8;
	addr += ((uint64_t)(*s++)) << shift;
    }
    MacAddr (const string &s) : addr (0xffffffffffffffff) {
	if (s.size() < 12) {
	    cerr << "invalid mac-addr (bad length) : " << s << endl;
	    return;
	}
	uint64_t a = 0;
	size_t p = 0;
	size_t n = 0;
	Tmactype mactype = CISCO4MAC;
	
	for (p=0 ; (n<12) && (p<s.size()) ; p++) {
	    if (p == 2) {
		if (s[p] == ':') {
		    mactype = REGULARMAC;
		} else if (isxdigit (s[p])) {
		    ; //mactype = CISCO4MAC;
		} else
		    return;
	    }
	    if ((mactype != REGULARMAC) && (n==4)) {
		if (isxdigit (s[p]))
		    mactype = PACKMAC;
		else if (s[p] == '.')
		    mactype = CISCO4MAC;
		else
		    return;
	    }

	    if ((mactype == CISCO4MAC) && ((p==4) || (p==9))) {
		if (s[p] != '.') {
		    cerr << "invalid mac-addr (bad separator) : " << s << endl;
		    return;
		}
		continue;
	    }
	    if ((mactype == REGULARMAC) && ((p%3) ==2)) {
		if (s[p] != ':') {
		    cerr << "invalid mac-addr (bad separator) : " << s << endl;
		    return;
		}
		continue;
	    }
	    switch (s[p]) {
		case '0': a+=0x0 ; a<<=4 ; n++ ; continue;
		case '1': a+=0x1 ; a<<=4 ; n++ ; continue;
		case '2': a+=0x2 ; a<<=4 ; n++ ; continue;
		case '3': a+=0x3 ; a<<=4 ; n++ ; continue;
		case '4': a+=0x4 ; a<<=4 ; n++ ; continue;
		case '5': a+=0x5 ; a<<=4 ; n++ ; continue;
		case '6': a+=0x6 ; a<<=4 ; n++ ; continue;
		case '7': a+=0x7 ; a<<=4 ; n++ ; continue;
		case '8': a+=0x8 ; a<<=4 ; n++ ; continue;
		case '9': a+=0x9 ; a<<=4 ; n++ ; continue;
		case 'a': a+=0xa ; a<<=4 ; n++ ; continue;
		case 'b': a+=0xb ; a<<=4 ; n++ ; continue;
		case 'c': a+=0xc ; a<<=4 ; n++ ; continue;
		case 'd': a+=0xd ; a<<=4 ; n++ ; continue;
		case 'e': a+=0xe ; a<<=4 ; n++ ; continue;
		case 'f': a+=0xf ; a<<=4 ; n++ ; continue;
		case 'A': a+=0xa ; a<<=4 ; n++ ; continue;
		case 'B': a+=0xb ; a<<=4 ; n++ ; continue;
		case 'C': a+=0xc ; a<<=4 ; n++ ; continue;
		case 'D': a+=0xd ; a<<=4 ; n++ ; continue;
		case 'E': a+=0xe ; a<<=4 ; n++ ; continue;
		case 'F': a+=0xf ; a<<=4 ; n++ ; continue;
		default:
		    cerr << "invalid mac-addr (unexpected character " << s[p] << ") : " << s << endl;
		    return;
	    }
	}
	addr = a >> 4;	// we did it once too much !
    }

    inline bool valid (void) const { return addr != 0xffffffffffffffff; }
    inline bool invalid (void) const { return addr == 0xffffffffffffffff; }
    inline bool isbroadcast (void) const { return addr == 0x0000ffffffffffff; }

    bool operator< (const MacAddr &a) const {
	return (a.addr < addr);
    }
};

ostream &operator<< (ostream &out, const MacAddr &m) {
    if (m.addr == 0xffffffffffffffff)
	return out << "[bad mac]";
    int p;
    for (p=44 ; p>=0 ; p-= 4) {
	switch ((m.addr >> p) & 0xf) {
	    case 0x0: out << "0"; continue;
	    case 0x1: out << "1"; continue;
	    case 0x2: out << "2"; continue;
	    case 0x3: out << "3"; continue;
	    case 0x4: out << "4"; continue;
	    case 0x5: out << "5"; continue;
	    case 0x6: out << "6"; continue;
	    case 0x7: out << "7"; continue;
	    case 0x8: out << "8"; continue;
	    case 0x9: out << "9"; continue;
	    case 0xa: out << "a"; continue;
	    case 0xb: out << "b"; continue;
	    case 0xc: out << "c"; continue;
	    case 0xd: out << "d"; continue;
	    case 0xe: out << "e"; continue;
	    case 0xf: out << "f"; continue;
	}
    }
    return out;
}

} // namespace rzp_net

#endif  // RZPNETMACADDR

