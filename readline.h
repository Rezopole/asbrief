
// {
//
//  asbrief, renders a set of useful per-prefix, per-AS, etc, cross-repartitions. and more ....
//  Copyright (C) 2016-2020 Jean-Daniel Pauget <jdpauget@rezopole.net>
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




#ifndef STDJDREADLINE
#define STDJDREADLINE

#include <iostream>

namespace stdjd {

    using namespace std;

    // ----------------- readline -----------------------------------------------------------

    void readline (istream &cin, string &s) {
	while (cin) {
	    char c;
	    size_t n=0;
	    while (cin && cin.get(c) && (c!=10) && (c!=13)) {
		if (c==9) {
		    // this part untabulates things ...
		    int nn = 8 - (n%8);
		    for (int i=0 ; i<nn ; i++) s+=' ', n++;
		} else {
		    s+=c, n++;
		}
	    }
	    if (!cin) return;
	    if (c==10) {
		if (cin.get(c) && (c!=13)) {
		    cin.unget();
		}
		return;
	    }
	    if (c==13) {
		if (cin.get(c) && (c!=10)) {
		    cin.unget();
		}
		return;
	    }
	}
    }
}

#endif // STDJDREADLINE

