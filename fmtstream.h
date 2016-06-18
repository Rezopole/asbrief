
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




#ifndef NSTABULATEDOUT
#define NSTABULATEDOUT

#include <iostream>
#include <iomanip>
#include <string>
#include <list>

namespace NSTabulatedOut {

    using namespace std;

    class TabulatedOut {
      public:
	list <string> ls;
	ostream &out;

	TabulatedOut (ostream & out) : out (out) {}

	void push_back (const string &s) {
	    ls.push_back (s);
	}

	void flush (void) {
	    list<string>::iterator li;
	    list<size_t> tab;

	    for (li=ls.begin() ; li!=ls.end() ; li++) {
		string const &s = *li;
		size_t p, q,
		       tabsize,
		       l = s.size();
		list<size_t>::iterator lti = tab.begin();
		for (p=0 ; p<l ; ) {
		    q = s.find ('\t', p);
		    if (q == string::npos)
			tabsize = l-p;
		    else
			tabsize = q-p;
		    
		    if (lti == tab.end()) {
			tab.push_back (tabsize);
		    } else {
			if (tabsize > *lti) *lti = tabsize;
			lti ++;
		    }
		    if (q == string::npos)
			break;
		    p = q+1;
		    if ((s[p] != '-') && (s[p] != '+')) {
			cerr << "warning : missing '+' or '-' after \\t  !!!" << endl;
		    } else
			p++;
		}
	    }

	    for (li=ls.begin() ; li!=ls.end() ; li++) {
		string const &s = *li;
		size_t p, q,
		       l = s.size();
		list<size_t>::iterator lti = tab.begin();
		for (p=0 ; p<l ; ) {
		    q = s.find ('\t', p);
		    if (q == string::npos) {
			out << setw(*lti) << s.substr(p) << ' ';
			break;
		    } else {
			if (s[q+1] == '-') {
			    out << std::left << setw(*lti) << s.substr(p, q-p) << ' ';
			    p = q + 2;
			} else if (s[q+1] == '+') {
			    out << std::right << setw(*lti) << s.substr(p, q-p) << ' ';
			    p = q + 2;
			} else {
			    out << setw(*lti) << s.substr(p, q-p) << ' ';
			    p = q + 1;
			}
		    }
		    
		    lti ++;
		    if (lti == tab.end()) break;
		}
		out << endl;
	    }
	}
    };

} // namespace NSTabulatedOut

#endif // NSTABULATEDOUT
