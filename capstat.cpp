
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




#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <string>
#include <list>
#include <map>

#include <math.h>   // log2
#include <stdlib.h> // atol
#include <arpa/inet.h>	// inet_pton
#include <errno.h>  // errno
#include <string.h> // strerror

#include <stdio.h>
#include <pcap.h>

#include "macaddr.h"
#include "ethertype.h"
#include "level3addr.h"

#include "readline.h"
#include "fmtstream.h"



// #include <netinet/if_ether.h> 

using namespace std;
using namespace stdjd;
using namespace rzpnet;


size_t seek_ending_parenthesis (const string &s, size_t p) {
    size_t q = s.find ('(', p);
    if (q == string::npos) return p;

    p = q+1;
    int parenth_level = 1;
    do {
	q = s.find_first_of ("()", p);
	if (q == string::npos) return string::npos;
	if (s[q] == '(')
	    parenth_level ++;
	else if (s[q] == ')')
	    parenth_level --;
	else {
	    cerr << "seek_ending_parenthesis : what are we doing here ? [" << s.substr(p) << "]" << endl;
	    return string::npos;
	}
	p = q+1;
    } while (parenth_level > 0);
    return p;
}

// --------- ethernet.desc ---------------------------------------------------------------------------------------------------------------------

map <MacAddr, string> ethernetdesc;

void readethernetdesc (const string &fname) {
    ifstream file(fname.c_str());

    while (file) {
	string s;
	readline (file, s);
	size_t p = s.find(':');
	if (p == string::npos)
	    continue;
	MacAddr m(s.substr (0,p));
	if (m.invalid())
	    continue;
	string desc = s.substr (p+1);
	if (desc.size() == 0)
	    continue;
	ethernetdesc[m] = desc;
    }
}

void matcher (const MacAddr &m, ostream &out) {
    map <MacAddr, string>::iterator mi = ethernetdesc.find(m);
    if (mi == ethernetdesc.end())
	out << m;
    else
	out << mi->second << " (" << m << ")";
}

// --------- AS (autonomous System) ------------------------------------------------------------------------------------------------------------

class AS {
  public:
    int as;

    AS (void) : as (-1) {}
    AS (int as) : as(as) {}
    AS (const AS &a) : as(a.as) {}
    bool operator< (const AS &a) const {
	return as < a.as;
    }
};

map <int, string> ASdesc;

ostream &operator<< (ostream &out, const AS &a) {
    map <int, string>::const_iterator mi = ASdesc.find (a.as);
    if (mi!=ASdesc.end())
	return out << "(" << mi->second << " as" << a.as << ")";
    else
	return out << "(as" << a.as << ")";
}

// --------- Level3Addr ------------------------------------------------------------------------------------------------------------------------

void matcher (const Level3Addr &a, ostream &out);  // thyis one is defined later because of Level3Addr / Prefix interdependencies

// --------- Level3AddrPair : a pair of level-3 addresses, src / dst ---------------------------------------------------------------------------

class Level3AddrPair {
  public:
    Level3Addr src, dst;
    Level3AddrPair () {}
    Level3AddrPair (Level3Addr src, Level3Addr dst) :
	src(src), dst(dst) {}
    Level3AddrPair (Level3AddrPair const & o) : src(o.src), dst(o.dst) {}
    bool operator< (const Level3AddrPair &a) const {
	if (a.src < src)
	    return true;
	else if (src < a.src)
	    return false;
	else if (a.dst < dst)
	    return true;
	else
	    return false;
    }
};
ostream &operator<< (ostream &out, const Level3AddrPair &p) {
    stringstream s;
    s << "[ " << p.src << "\t-" <<  p.dst << "\t+]";
    return out << s.str();
}
void matcher (const Level3AddrPair &p, ostream &out) {
    out << "[ ";
    matcher (p.src, out);
    out << "\t-";
    matcher (p.dst, out);
    out << "\t+]";
}


// --------- MacPair : a pair of mac addresses, src / dst --------------------------------------------------------------------------------------

class MacPair {
  public:
    MacAddr src, dst;
    MacPair () {}
    MacPair (MacAddr src, MacAddr dst) :
	src(src), dst(dst) {}
    MacPair (MacPair const & o) : src(o.src), dst(o.dst) {}
    bool operator< (const MacPair &a) const {
	if (a.src < src)
	    return true;
	else if (src < a.src)
	    return false;
	else if (a.dst < dst)
	    return true;
	else
	    return false;
    }
};
ostream &operator<< (ostream &out, const MacPair &p) {
    return out << "[ " << p.src << "\t-" << p.dst << "\t+]";
}

void matcher (const MacPair &p, ostream &out) {
    out << "[ ";
    matcher (p.src, out);
    out << "\t-";
    matcher (p.dst, out);
    out << "\t+]";
}

// --------- ASPair : a pair of AS src / dst ---------------------------------------------------------------------------------------------------

class ASPair {
  public:
    AS src, dst;
    ASPair () {}
    ASPair (AS src, AS dst) :
	src(src), dst(dst) {}
    ASPair (ASPair const & o) : src(o.src), dst(o.dst) {}
    bool operator< (const ASPair &a) const {
	if (a.src < src)
	    return true;
	else if (src < a.src)
	    return false;
	else if (a.dst < dst)
	    return true;
	else
	    return false;
    }
};
ostream &operator<< (ostream &out, const ASPair &p) {
    return out << "[ " << p.src << "\t-" << p.dst << "\t+]";
}

// void matcher (const ASPair &p, ostream &out) {
//     out << '[';
//     matcher (p.src, out);
//     out << " ";
//     matcher (p.dst, out);
//     out << ']';
// }

// --------- Qualifier -------------------------------------------------------------------------------------------------------------------------

class Qualifier {
  public:
    size_t nb;	    // number of packet, usually
    size_t len;	    // total length of said packets

    Qualifier (void) : nb(0), len(0) {};
    Qualifier (size_t nb, size_t len) : nb(nb), len(len) {};
    Qualifier (size_t len) : nb(1), len(len) {};
    Qualifier (const Qualifier &q) : nb(q.nb), len(q.len) {};
    Qualifier &operator+= (Qualifier const &q) {
	len += q.len;
	nb += q.nb;
	return *this;
    }
};


// --------- mapped T / Qualifier template -----------------------------------------------------------------------------------------------------

template <typename T>
class MappedQualifier : public map <T, Qualifier> {
  public:
    Qualifier localtotal;

    MappedQualifier (void) : localtotal() {}
};


// --------- desc_[nb/len] Templates for map<T,Qualifier> types --------------------------------------------------------------------------------

template <typename T> void matcher (const T &a, ostream &out) {
    out << a ;
}

template <typename T> bool desc_comparator_nb (typename MappedQualifier<T>::const_iterator mi1, typename MappedQualifier<T>::const_iterator mi2) {
    return mi1->second.nb > mi2->second.nb;
}


template <typename T> void dump_desc_nb (const string & tname, MappedQualifier<T> const &m, ostream &cout, Qualifier total, bool matched=false, double ceil=1.0) {
    cout << tname << " repartition : " << m.size() << " " << tname << ", spread over " << m.localtotal.nb << " packets" << endl;
    //cout << m.size() << " entries" << ", total: " << m.localtotal.nb << " packets" << endl;
    if ((m.size() ==0) || (m.localtotal.nb==0))
	return;


    list <typename MappedQualifier<T>::const_iterator> l;
    typename MappedQualifier<T>::const_iterator mi;
    for (mi=m.begin() ; mi!=m.end() ; mi++)
	l.push_back (mi);

    l.sort (desc_comparator_nb<T>);

//    int maxw = (int)(log2((*(l.begin()))->second.nb) / log2(10)) + 1;
//    int nw = (int)(log2(l.size()) / log2(10)) + 1;
    size_t n = 0;
    size_t curtot = 0;
    typename list <typename MappedQualifier<T>::const_iterator>::const_iterator li;

    NSTabulatedOut::TabulatedOut tabul (cout);

    for (li=l.begin() ; li!=l.end() ; li++) {
	stringstream buf;

	curtot += (*li)->second.nb;
	n++;

	buf << n << "\t+";
	if (matched) {
	    matcher((*li)->first, buf);
	    buf << "\t-";
	} else {
	    buf << (*li)->first << "\t-";
	}

	buf << (*li)->second.nb << "\t+"
	     << (100*(*li)->second.nb)/m.localtotal.nb << "%\t+"
	     << (100*curtot)/m.localtotal.nb << "%\t+"
	     << " ("
	     << (100*(*li)->second.nb)/total.nb << "%\t+"
	     << (100*curtot)/total.nb << "%\t+"
	     << " grand-total)";
	tabul.push_back (buf.str());
	if ((double)curtot/(double)m.localtotal.nb > ceil) break;
    }
    tabul.flush();
}

template <typename T> bool desc_comparator_len (typename MappedQualifier<T>::const_iterator mi1, typename MappedQualifier<T>::const_iterator mi2) {
    return mi1->second.len > mi2->second.len;
}


template <typename T> void dump_desc_len (const string & tname, MappedQualifier<T> const &m, ostream &cout, Qualifier total, bool matched=false, double ceil=1.0) {
    cout << tname << " repartition : " << m.size() << " " << tname << ", spread over " << m.localtotal.len << " bytes" << endl;
    // cout << m.size() << " entries" << ", total: " << m.localtotal.len << " bytes" << endl;
    if ((m.size() ==0) || (m.localtotal.len==0))
	return;


    list <typename MappedQualifier<T>::const_iterator> l;
    typename MappedQualifier<T>::const_iterator mi;
    for (mi=m.begin() ; mi!=m.end() ; mi++)
	l.push_back (mi);

    l.sort (desc_comparator_len<T>);

//    int maxw = (int)(log2((*(l.begin()))->second.len) / log2(10)) + 1;
//    int nw = (int)(log2(l.size()) / log2(10)) + 1;
    size_t n = 0;
    size_t curtot = 0;
    typename list <typename MappedQualifier<T>::const_iterator>::const_iterator li;

    NSTabulatedOut::TabulatedOut tabul (cout);

    for (li=l.begin() ; li!=l.end() ; li++) {
	stringstream buf;

	curtot += (*li)->second.len;
	n++;

	buf << n << "\t+";
	if (matched) {
	    matcher((*li)->first, buf);
	    buf << "\t-";
	} else {
	    buf << (*li)->first << "\t-";
	}

//	cout << setw(maxw) << (*li)->second.len << " "
//	     << setw(3)    << (100*(*li)->second.len)/m.localtotal.len << "% "
//	     << setw(3)    << (100*curtot)/m.localtotal.len << "%"
//	     << endl;
	buf << (*li)->second.len << "\t+"
	     << (100*(*li)->second.len)/m.localtotal.len << "%\t+"
	     << (100*curtot)/m.localtotal.len << "%\t+"
	     << " ("
	     << (100*(*li)->second.len)/total.len << "%\t+"
	     << (100*curtot)/total.len << "%\t+"
	     << " grand-total)";
	tabul.push_back (buf.str());
	if ((double)curtot/(double)m.localtotal.len > ceil) break;
    }
    tabul.flush();
}

// --------- insert_qualifier templates --------------------------------------------------------------------------------------------------------

template <typename T> void insert_qualifier (MappedQualifier <T> &m, T const &key, Qualifier q) {
    typename MappedQualifier<T>::iterator mi = m.find (key);
    m.localtotal += q;
    if (mi != m.end())
	mi->second += q;
    else
	m[key] = q;
}

// --------- hash full view --------------------------------------------------------------------------------------------------------------------


class Prefix;

class Prefix {
  public:
    Level3Addr a;   // start address
    int ml;	    // mask len, -1 == invalid prefix
    mutable Prefix const *parent;
    mutable int as;	    // le numero d'as ...

    Prefix (void) : a(), ml(-1), parent(NULL), as(-1) {}

    Prefix (Prefix const & pr) : a(pr.a), ml(pr.ml), parent(NULL), as(pr.as) {}

    inline void setparent (Prefix const &p) const {
	parent = &p;
    }

    inline void setas (int new_as) const {
	as = new_as;
    }

    inline TEthertype gettype (void) { return a.t; }

    inline bool contain (const Prefix &p) const {
	Level3Addr b = p.a;
	b.applymask (ml);
	if ((a == b) && (ml <= p.ml))
	    return true;
	else 
	    return false;
    }

    Prefix (Level3Addr prop_a, int prop_ml, bool lousycreation = false) : a(), ml(-1), as(-1) {
	switch (prop_a.t) {
	    case TETHER_IPV4:
		if ((prop_ml <0) || (prop_ml>32)) {
		    ml = -1;
		    return;
		}
		break;
	    case TETHER_IPV6:
		if ((prop_ml <0) || (prop_ml>128)) {
		    ml = -1;
		    return;
		}
		break;
	    default:
		ml = -1;
		return;
	}

	Level3Addr m(prop_a);
	m.applymask (prop_ml);
	if (lousycreation) {	// we accept unmatched address start vs masklen
	    a = m;
	    ml = prop_ml;
// cerr << "good prefix1 : " << prop_a << "/" << prop_ml << endl;
	    return;
	}
	if (prop_a == m) {
	    a = prop_a;
	    ml = prop_ml;
// cerr << "good prefix2 : " << prop_a << "/" << prop_ml << endl;
	    return;
	}
cerr << "bad prefix : " << prop_a << "/" << prop_ml << endl;
	ml = -1;
	return;
    }
    inline bool valid (void) const {
	return (ml != -1);
    }
    inline bool invalid (void) const {
	return (ml == -1);
    }
    bool operator< (const Prefix &pr) const {
	if (a < pr.a) {
	    return true;
	} else if (pr.a < a) {
	    return false;
	} else if (ml < pr.ml) {
	    return true;
	} else if (pr.ml < ml) {
	    return false;
	}
	return false;
    }
    bool operator== (const Prefix &pr) const {
	if (a == pr.a) {
	    if (ml != pr.ml)
		return false;
	    else
		return true;
	} else
	    return false;
    }
};
ostream &operator<< (ostream &out, const Prefix &pr) {
    return out << pr.a << "/" << pr.ml;
}


class HashedPrefixes {
  public:

    map <Prefix, int> m;

    HashedPrefixes () {
	/// Level3Addr zero(TETHER_IPV6, "0::");
	Level3Addr zero(TETHER_IPV4, "0.0.0.0");
	Prefix All (zero, 0);
	m[All] = 0;
    }

    void insert (Prefix const &pr, int AS) {
	if (pr.invalid()) return;
//	map <Prefix, size_t>::iterator mi = m.upper_bound (pr);
//	if (mi == m.end()) { // this should not occur since we've pushed an initial all-match-prefix
//	    cerr << "HashedPrefixes::insert : \"Houston, we have a problem !\" : no upper bound found pr=" << pr << endl;
//	    return;
//	}
//	if (mi->first == pr) { // we've got a duplicate ?? 
//	    cerr << "HashedPrefixes::insert : duplicate prefix : " << pr << endl;
//	    return;
//	}
	m[pr] = AS;
    }
    void reparent (void) {
	map <Prefix, int>::iterator mi, mj;

	for (mi=m.begin() ; mi!=m.end() ; mi++) {
	    mi->first.setas (mi->second);
	    mj=mi;
	    for (mj++ ; mj!=m.end() ; mj++) {
		if (mi->first.contain (mj->first)) {
// if (mi->first.ml > 0)
// cerr << mi->first << " is parent of " << mj->first << endl;
		    mj->first.setparent (mi->first);
		} else
		    break;
	    }
	}
    }
    int getAS (Level3Addr const &a) {
	int mask;
	switch (a.t) {
	    case TETHER_IPV4:
		mask = 32;
		break;
	    case TETHER_IPV6:
		mask = 128;
		break;
	    default:
		return 0;
	}
	Prefix tofind(a, mask);
	map <Prefix, int>::iterator mi = m.upper_bound (tofind);
////		if (mi!=m.begin())
////		    mi --;
////	////////	if (mi == m.end()) { // this should not occur since we've pushed an initial all-match-prefix
////	////////	    cerr << "HashedPrefixes::insert : \"Houston, we have a problem !\" : no upper bound found pr=" << a << " as prefix " << tofind << endl;
////	////////	    return -1;
////	////////	}
////	//	if (mi->first == pr) { // we've got a duplicate ?? 
////	//	    cerr << "HashedPrefixes::insert : duplicate prefix : " << pr << endl;
////	//	    return;
////	//	}
////	//cerr << "   getAS(" << a << ") = " << mi->first << " = " << mi->second << endl;
////		Level3Addr b = a;
////		b.applymask (mi->first.ml);
////		if (b == mi->first.a)
////		    return mi->second;
////		else {
////	cerr << "getAS : " << a << " not into " << mi->first << endl;
////		    return -1;
////		}

	// version qui march en arriere de prefix en prefix jusqu'au debut ...
if (false) {
	if (mi==m.begin()) return mi->second;
	mi --;

	while ((mi!=m.begin()) && ((mi->first.a < a) || (mi->first.a == a))) {
	    Level3Addr b = a;
	    b.applymask (mi->first.ml);
	    if (b == mi->first.a)
		return mi->second;
	    mi--;
	}
	
cerr << "getAS : " << a << " not into " << mi->first << endl;
	return -1;
} else {
	if (mi==m.begin()) return mi->second;
	mi --;
	// version qui remonte de parent en parent en subnets imbriqués
	Prefix const * pp = &mi->first;

	while (pp != NULL) {
	    if (pp->contain (tofind))
		return pp->as;
	    else
		pp = pp->parent;
	}
	if (pp == NULL)
	    return -2;
	return -3;
}
    }
};
ostream & operator<< (ostream &out, const HashedPrefixes &h) {
    map <Prefix, int>::const_iterator mi;
    for (mi=h.m.begin() ; mi!=h.m.end() ; mi++) {
	out << "   m[" << mi->first << "] = " << mi->second << endl;
    }
    return out;
}

HashedPrefixes view_ipv4;
HashedPrefixes view_ipv6;

int retrieve_last_as (const string & s) {
    size_t p;
    if ((s.size() < 64) || (!isalnum (s[63])))
	return -1;
    p = s.rfind (' ');
    if (p == string::npos) return -1;
    if (p < 62) return -1;
    int AS = atoi (s.substr(p+1).c_str());
    if (AS != 0) return AS;
    if (p == 0) return -1;

    p = s.rfind (' ', p-1);
    if (p == string::npos) return -1;
    if (p < 62) return -1;
    AS = atoi (s.substr(p+1).c_str());
    if (AS != 0) return AS;

    return -1;
}

typedef enum {
    RFV_SEEK_LEGEND,
    RFV_SEEK_EXPLICITPREFIX,
    RFV_SEEKBESTROUTE,
    RFV_SEEK_GOODASPATH
} RFV_State;

void hash_full_bgp (istream &cin) {
    RFV_State status = RFV_SEEK_LEGEND;
    map <int, int> IP4ases, IP6ases, ases;

    size_t lno = 0;
    Prefix curprefix;

    cout << "reading full view ... " ;
    cout.flush();

    while (cin) {
	string s;
	lno++; readline (cin, s);
	size_t p, q;

//if (lno >= 100) return;

	switch (status) {
	  case RFV_SEEK_LEGEND:
	    if (s != "     Network          Next Hop            Metric LocPrf Weight Path") {
		continue;
	    } else {
		status = RFV_SEEK_EXPLICITPREFIX;
	    }
	    break;

	  case RFV_SEEK_EXPLICITPREFIX:
	    if ((s.size() > 6) && (! isxdigit (s[5]))) continue;
	    p = s.find_first_of ("0123456789abcdefABCDEF");
	    if (p != string::npos) {
		q = s.find_first_not_of ("0123456789", p);
		if ((q != string::npos) && (s[q] == '.')) { // it looks like an IPv4 !	

		    Level3Addr prefixbase(TETHER_IPV4, s.substr(p));
		    q = s.find_first_not_of("0123456789.", p);
		    if ((q != string::npos) && ((s[q] == '/') || (s[q] == ' '))) {	// it looks like an IPv4 prefix ...
			int masklen;
			if (s[q] == '/')
			    masklen = atoi (s.substr (q+1).c_str());
			else {
static Level3Addr firstclassB (TETHER_IPV4, "128.0.0.0");
static Level3Addr firstclassC (TETHER_IPV4, "192.0.0.0");
static Level3Addr firstclassD (TETHER_IPV4, "224.0.0.0");
static Level3Addr firstclassE (TETHER_IPV4, "240.0.0.0");
			    if (prefixbase < firstclassB)
				masklen = 8;
			    else if (prefixbase < firstclassC)
				masklen = 16;
			    else if (prefixbase < firstclassD)
				masklen = 24;
			    else if (prefixbase < firstclassE) {
				masklen = 32;
cerr << "hash_full_bgp : we have a ClassD prefix : " << prefixbase << " ??" << endl;
			    } else {
				masklen = 32;
cerr << "hash_full_bgp : we have a ClassE prefix : " << prefixbase << " ??" << endl;
			    }
			}
			Prefix prefix(prefixbase, masklen);
			if (prefix.valid()) {
			    if (s[2] == '>') {
				int AS = retrieve_last_as (s);
				if (AS != -1) {
				    view_ipv4.insert (prefix, AS);
				    IP4ases [AS] = 1;
				    ases [AS] = 1;
				}
			    } else {
				curprefix = prefix;
				status = RFV_SEEKBESTROUTE;
			    }
			}
		    }

		} else {
		    q = s.find_first_not_of ("0123456789abcdefABCDEF", p);
		    if ((q != string::npos) && (s[q] == ':')) { // it looks like an IPv6 !	

		    Level3Addr prefixbase(TETHER_IPV6, s.substr(p));
		    q = s.find_first_not_of("0123456789abcdefABCDEF:", p);
		    if ((q != string::npos) && (s[q] == '/')) {	// it looks like an IPv4 prefix ...
			int masklen = atoi (s.substr (q+1).c_str());
			Prefix prefix(prefixbase, masklen);
			if (prefix.valid()) {
			    if (s[2] == '>') {
				int AS = retrieve_last_as (s);
				if (AS != -1) {
				    view_ipv6.insert (prefix, AS);
				    IP6ases [AS] = 1;
				    ases [AS] = 1;
				}
			    } else {
				curprefix = prefix;
				status = RFV_SEEKBESTROUTE;
			    }
			}
		    }


		    }
		}
	    }
	    break;

	  case RFV_SEEKBESTROUTE:
	    // here, maybe we should roll back to previous state if we encounter a new prefix start line ?
	    if (s[2] == '>') {
		if ((s.size()<64) || (!isalnum(s[63]))) {
		    status = RFV_SEEK_GOODASPATH;
		    break;
		}
		int AS = retrieve_last_as (s);
		if (AS != -1) {
		    switch (curprefix.gettype()) {
		      case TETHER_IPV4:
			view_ipv4.insert (curprefix, AS);
			IP4ases [AS] = 1;
			ases [AS] = 1;
			break;
		      case TETHER_IPV6:
			view_ipv6.insert (curprefix, AS);
			IP6ases [AS] = 1;
			ases [AS] = 1;
			break;
		      default:
			;
		    }
		}
		status = RFV_SEEK_EXPLICITPREFIX;
	    }
	    break;

	  case RFV_SEEK_GOODASPATH:
	    // here, maybe we should roll back to previous state if we encounter a new prefix start line ?
	    if ((s.size()<65) || (!isalnum(s[64])))
		break;
	    else {
		int AS = retrieve_last_as (s.substr(1));
		if (AS != -1) {
		    switch (curprefix.gettype()) {
		      case TETHER_IPV4:
			view_ipv4.insert (curprefix, AS);
			IP4ases [AS] = 1;
			ases [AS] = 1;
			break;
		      case TETHER_IPV6:
			view_ipv6.insert (curprefix, AS);
			IP6ases [AS] = 1;
			ases [AS] = 1;
			break;
		      default:
			;
		    }
		}
		status = RFV_SEEK_EXPLICITPREFIX;
	    }
	    break;
	}
    }

    cout << " done. " << view_ipv4.m.size() << " IPv4 prefixes (" << IP4ases.size()<< " AS), "
	 << view_ipv6.m.size() << " IPv6 prefixes (" << IP6ases.size()<< " AS).   total :  " << ases.size() << " AS" << endl;
    
}

void hash_asnlist (istream &cin) {
    size_t lno = 0;
    while (cin) {
	string s;
	lno++; readline (cin, s);
	size_t p;

	p = s.find (';');
	if (p == string::npos) continue;
	if (s.size() <= p+1) continue;
	int as = atoi (s.substr(0, p).c_str());
	if (as>0)
	    ASdesc [as] = s.substr(p+1);
    }
}

void matcher (const Level3Addr &a, ostream &out) {
    AS as = 0;
    switch (a.t) {
      case TETHER_IPV4:
	as = view_ipv4.getAS(a);
	    
	if (as.as == 0)
	    out << a;
	else
	    out << a << as;
	break;

      case TETHER_IPV6:
	as = view_ipv6.getAS(a);
	    
	if (as.as == 0)
	    out << a;
	else
	    out << a << as;
	break;

      default:
	out << a;
    }
}

int getAS (const Level3Addr &a) {
    switch (a.t) {
      case TETHER_IPV4:
	return view_ipv4.getAS(a);

      case TETHER_IPV6:
	return view_ipv6.getAS(a);

      default:
	return 0;
    }
}

// --------- VLan ------------------------------------------------------------------------------------------------------------------------------

class VLan {
  public:
    int id;

    VLan (void) : id(-2) {}
    VLan (int id) : id(id) {}
    VLan (const VLan &vl) : id(vl.id) {}

    bool operator< (const VLan &vl) const {
	return id < vl.id;
    }
};

ostream &operator<< (ostream &out, const VLan vl) {
    if (vl.id > 0)
	return out << "vlan." << vl.id;
    else if (vl.id == -2)
	return out << "vlan.undefined";
    else if (vl.id == -1)
	return out << "untagged";
    else
	return out << "vlan.weird." << vl.id;
}

// ---------------------------------------------------------------------------------------------------------------------------------------------


MappedQualifier <MacAddr> rep_src_macaddr;
MappedQualifier <MacAddr> rep_dst_macaddr;
MappedQualifier <MacPair> rep_pair_macaddr;

MappedQualifier <Level3Addr> rep_l3src;
MappedQualifier <Level3Addr> rep_l3dst;
MappedQualifier <Level3AddrPair> rep_l3pair;

MappedQualifier <Level3Addr> rep_ip6src;
MappedQualifier <Level3Addr> rep_ip6dst;
MappedQualifier <Level3AddrPair> rep_ip6pair;

MappedQualifier <AS> rep_ASsrc;
MappedQualifier <AS> rep_ASdst;
MappedQualifier <ASPair> rep_ASpair;

MappedQualifier <Ethertype> rep_ethertype;
MappedQualifier <VLan> rep_vlan;

size_t totsize = 0;
size_t nbpacket = 0;

int ipv4_mask = 24;
int ipv6_mask = ipv4_mask*2;

bool displaysizes = true;
bool displayframes = true;
double percent_ceil = 0.9;
bool matched = true;


// --------- proper pcap part ------------------------------------------------------------------------------------------------------------------

class PacketQual {
  public:
    int ipv4_mask;
    int ipv6_mask;
    MacAddr src, dst;
    Level3Addr l3src, l3dst;
    Ethertype ethertype;
    long packetlen;
    int vlan;

    PacketQual (void) : packetlen (0), vlan (-1) {}
    void invalidate (void) {
	src.addr = 0xffffffffffffffff;
	dst.addr = 0xffffffffffffffff;
	ethertype.ethertype = TETHER_UNKNOWN;
	l3src.t = TETHER_UNKNOWN;
	l3dst.t = TETHER_UNKNOWN;
    }
};

bool debug = false;

void process_ipv4 (u_char *args, const u_char *packet, size_t len) {
    PacketQual &pq = *(PacketQual *) args;
    Level3Addr l3src (TETHER_IPV4, packet+12);
    Level3Addr l3dst (TETHER_IPV4, packet+16);
    if (debug)
	cout << "      " << l3src << " -> " << l3dst << endl;
    pq.l3src = l3src;
    pq.l3src.applymask (pq.ipv4_mask);
    pq.l3dst = l3dst;
    pq.l3dst.applymask (pq.ipv4_mask);
}

void process_ipv6 (u_char *args, const u_char *packet, size_t len) {
    PacketQual &pq = *(PacketQual *) args;
    Level3Addr l3src (TETHER_IPV6, packet+8);
    Level3Addr l3dst (TETHER_IPV6, packet+24);
    if (debug)
	cout << "      " << l3src << " -> " << l3dst << endl;
    pq.l3src = l3src;
    pq.l3src.applymask (pq.ipv6_mask);
    pq.l3dst = l3dst;
    pq.l3dst.applymask (pq.ipv6_mask);
}

void process_packet (u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    PacketQual &pq = *(PacketQual *) args;
    size_t l;

    pq.invalidate();
    pq.packetlen = header->len;

    if (header->len < 16) {
	cerr << "what a small ethernet header ! : len=" << header->len << endl;

	for (l=0 ; (l<header->len) && (l<16) ; l++) {
	    if (isalnum (packet[l]))
		cerr << packet[l];
	    else
		cerr << '.';
	    if (l==7) cerr << ' ';
	}
	cerr << " | " ;
	for (l=0 ; (l<header->len) && (l<16) ; l++) {
	    cerr << setw(2) << setfill ('0') << setbase(16) << (int)packet[l] << " ";
	    if (l==7) cerr << ' ';
	}
	cerr << endl;
	cerr << endl;

// JDJDJD the pq object should be invalidated here ?
	return;
    }
    MacAddr dst ((const ether_addr *) packet);
    MacAddr src ((const ether_addr *) (packet+6));
    
    pq.src = src;
    pq.dst = dst;

    Ethertype etype ((const u_short *) (packet+12));

    pq.ethertype = etype;
    pq.vlan = -1;

    if (debug) cout << src << " -> " << dst << " " << etype << " len=" << header->len;

    if (etype.ethertype == TETHER_IPV4) {
	if (debug) cout << endl;
	process_ipv4 (args, packet+14, header->len -14);
    } else if (etype.ethertype == TETHER_IPV6) {
	if (debug) cout << endl;
	process_ipv6 (args, packet+14, header->len -14);
    } else if (etype.ethertype == TETHER_8021Q) {
	const u_char * p = packet+14;
	u_short vlanid = ((*p & 0xf) << 8) + *(p+1);  // 12 lower bits

	pq.vlan = vlanid;
	if (debug) cout << ", vlanid=" << vlanid << endl;

	Ethertype etype ((const u_short *) (packet+16));
	pq.ethertype = etype;
	if (debug) cout << "   " << etype << endl;

	if (etype.ethertype == TETHER_IPV4) {
	    process_ipv4 (args, packet+18, header->len -18);
	} else if (etype.ethertype == TETHER_IPV6) {
	    process_ipv6 (args, packet+18, header->len -18);
	}
    }

    
    if (pq.src.valid()) {
	nbpacket ++;
	totsize += pq.packetlen;
	Qualifier q (pq.packetlen);

	insert_qualifier (rep_src_macaddr, pq.src, q);
	insert_qualifier (rep_ethertype, pq.ethertype, q);
	insert_qualifier (rep_vlan, VLan(pq.vlan), q);
	if (pq.dst.valid()) {
	    insert_qualifier (rep_dst_macaddr, pq.dst, q);
	    MacPair pair(pq.src, pq.dst);
	    insert_qualifier (rep_pair_macaddr, pair, q);
	}
	if (pq.l3src.valid()) {
	    AS ASsrc = getAS(pq.l3src);
	    insert_qualifier (rep_l3src, pq.l3src, q);
	    insert_qualifier (rep_ASsrc, ASsrc, q);
	    if (pq.l3src.t == TETHER_IPV6)
		insert_qualifier (rep_ip6src, pq.l3src, q);
	    if (pq.l3dst.valid()) {
		AS ASdst = getAS(pq.l3dst);
		insert_qualifier (rep_l3dst, pq.l3dst, q);
		insert_qualifier (rep_ASdst, ASdst, q);
		Level3AddrPair pair(pq.l3src, pq.l3dst);
		insert_qualifier (rep_l3pair, pair, q);
		ASPair aspair (ASsrc, ASdst);
		insert_qualifier (rep_ASpair, aspair, q);
		if (pq.l3dst.t == TETHER_IPV6) {
		    insert_qualifier (rep_ip6dst, pq.l3dst, q);
		    insert_qualifier (rep_ip6pair, pair, q);
		}
	    }
	}
    }

}


void report (ostream &cout) {
    {    dump_desc_nb  ("EtherType", rep_ethertype, cout, Qualifier(nbpacket,totsize)); cout << endl; }
    {    dump_desc_len ("EtherType", rep_ethertype, cout, Qualifier(nbpacket,totsize)); cout << endl; }

    {    dump_desc_nb  ("VLan", rep_vlan, cout, Qualifier(nbpacket,totsize)); cout << endl; }
    {    dump_desc_len ("VLan", rep_vlan, cout, Qualifier(nbpacket,totsize)); cout << endl; }

    if (displayframes) {    dump_desc_nb  ("src mac-address", rep_src_macaddr, cout, Qualifier(nbpacket,totsize), matched, percent_ceil); cout << endl; }
    if (displaysizes)  {    dump_desc_len ("src mac-address", rep_src_macaddr, cout, Qualifier(nbpacket,totsize), matched, percent_ceil); cout << endl; }

    if (displayframes) {    dump_desc_nb  ("dst mac-address", rep_dst_macaddr, cout, Qualifier(nbpacket,totsize), matched, percent_ceil); cout << endl; }
    if (displaysizes)  {    dump_desc_len ("dst mac-address", rep_dst_macaddr, cout, Qualifier(nbpacket,totsize), matched, percent_ceil); cout << endl; }

    if (displayframes) {    dump_desc_nb  ("src/dst mac-addresses", rep_pair_macaddr, cout, Qualifier(nbpacket,totsize), matched, percent_ceil); cout << endl; }
    if (displaysizes)  {    dump_desc_len ("src/dst mac-addresses", rep_pair_macaddr, cout, Qualifier(nbpacket,totsize), matched, percent_ceil); cout << endl; }

    if (displayframes) {    dump_desc_nb  ("src IP address", rep_l3src, cout, Qualifier(nbpacket,totsize), matched, percent_ceil); cout << endl; }
    if (displaysizes)  {    dump_desc_len ("src IP address", rep_l3src, cout, Qualifier(nbpacket,totsize), matched, percent_ceil); cout << endl; }

    if (displayframes) {    dump_desc_nb  ("dst IP adress", rep_l3dst, cout, Qualifier(nbpacket,totsize), matched, percent_ceil); cout << endl; }
    if (displaysizes)  {    dump_desc_len ("dst IP adress", rep_l3dst, cout, Qualifier(nbpacket,totsize), matched, percent_ceil); cout << endl; }

    if (displayframes) {    dump_desc_nb  ("src/dst IP addresses", rep_l3pair, cout, Qualifier(nbpacket,totsize), matched, percent_ceil); cout << endl; }
    if (displaysizes)  {    dump_desc_len ("src/dst IP addresses", rep_l3pair, cout, Qualifier(nbpacket,totsize), matched, percent_ceil); cout << endl; }

    if (!rep_ip6src.empty()) {
	if (displayframes) {    dump_desc_nb  ("src IPv6", rep_ip6src, cout, Qualifier(nbpacket,totsize), matched, percent_ceil); cout << endl; }
	if (displaysizes)  {    dump_desc_len ("src IPv6", rep_ip6src, cout, Qualifier(nbpacket,totsize), matched, percent_ceil); cout << endl; }
    }

    if (!rep_ip6dst.empty()) {
	if (displayframes) {    dump_desc_nb  ("dst IPv6", rep_ip6dst, cout, Qualifier(nbpacket,totsize), matched, percent_ceil); cout << endl; }
	if (displaysizes)  {    dump_desc_len ("dst IPv6", rep_ip6dst, cout, Qualifier(nbpacket,totsize), matched, percent_ceil); cout << endl; }
    }

    if (!rep_ip6pair.empty()) {
	if (displayframes) {    dump_desc_nb  ("src/dst IPv6", rep_ip6pair, cout, Qualifier(nbpacket,totsize), matched, percent_ceil); cout << endl; }
	if (displaysizes)  {    dump_desc_len ("src/dst IPv6", rep_ip6pair, cout, Qualifier(nbpacket,totsize), matched, percent_ceil); cout << endl; }
    }

    if (displayframes) {    dump_desc_nb  ("src AS", rep_ASsrc, cout, Qualifier(nbpacket,totsize), matched, percent_ceil); cout << endl; }
    if (displaysizes)  {    dump_desc_len ("src AS", rep_ASsrc, cout, Qualifier(nbpacket,totsize), matched, percent_ceil); cout << endl; }

    if (displayframes) {    dump_desc_nb  ("dst AS", rep_ASdst, cout, Qualifier(nbpacket,totsize), matched, percent_ceil); cout << endl; }
    if (displaysizes)  {    dump_desc_len ("dst AS", rep_ASdst, cout, Qualifier(nbpacket,totsize), matched, percent_ceil); cout << endl; }

    if (displayframes) {    dump_desc_nb  ("src/dst AS", rep_ASpair, cout, Qualifier(nbpacket,totsize), matched, percent_ceil); cout << endl; }
    if (displaysizes)  {    dump_desc_len ("src/dst AS", rep_ASpair, cout, Qualifier(nbpacket,totsize), matched, percent_ceil); cout << endl; }
}


void usage (ostream &cout, char *cmde0) {
    cout << "usage :  " << cmde0 << " [-h|--help] [[--capture=]filename] [--count=nbpackets]"
	 << "                  [--ceil=xx%] [--sizes] [--frames] [--sizes+frames (default)]" << endl
         << "                  [--mask=(0-32)] [--nomask]" << endl
         << "                  [--ipv4mask=(0-32)] [--ipv6mask=(0-128)]" << endl
         << "                  [--fullview=fname ]" << endl
	 << endl;
}

int main (int nb, char ** cmde) {

    int i;

    string fullviewfname;  //  ("full.bgp.txt");
    list<string> capturefiles;
    string dev;
    long count = 0;

    for (i=1 ; i<nb ; i++) {
	if (cmde[i][0] == '-') {
	    if ((strcmp (cmde[i], "--help") == 0) || (strcmp (cmde[i], "-h") ==0)) {
		usage (cout, cmde[0]);
		return 0;
	    }
	    if (strncmp (cmde[i], "--capture=", 10) == 0) {
		capturefiles.push_back (cmde[i]+10);
	    }
	    if (strncmp (cmde[i], "--count=", 8) == 0) {
		count = atol (cmde[i]+8);
	    }
	    if (strncmp (cmde[i], "--fullview=", 11) == 0) {
		fullviewfname = cmde[i]+11;
	    }
	    if (strcmp (cmde[i], "--sizes") == 0) {
		displaysizes = true;
		displayframes = false;
	    }
	    if (strcmp (cmde[i], "--frames") == 0) {
		displaysizes = false;
		displayframes = true;
	    }
	    if (strcmp (cmde[i], "--sizes+frames") == 0) {
		displaysizes = true;
		displayframes = true;
	    }
	    if (strncmp (cmde[i], "--ceil=", 7) == 0) {
		int p = atoi (cmde[i] + 7);
		if (p > 0)
		    percent_ceil = (double)p/100.0;
		else
		    cerr << "unsuable pecentage : " << p << ", ignored" << endl;
	    }
	    if (strncmp (cmde[i], "--mask=", 7) == 0) {
		int m = atoi (cmde[i] + 7);
		if ((m >= 0) && (m <= 32)) {
		    ipv4_mask = m;
		    ipv6_mask = 2 * m;
		}
	    }
	    if (strncmp (cmde[i], "--ipv4mask=", 11) == 0) {
		int m = atoi (cmde[i] + 11);
		if ((m >= 0) && (m <= 32)) {
		    ipv4_mask = m;
		}
	    }
	    if (strncmp (cmde[i], "--ipv6mask=", 11) == 0) {
		int m = atoi (cmde[i] + 11);
		if ((m >= 0) && (m <= 128)) {
		    ipv6_mask = m;
		}
	    }
	    if (strcmp (cmde[i], "--nomask") == 0) {
		ipv4_mask = 32;
		ipv6_mask = 128;
	    }
	} else {    // attempt to read as a capture file
	    capturefiles.push_back (cmde[i]);
	}
    }

    // JDJDJDJD we should improve this part !!!
    readethernetdesc ("ethernet.desc");


if (false)	// set of basic tests for Prefix maps
{
							cerr << "addr = " << Level3Addr(TETHER_IPV4, "134.214.0.0") << endl;

							Prefix       univ(Level3Addr(TETHER_IPV4, "134.214.0.0"   ), 16),
								     cism(Level3Addr(TETHER_IPV4, "134.214.100.0" ), 22),
								 outerbad(Level3Addr(TETHER_IPV4, "134.214.100.0" ), 21),
								    outer(Level3Addr(TETHER_IPV4, "134.214.96.0"  ), 21),
								    outerin(Level3Addr(TETHER_IPV4, "134.214.96.0"  ), 22);

							view_ipv4.insert(univ,	2200);
							view_ipv4.insert(cism,	2060);
							view_ipv4.insert(outerbad,	2200);
							view_ipv4.insert(outer,	2200);
							view_ipv4.insert(outerin,	43100);

						    cout << "view_ipv4.size = " <<view_ipv4.m.size() << endl;
						    cout << view_ipv4 << endl << endl;

						    {
						    map <Level3Addr, int> m;
						    m[Level3Addr(TETHER_IPV4, "134.214.100.6")] =   1;
						    m[Level3Addr(TETHER_IPV4, "134.214.100.255")] = 2;
						    m[Level3Addr(TETHER_IPV4, "134.214.103.255")] = 3;
						    m[Level3Addr(TETHER_IPV4, "134.214.104.1")] = 4;
						    m[Level3Addr(TETHER_IPV4, "192.168.0.1")] = 5;

						    map <Level3Addr, int>::iterator mi;
						    for (mi=m.begin() ; mi!=m.end() ; mi++) {
							cout << mi->first << " ---- " << mi->second << endl;
						    }
						    }


							view_ipv4.getAS( Level3Addr(TETHER_IPV4, "134.213.0.1"));
							view_ipv4.getAS( Level3Addr(TETHER_IPV4, "134.214.92.2"));
							view_ipv4.getAS( Level3Addr(TETHER_IPV4, "134.214.96.2"));
							view_ipv4.getAS( Level3Addr(TETHER_IPV4, "134.214.100.6"));
							view_ipv4.getAS( Level3Addr(TETHER_IPV4, "134.214.100.255"));
							view_ipv4.getAS( Level3Addr(TETHER_IPV4, "134.214.103.255"));
							view_ipv4.getAS( Level3Addr(TETHER_IPV4, "134.214.104.1"));
							view_ipv4.getAS( Level3Addr(TETHER_IPV4, "192.168.0.1"));

							return 0;
}

    bool full_view_and_co_not_read_yet = true;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    PacketQual pq;

    pq.ipv4_mask = ipv4_mask;
    pq.ipv6_mask = ipv6_mask;

    list<string>::iterator li;

    for (li=capturefiles.begin() ; li!=capturefiles.end() ; li++) {
	string &capturefile = *li;

	//handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	handle = pcap_open_offline (capturefile.c_str(), errbuf);
	if (handle == NULL) {
	    cerr << "Couldn't open capture file \"" << capturefile << "\" : " << errbuf << endl;
	    return(2);
	}
	dev = capturefile;

	if (full_view_and_co_not_read_yet) {
	    if (!fullviewfname.empty()) {
		ifstream fullview (fullviewfname.c_str());
		if (!fullview) {
		    int e = errno;
		    cerr << "could not read full-view file : " << fullviewfname << " : " << strerror (e) << endl;
		}
		else {
		    hash_full_bgp (fullview);
		    view_ipv4.reparent();
		    view_ipv6.reparent();
		}
	    }

	    {	ifstream asnlist("asn.list");
		hash_asnlist (asnlist);
	    }

	    {   Level3Addr m4(TETHER_IPV4, "255.255.255.255");
		Level3Addr m6(TETHER_IPV6, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
		m4.applymask (ipv4_mask);
		m6.applymask (ipv6_mask);

	    cout << "ipv4mask = " << m4 << endl;
	    cout << "ipv6mask = " << m6 << endl << endl ;
	    }

	    full_view_and_co_not_read_yet = false;
	}
	
	if (pcap_datalink(handle) != DLT_EN10MB) {
	    cerr << "Device " << dev << " doesn't provide Ethernet headers - not supported" << endl;
	    return(2);
	}

	bpf_u_int32 net, mask;
	if (pcap_lookupnet(dev.c_str(), &net, &mask, errbuf) == -1) {
	    cerr << "Can't get netmask for device " << dev << endl;
	    net = 0;
	    mask = 0;
	}

	struct bpf_program fp;	/* The compiled filter expression */
	char filter_exp[] = "";
	// char filter_exp[] = "port 23 and host 134.214.100.6"; /* The filter expression */

	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
	    cerr << "Couldn't parse filter " << filter_exp << " : " << pcap_geterr(handle) << endl;
	    return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
	    cerr << "Couldn't parse filter " << filter_exp << " : " << pcap_geterr(handle) << endl;
	    return(2);
	}




	int r = pcap_loop(handle, count, process_packet, (u_char *)&pq);

	cout << endl << "pcap_loop returned : " << r << endl;

	pcap_close (handle);
    }


    report (cout);

    return 0;

}
