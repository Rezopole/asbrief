
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

#include "macaddr.h"

#include "readline.h"

#include "fmtstream.h"


using namespace std;
using namespace stdjd;

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

// --------- Ethertype -------------------------------------------------------------------------------------------------------------------------

typedef enum {
    TETHER_IPV4,
    TETHER_IPV6,
    TETHER_ARP,
    TETHER_8023,
    TETHER_8021Q,
    TETHER_MOPRC,
    TETHER_LLC,
    TETHER_AOE,
    TETHER_UNKNOWN,
    TETHER_OTHER
} TEthertype;

class Ethertype {
  public:
    TEthertype ethertype;
    Ethertype () : ethertype (TETHER_UNKNOWN) {};
    Ethertype (const string &s) {
//cerr << "===================" << s.substr (0,20) << endl;
	     if (s.find ("ethertype IPv4") == 0)		ethertype = TETHER_IPV4;
	else if (s.find ("ethertype IPv6") == 0)		ethertype = TETHER_IPV6;
	else if (s.find ("ethertype ARP") == 0)			ethertype = TETHER_ARP;
	else if (s.find ("802.3") == 0)				ethertype = TETHER_8023;
	else if (s.find ("ethertype 802.1Q") == 0)		ethertype = TETHER_8021Q;
	else if (s.find ("LLC") == 0)				ethertype = TETHER_LLC;
	else if (s.find ("ethertype MOP RC") == 0)		ethertype = TETHER_MOPRC;
	else if (s.find ("ethertype AoE") == 0)			ethertype = TETHER_AOE;
	else if (s.find ("ethertype Unknown ") == 0)		ethertype = TETHER_UNKNOWN;
	else							ethertype = TETHER_OTHER;
    }
    Ethertype (const Ethertype &o) : ethertype(o.ethertype) {}
    bool operator< (const Ethertype &a) const {
	return ethertype < a.ethertype;
    }
};
ostream &operator<< (ostream &out, const Ethertype &p) {
    switch (p.ethertype) {
	case TETHER_IPV4:    return out << "IPv4";
	case TETHER_IPV6:    return out << "IPv6";
	case TETHER_ARP:     return out << "ARP";
	case TETHER_8023:    return out << "803.3";
	case TETHER_MOPRC:   return out << "MOP RC";
	case TETHER_AOE:     return out << "AoE";
	case TETHER_8021Q:   return out << "802.1q";
	case TETHER_UNKNOWN: return out << "Unknown";
	case TETHER_OTHER:   return out << "Other";
	default:             return out << "Other";
    }
}

// --------- Level3Addr ------------------------------------------------------------------------------------------------------------------------

class Level3Addr;
ostream &operator<< (ostream &out, const Level3Addr &a);
Level3Addr l3mask (int nb);

class Level3Addr {
  private:
    static Level3Addr mask[128];
    static bool mask_not_initialized;

  public:
    TEthertype t;
    unsigned char b[16];

    bool valid (void) const {
	return ((t == TETHER_IPV4) || (t == TETHER_IPV6));
    }

    Level3Addr (void)  : t(TETHER_UNKNOWN) {
	size_t i;
	for (i=0 ; i<16 ; i++) b[i] = 0;
    }

    void applymask (Level3Addr const &mask) {
	size_t i;
	for (i=0 ; i<16 ; i++) b[i] &= mask.b[i];
    }

    inline void init_mask (void) {
	if (mask_not_initialized) {
	    size_t i;
	    for (i=0 ; i<128 ; i++) {
		mask[i] = l3mask(i);
	    }
	    mask_not_initialized = false;
	}
    }

    void applymask (int masklen) {
	init_mask();
	if (masklen < 0) masklen = 0;
	if (masklen >=128) return;
	applymask (mask[masklen]);
    }

    Level3Addr (TEthertype proposed_type, string const &s) : t(TETHER_UNKNOWN) {
	size_t p, i;
	switch (proposed_type) {
	  case TETHER_IPV4:
	    b[0] = atoi (s.c_str());
	    p = s.find('.');
	    if (p!=string::npos) {
		b[1] = atoi (s.substr(p+1).c_str());
		p = s.find('.', p+1);
		if (p!=string::npos) {
		    b[2] = atoi (s.substr(p+1).c_str());
		    p = s.find('.', p+1);
		    if (p!=string::npos) {
			b[3] = atoi (s.substr(p+1).c_str());
			t = TETHER_IPV4;
		    }
		}
	    }
	    for (i=4 ; i<16 ; i++) b[i] = 0;	// we pad with zeros for comparisons
	    break;

	  case TETHER_IPV6:
	    p = s.find_first_not_of ("0123456789abcdefABCDEF:");
	    if (p == string::npos) {
		if (inet_pton(AF_INET6, s.c_str(), &(b[0])) == 1)
		    t = TETHER_IPV6;
	    } else {
		if (inet_pton(AF_INET6, s.substr(0,p).c_str(), &(b[0])) == 1)
		    t = TETHER_IPV6;
	    }
	    break;

	  default:
	    for (i=0 ; i<16 ; i++) b[i] = 0;
	    t = TETHER_UNKNOWN;
	}
    }

    Level3Addr (Level3Addr const &r) : t(r.t) {
	size_t i;
	for (i=0 ; i<16 ; i++) b[i] = r.b[i];
    }
    bool operator< (const Level3Addr &a) const {
	if (t < a.t) {
	    return true;
	} else if (a.t < t) {
	    return false;
	} else {	// we have equal types
	    size_t i;
	    for (i=0 ; i<16 ; i++) {
		if (b[i] < a.b[i]) {
		    return true;
		} else if (a.b[i] < b[i]) {
		    return false;
		}
	    }
	}
	return false;	// we should get there only if a == *this
    }

    bool operator== (const Level3Addr &a) const {
	if (t != a.t) {
	    return false;
	}
	// we have equal types
	size_t i;
	for (i=0 ; i<16 ; i++) {
	    if (b[i] != a.b[i]) {
		return false;
	    }
	}
	return true;	// we should get there only if a == *this
    }

};

bool Level3Addr::mask_not_initialized = true;
Level3Addr Level3Addr::mask[128];

ostream &operator<< (ostream &out, const Level3Addr &a) {
    stringstream s;
    switch (a.t) {
      case TETHER_IPV4:
	s << (unsigned int)a.b[0] << '.' << (unsigned int)a.b[1] << '.' << (unsigned int)a.b[2] << '.' << (unsigned int)a.b[3];
	return out << s.str();
	break;
      case TETHER_IPV6:
	char str[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &(a.b[0]), str, INET6_ADDRSTRLEN);
	return out << str;
	break;
      default:
	return out << "invalidL3addr";
	break;
    }
}

Level3Addr l3mask (int nb) {
    Level3Addr mask;
    mask.t = TETHER_IPV6;

    int bit = 0;

    for (bit=0 ; bit<128 ; bit++) {
	size_t i = bit / 8;
	size_t n = 7-(bit % 8);

	if (bit < nb) {	// we set one bit to 1
	    mask.b[i] |= (1 << n);
	} else {	// we set one bit to 0
	    mask.b[i] &= ~(1 << n);
	}
    }
    return mask;
}

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
    out << '[';
    matcher (p.src, out);
    out << " ";
    matcher (p.dst, out);
    out << ']';
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

// --------- desc_[nb/len] Templates for map<T,Qualifier> types --------------------------------------------------------------------------------

template <typename T> void matcher (const T &a, ostream &out) {
    out << a ;
}

template <typename T> bool desc_comparator_nb (typename map <T, Qualifier>::const_iterator mi1, typename map <T, Qualifier>::const_iterator mi2) {
    return mi1->second.nb > mi2->second.nb;
}


template <typename T> void dump_desc_nb (const string & tname, map <T, Qualifier> const &m, ostream &cout, Qualifier total, bool matched=false, double ceil=1.0) {
    cout << tname << " repartition : " << m.size() << " " << tname << ", spread over " << total.nb << " packets" << endl;
    //cout << m.size() << " entries" << ", total: " << total.nb << " packets" << endl;
    if ((m.size() ==0) || (total.nb==0))
	return;


    list <typename map <T, Qualifier>::const_iterator> l;
    typename map <T, Qualifier>::const_iterator mi;
    for (mi=m.begin() ; mi!=m.end() ; mi++)
	l.push_back (mi);

    l.sort (desc_comparator_nb<T>);

//    int maxw = (int)(log2((*(l.begin()))->second.nb) / log2(10)) + 1;
//    int nw = (int)(log2(l.size()) / log2(10)) + 1;
    size_t n = 0;
    size_t curtot = 0;
    typename list <typename map <T, Qualifier>::const_iterator>::const_iterator li;

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
	     << (100*(*li)->second.nb)/total.nb << "%\t+"
	     << (100*curtot)/total.nb << "%\t+";
	tabul.push_back (buf.str());
	if ((double)curtot/(double)total.nb > ceil) break;
    }
    tabul.flush();
}

template <typename T> bool desc_comparator_len (typename map <T, Qualifier>::const_iterator mi1, typename map <T, Qualifier>::const_iterator mi2) {
    return mi1->second.len > mi2->second.len;
}


template <typename T> void dump_desc_len (const string & tname, map <T, Qualifier> const &m, ostream &cout, Qualifier total, bool matched=false, double ceil=1.0) {
    cout << tname << " repartition : " << m.size() << " " << tname << ", spread over " << total.len << " bytes" << endl;
    // cout << m.size() << " entries" << ", total: " << total.len << " bytes" << endl;
    if ((m.size() ==0) || (total.len==0))
	return;


    list <typename map <T, Qualifier>::const_iterator> l;
    typename map <T, Qualifier>::const_iterator mi;
    for (mi=m.begin() ; mi!=m.end() ; mi++)
	l.push_back (mi);

    l.sort (desc_comparator_len<T>);

//    int maxw = (int)(log2((*(l.begin()))->second.len) / log2(10)) + 1;
//    int nw = (int)(log2(l.size()) / log2(10)) + 1;
    size_t n = 0;
    size_t curtot = 0;
    typename list <typename map <T, Qualifier>::const_iterator>::const_iterator li;

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
//	     << setw(3)    << (100*(*li)->second.len)/total.len << "% "
//	     << setw(3)    << (100*curtot)/total.len << "%"
//	     << endl;
	buf << (*li)->second.len << "\t+"
	     << (100*(*li)->second.len)/total.len << "%\t+"
	     << (100*curtot)/total.len << "%\t+";
	tabul.push_back (buf.str());
	if ((double)curtot/(double)total.len > ceil) break;
    }
    tabul.flush();
}

// --------- insert_qualifier templates --------------------------------------------------------------------------------------------------------

template <typename T> void insert_qualifier (map <T, Qualifier> &m, T const &key, Qualifier q) {
    typename map <T, Qualifier>::iterator mi = m.find (key);
    if (mi != m.end())
	mi->second += q;
    else
	m[key] = q;
}

// --------- hash full view --------------------------------------------------------------------------------------------------------------------


class Prefix {
  public:
    Level3Addr a;   // start address
    int ml;	    // mask len, -1 == invalid prefix

    Prefix (void) : a(), ml(-1) {}

    Prefix (Prefix const & pr) : a(pr.a), ml(pr.ml) {}

    inline TEthertype gettype (void) { return a.t; }

    Prefix (Level3Addr prop_a, int prop_ml, bool lousycreation = false) : a(), ml(-1) {
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
    map <Prefix, size_t> m;
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
	map <Prefix, size_t>::iterator mi = m.upper_bound (tofind);
	if (mi!=m.begin())
	    mi --;
////////	if (mi == m.end()) { // this should not occur since we've pushed an initial all-match-prefix
////////	    cerr << "HashedPrefixes::insert : \"Houston, we have a problem !\" : no upper bound found pr=" << a << " as prefix " << tofind << endl;
////////	    return -1;
////////	}
//	if (mi->first == pr) { // we've got a duplicate ?? 
//	    cerr << "HashedPrefixes::insert : duplicate prefix : " << pr << endl;
//	    return;
//	}
//cerr << "   getAS(" << a << ") = " << mi->first << " = " << mi->second << endl;
	return mi->second;
    }
};
ostream & operator<< (ostream &out, const HashedPrefixes &h) {
    map <Prefix, size_t>::const_iterator mi;
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
		    if ((q != string::npos) && (s[q] == '/')) {	// it looks like an IPv4 prefix ...
			int masklen = atoi (s.substr (q+1).c_str());
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

// ---------------------------------------------------------------------------------------------------------------------------------------------


map <MacAddr, Qualifier> rep_src_macaddr;
map <MacAddr, Qualifier> rep_dst_macaddr;
map <MacPair, Qualifier> rep_pair_macaddr;

map <Level3Addr, Qualifier> rep_l3src;
map <Level3Addr, Qualifier> rep_l3dst;
map <Level3AddrPair, Qualifier> rep_l3pair;

map <Level3Addr, Qualifier> rep_ip6src;
map <Level3Addr, Qualifier> rep_ip6dst;
map <Level3AddrPair, Qualifier> rep_ip6pair;

map <AS, Qualifier> rep_ASsrc;
map <AS, Qualifier> rep_ASdst;
map <ASPair, Qualifier> rep_ASpair;

map <Ethertype, Qualifier> rep_ethertype;

size_t totsize = 0;
size_t nbpacket = 0;

int ipv4_mask = 24;
int ipv6_mask = ipv4_mask*2;

bool displaysizes = true;
bool displayframes = true;
double percent_ceil = 0.9;
bool matched = true;

typedef enum {
    SEEK_NEXT_PACKET,
    SEEK_FIRST_IPV4,
} Treadtextstate;

int capstat (istream &cin, ostream &cout) {

    Level3Addr ipv4mask = l3mask (ipv4_mask);
    Level3Addr ipv6mask = l3mask (ipv6_mask);
cout << "ipv4mask = " << ipv4mask << endl;
cout << "ipv6mask = " << ipv6mask << endl << endl ;
    size_t lno = 0;
    Treadtextstate state = SEEK_NEXT_PACKET;
    while (cin) {
	MacAddr src, dst;
	Level3Addr l3src, l3dst;
	Ethertype ethertype;
	long packetlen = 0;

	do {
	    string s;
	    lno++; readline (cin, s);
	    size_t p, q;
	    int vlan = -1;

	    switch (state) {
	      case SEEK_NEXT_PACKET:
		if (isdigit(s[0])) {    // the line must start with a time-stamp
		    p = s.find(' ');
		    if (p != string::npos) {
			src = MacAddr (s.substr(p+1));
			if (src.invalid()) cerr << "   ligne : " << lno << endl;
			p = s.find (" > ", p+1);
			if (p != string::npos) {
			    dst = MacAddr (s.substr(p+3));
			    if (dst.invalid()) cerr << "   ligne : " << lno << endl;
			    p = s.find (", ", p+3);
			    if (p != string::npos) {
				ethertype = Ethertype (s.substr (p+2));
				p = s.find (", length ", p+2);
				if (p != string::npos) {
				    packetlen = atol (s.substr(p+9, 10).c_str());

								if (ethertype.ethertype == TETHER_IPV6) {
								    p = seek_ending_parenthesis (s, p+9);
								    l3src = Level3Addr(TETHER_IPV6, s.substr (p+1));
								    l3src.applymask (ipv6mask);
								    p = s.find (" > ", p);
								    if (p != string::npos) {
									l3dst = Level3Addr(TETHER_IPV6, s.substr (p+3));
									l3dst.applymask (ipv6mask);
								    }

				    } else if (ethertype.ethertype == TETHER_8021Q) {
					q = s.find (": vlan ", p+9);
					if (q != string::npos) {
					    p = q;
					    vlan = atoi (s.substr(p+7).c_str());
					    p = s.find (", ", p+7);
					    if (p != string::npos) {
						p = s.find (", ", p+2);
						ethertype = Ethertype (s.substr (p+2));

								if (ethertype.ethertype == TETHER_IPV6) {
								    p = seek_ending_parenthesis (s, p+9);
//cerr << "   lala   ==" << s.substr (p+1) << endl;
								    l3src = Level3Addr(TETHER_IPV6, s.substr (p+1));
								    l3src.applymask (ipv6mask);
								    p = s.find (" > ", p);
								    if (p != string::npos) {
									l3dst = Level3Addr(TETHER_IPV6, s.substr (p+3));
									l3dst.applymask (ipv6mask);
								    }
								}

					    }
					} else {
					    vlan = 0;
					}
				    }
				}
			    }
			}
		    }
		}
		if (ethertype.ethertype == TETHER_IPV4)
		    state = SEEK_FIRST_IPV4;
		break;

	      case SEEK_FIRST_IPV4:
		if (isdigit(s[0])) {
		    state = SEEK_NEXT_PACKET;
		    break;
		}
		p = s.find_first_not_of (' ');
		if (p != string::npos) {
		    l3src = Level3Addr(TETHER_IPV4, s.substr (p));
//		    l3src.applymask (ipv4mask);
l3src.applymask (ipv4_mask);
		    p = s.find (" > ", p);
		    if (p != string::npos) {
			l3dst = Level3Addr(TETHER_IPV4, s.substr (p+3));
//			l3dst.applymask (ipv4mask);
l3dst.applymask (ipv4_mask);
		    }
		}

		state = SEEK_NEXT_PACKET;
		break;
	    }
	} while (cin && (state != SEEK_NEXT_PACKET));

	if (src.valid()) {
	    nbpacket ++;
	    totsize += packetlen;
	    Qualifier q (packetlen);

	    insert_qualifier (rep_src_macaddr, src, q);
	    if (dst.valid()) {
		insert_qualifier (rep_dst_macaddr, dst, q);
		MacPair pair(src, dst);
		insert_qualifier (rep_pair_macaddr, pair, q);
		insert_qualifier (rep_ethertype, ethertype, q);
	    }
	    if (l3src.valid()) {
		AS ASsrc = getAS(l3src);
		insert_qualifier (rep_l3src, l3src, q);
		insert_qualifier (rep_ASsrc, ASsrc, q);
		if (l3src.t == TETHER_IPV6)
		    insert_qualifier (rep_ip6src, l3src, q);
		if (l3dst.valid()) {
		    AS ASdst = getAS(l3dst);
		    insert_qualifier (rep_l3dst, l3dst, q);
		    insert_qualifier (rep_ASdst, ASdst, q);
		    Level3AddrPair pair(l3src, l3dst);
		    insert_qualifier (rep_l3pair, pair, q);
		    ASPair aspair (ASsrc, ASdst);
		    insert_qualifier (rep_ASpair, aspair, q);
		    if (l3dst.t == TETHER_IPV6) {
			insert_qualifier (rep_ip6dst, l3dst, q);
			insert_qualifier (rep_ip6pair, pair, q);
		    }
		}
	    }
	}
    }

    {    dump_desc_nb  ("EtherType", rep_ethertype, cout, Qualifier(nbpacket,totsize)); cout << endl; }
    {    dump_desc_len ("EtherType", rep_ethertype, cout, Qualifier(nbpacket,totsize)); cout << endl; }

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


//    cout << "nb packet = " << nbpacket << endl;
//    cout << "nb src mac = " << rep_src_macaddr.size() << endl;
//    cout << "nb dst mac = " << rep_dst_macaddr.size() << endl;
//    cout << "nb pair mac = " << rep_pair_macaddr.size() << endl;
    cout << "tcpdump line read : " << lno << endl;
    return 0;
}


void usage (ostream &cout, char *cmde0) {
    cout << "usage :  " << cmde0 << " [-h|--help] [--ceil=xx%] [--sizes] [--frames] [--sizes+frames (default)]" << endl
         << "                  [--mask=(0-32)] [--nomask]" << endl
         << "                  [--ipv4mask=(0-32)] [--ipv6mask=(0-128)]" << endl
         << "                  [--fullview=fname ]" << endl
	 << endl;
}

int main (int nb, char ** cmde) {

    int i;

    string fullviewfname;  //  ("full.bgp.txt");

    for (i=1 ; i<nb ; i++) {
	if (cmde[i][0] == '-') {
	    if ((strcmp (cmde[i], "--help") == 0) || (strcmp (cmde[i], "-h") ==0)) {
		usage (cout, cmde[0]);
		return 0;
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

    if (!fullviewfname.empty()) {
	ifstream fullview (fullviewfname.c_str());
	if (!fullview) {
	    int e = errno;
	    cerr << "could not read full-view file : " << fullviewfname << " : " << strerror (e) << endl;
	}
	else
	    hash_full_bgp (fullview);
    }

    {	ifstream asnlist("asn.list");
	hash_asnlist (asnlist);
    }

    return capstat (cin, cout);

    return 0;

}
