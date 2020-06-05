dnl {
dnl
dnl  asbrief, renders a set of useful per-prefix, per-AS, etc, cross-repartitions. and more ....
dnl  Copyright (C) 20162020 Jean-Daniel Pauget <jdpauget@rezopole.net>
dnl  
dnl  This program is free software; you can redistribute it and/or
dnl  modify it under the terms of the GNU General Public License
dnl  as published by the Free Software Foundation; either version 2
dnl  of the License, or (at your option) any later version.
dnl  
dnl  This program is distributed in the hope that it will be useful,
dnl  but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl  GNU General Public License for more details.
dnl  
dnl  You should have received a copy of the GNU General Public License
dnl  along with this program; if not, write to the Free Software
dnl  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
dnl
dnl }

dnl Process this file with autoconf to produce a configure script.
AC_INIT([asbrief], [0.0.80], [sysadm@rezopole.net])
AC_CONFIG_SRCDIR([./asbrief.cpp])


dnl Detect the canonical host and target build environment
AC_CANONICAL_HOST
AC_CANONICAL_TARGET


dnl quieten some complains from missing files
AM_INIT_AUTOMAKE([foreign])

dnl the magic of additionnal local m4 ?
AC_CONFIG_MACRO_DIR([m4])

dnl autoheader
AM_CONFIG_HEADER(config.h)
AC_DEFINE_UNQUOTED([ASBRIEF_VERSION], ["$VERSION"], [the release-version of asbrief])
AC_SUBST(ASBRIEF_VERSION,[$VERSION])

dnl Check for tools

AC_PROG_CC
AC_PROG_CXX
AC_LIBTOOL_WIN32_DLL
AM_PROG_LIBTOOL

dnl Check for compiler environment

AC_C_CONST

dnl JD's standard minimum CFLAG
CFLAGS="$CFLAGS -O2 -Wall -Wcast-qual -Wwrite-strings -Wstrict-prototypes -Wmissing-prototypes"
CXXFLAGS="$CXXFLAGS -O2 -Wall -Woverloaded-virtual -Wcast-qual -Wwrite-strings -Wredundant-decls"

dnl how to dns resolv in regard with target-system's flavor
dnl DISCLAIMER : this part hasn't been thoroughly tested, please feel free to contribute !
case "$target" in
    *-freebsd* | *-netbsd* | *-openbsd*)
	RESOLV_CXXFLAGS="-I/usr/local/include/bind"
	RESOLV_LDFLAGS="-L/usr/local/lib/libbind -lbind"
	;;
    *)
	RESOLV_CXXFLAGS=""
	RESOLV_LDFLAGS="-lresolv"
	;;
esac
AC_SUBST(RESOLV_CXXFLAGS)
AC_SUBST(RESOLV_LDFLAGS)


dnl check for mac-osX gcc stl variant
case "$target" in
    *-apple-darwin*)
	dnl some older darwin wanted that .... CXXFLAGS="$CXXFLAGS -stdlib=libstdc++"
	CXXFLAGS="$CXXFLAGS-std=libc++"
	AC_MSG_RESULT([stdlib variant : -stdlib=libstdc++])
	;;
    *)
	:
	;;
esac

dnl check for pcap include and lib
AC_MSG_CHECKING(for libpcap)
have_libpcap=no
SAVECXXFLAGS="$CXXFLAGS"
CXXFLAGS="$INCPATH $SAVECXXFLAGS"
AC_LANG(C++)
if test x$have_libpcap = xno; then
    if test "${prefix}" = "NONE"  ; then
        TESTPREFIX="/usr/local"
    else
        TESTPREFIX="${prefix}"
    fi
    for P_INC in "${TESTPREFIX}" /usr/local /usr
    do
        if test x$have_libpcap = xno; then
            echo -n "  ($P_INC :"
            CXXFLAGS="$INCPATH -I$P_INC/include $SAVECXXFLAGS"
            AC_TRY_COMPILE([
#include <pcap.h>
void testpcap (void) {
    pcap_t *handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_offline ("arbitrary_file.pcap", errbuf);
    if (handle == NULL)
	return;
}
            ],[
            ],[
            have_libpcap=yes
            ])
            if test x$have_libpcap = xyes; then
                INCPATH="$INCPATH -I$P_INC/include"
                if test "x$libpasbriefic" = "xyes"; then
                    LIBPCAPLDFLAGS=""
                    LIBPCAPLDLIB="${P_INC}/lib/libpcap.a"
                else
                    LIBPCAPLDFLAGS="-L${P_INC}/lib -lpcap"
                    LIBPCAPLDLIB=""
                fi

                echo -n " yes.)"
            else
                echo -n " no.)"
            fi
        fi
    done
    echo -n " : "
fi
CXXFLAGS="$SAVECXXFLAGS"
AC_MSG_RESULT($have_libpcap)
if test x$have_libpcap = xyes; then
    :
else
    AC_MSG_ERROR(Unable to find libpcap headers)
fi
AC_SUBST(LIBPCAPLDFLAGS)
AC_SUBST(LIBPCAPLDLIB)
dnl end of check for libpcap --------------------------------------------------


dnl  dnl concatenation of include dirs
CFLAGS="$INCPATH $CFLAGS"
CXXFLAGS="$INCPATH $CXXFLAGS"

dnl Finally create all the generated files
AC_OUTPUT([
	Makefile
	asbrief.1
])


