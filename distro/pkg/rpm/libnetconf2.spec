Name: libnetconf2
Version: {{ version }}
Release: {{ release }}%{?dist}
Summary: NETCONF protocol library
Url: https://github.com/CESNET/libnetconf2
Source: libnetconf2-%{version}.tar.gz
License: BSD

BuildRequires:  cmake
BuildRequires:  make
BuildRequires:  gcc
BuildRequires:  libssh-devel
BuildRequires:  openssl-devel
BuildRequires:  pkgconfig(libyang) >= 2

%package devel
Summary:    Headers of libnetconf2 library
Conflicts:  libnetconf-devel
Requires:   %{name}%{?_isa} = %{version}-%{release}

%description devel
Headers of libnetconf library.

%description
libnetconf2 is a NETCONF library in C intended for building NETCONF clients and
servers. NETCONF is the NETwork CONFiguration protocol introduced by IETF.


%prep
%autosetup -p1
mkdir build

%build
cd build
cmake \
    -DCMAKE_INSTALL_PREFIX:PATH=%{_prefix} \
    -DCMAKE_BUILD_TYPE:String="Release" \
    -DCMAKE_C_FLAGS="${RPM_OPT_FLAGS}" \
    -DCMAKE_CXX_FLAGS="${RPM_OPT_FLAGS}" \
    ..
make

%install
cd build
make DESTDIR=%{buildroot} install

%files
%license LICENSE
%{_libdir}/libnetconf2.so.*

%files devel
%{_libdir}/libnetconf2.so
%{_libdir}/pkgconfig/libnetconf2.pc
%{_includedir}/*.h
%{_includedir}/libnetconf2/*.h
%dir %{_includedir}/libnetconf2/


%changelog
* Tue Oct 12 2021 Jakub Ružička <jakub.ruzicka@nic.cz> - {{ version }}-{{ release }}
- upstream package
