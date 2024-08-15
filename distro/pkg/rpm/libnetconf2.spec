Name: libnetconf2
Version: {{ version }}
Release: {{ release }}%{?dist}
Summary: NETCONF protocol library
Url: https://github.com/CESNET/libnetconf2
Source: %{url}/archive/v%{version}/%{name}-%{version}.tar.gz
License: BSD

BuildRequires:  cmake
BuildRequires:  gcc
BuildRequires:  libssh-devel
BuildRequires:  openssl-devel
BuildRequires:  pam-devel
BuildRequires:  pkgconfig(libyang) >= 2
BuildRequires: 	libcurl-devel

%package devel
Summary:    Headers of libnetconf2 library
Conflicts:  libnetconf-devel
Requires:   %{name}%{?_isa} = %{version}-%{release}
Requires:   pkgconfig

%description devel
Headers of libnetconf library.

%description
libnetconf2 is a NETCONF library in C intended for building NETCONF clients and
servers. NETCONF is the NETwork CONFiguration protocol introduced by IETF.


%prep
%autosetup -p1

%build
%cmake -DCMAKE_BUILD_TYPE=RELWITHDEBINFO -DENABLE_TESTS=OFF
%cmake_build

%install
%cmake_install


%files
%license LICENSE
%doc README.md FAQ.md
%{_libdir}/libnetconf2.so.*
%{_datadir}/yang/modules/libnetconf2/*.yang
%dir %{_datadir}/yang/modules/libnetconf2/

%files devel
%doc CODINGSTYLE.md
%{_libdir}/libnetconf2.so
%{_libdir}/pkgconfig/libnetconf2.pc
%{_includedir}/*.h
%{_includedir}/libnetconf2/*.h
%dir %{_includedir}/libnetconf2/


%changelog
* {{ now }} Jakub Ružička <jakub.ruzicka@nic.cz> - {{ version }}-{{ release }}
- upstream package
