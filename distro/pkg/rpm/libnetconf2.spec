Name: libnetconf2
Version: {{ version }}
Release: {{ release }}%{?dist}
Summary: NETCONF protocol library
Url: https://github.com/CESNET/libnetconf2
Source: libnetconf2-%{version}.tar.gz
License: BSD-3-Clause

BuildRequires:  cmake
BuildRequires:  make
BuildRequires:  gcc
BuildRequires:  libssh-devel
BuildRequires:  libyang2-devel
BuildRequires:  openssl-devel

%package -n libnetconf2-devel
Summary:    Headers of libnetconf2 library
Conflicts:  libnetconf-devel
Requires:   %{name} = %{version}-%{release}

%description -n libnetconf2-devel
Headers of libnetconf library.

%description
libnetconf2 is a NETCONF library in C intended for building NETCONF clients and
servers. NETCONF is the NETwork CONFiguration protocol introduced by IETF.


%prep
%setup -n libnetconf2-%{version}
mkdir build

%build
cd build
cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr \
    -DCMAKE_BUILD_TYPE:String="Release" \
    -DCMAKE_C_FLAGS="${RPM_OPT_FLAGS}" \
    -DCMAKE_CXX_FLAGS="${RPM_OPT_FLAGS}" \
    ..
make

%install
cd build
make DESTDIR=%{buildroot} install

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig


%files
%defattr(-,root,root)
%{_libdir}/libnetconf2.so.2*

%files -n libnetconf2-devel
%defattr(-,root,root)
%{_libdir}/libnetconf2.so
%{_libdir}/pkgconfig/libnetconf2.pc
%{_includedir}/*.h
%{_includedir}/libnetconf2/*.h
%dir %{_includedir}/libnetconf2/


%changelog
* Fri Jul 09 2021 Jakub Ružička <jakub.ruzicka@nic.cz> - {{ version }}-{{ release }}
- upstream package
