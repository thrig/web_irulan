Name:		irulan-client
Version:	1.0
Release:	6%{?dist}
Summary:	automation for SSH host key management
Group:		Applications/System
License:	BSD
URL:		https://github.com/thrig/web_irulan
Source0:	irulan-upload
Requires:	curl
Requires:	util-linux
BuildArch:      noarch

%description
automation for SSH host key management

%prep
%setup -T -n irulan-client -c

%install
rm -rf $RPM_BUILD_ROOT
install -Dpm 750 %{SOURCE0} $RPM_BUILD_ROOT%{_sbindir}/irulan-upload

# usually this works out at kickstart time. keep trying if not
%post
/usr/sbin/irulan-upload || echo "@reboot root /usr/sbin/irulan-upload" > /etc/cron.d/irulan-upload

%postun
rm -rf /etc/irulan
rm -f /etc/cron.d/irulan-upload

%files
%{_sbindir}/irulan-upload

%changelog
* Fri Aug 09 2019 Jeremy Mates <jeremy.mates@gmail.com> r6
- drag out of the spec file repository at $work and cleanup
