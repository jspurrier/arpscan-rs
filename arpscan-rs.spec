```plain
Name:           arpscan-rs
Version:        0.1.0
Release:        1%{?dist}
Summary:        A Rust-based ARP scanning tool for network discovery

License:        MIT
URL:            https://github.com/yourusername/arpscan-rs
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  cargo
BuildRequires:  rust
BuildRequires:  gcc
BuildRequires:  libpcap-devel
Requires:       libpcap

%description
arpscan-rs is a command-line tool written in Rust for performing ARP scans to discover devices on a network. It identifies IP addresses, MAC addresses, and manufacturers based on OUI data.

%prep
%autosetup -n %{name}-%{version}

%build
cargo build --release

%install
install -D -m 0755 target/release/arpscan-rs %{buildroot}%{_bindir}/arpscan-rs
install -D -m 0644 src/files/oui.txt %{buildroot}%{_datadir}/arpscan-rs/oui.txt

%files
%{_bindir}/arpscan-rs
%{_datadir}/arpscan-rs/oui.txt
%doc README.md
%license LICENSE

%changelog
* Mon Apr 14 2025 Your Name <your.email@example.com> - 0.1.0-1
- Initial package release
```
