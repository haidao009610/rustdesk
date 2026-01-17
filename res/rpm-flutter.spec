Name:       nccdesk
Version:    1.4.5
Release:    0
Summary:    RPM package
License:    GPL-3.0
URL:        https://nccdesk.com
Vendor:     nccdesk <info@nccdesk.com>
Requires:   gtk3 libxcb libxdo libXfixes alsa-lib libva pam gstreamer1-plugins-base
Recommends: libayatana-appindicator-gtk3
Provides:   libdesktop_drop_plugin.so()(64bit), libdesktop_multi_window_plugin.so()(64bit), libfile_selector_linux_plugin.so()(64bit), libflutter_custom_cursor_plugin.so()(64bit), libflutter_linux_gtk.so()(64bit), libscreen_retriever_plugin.so()(64bit), libtray_manager_plugin.so()(64bit), liburl_launcher_linux_plugin.so()(64bit), libwindow_manager_plugin.so()(64bit), libwindow_size_plugin.so()(64bit), libtexture_rgba_renderer_plugin.so()(64bit)

# https://docs.fedoraproject.org/en-US/packaging-guidelines/Scriptlets/

%description
The best open-source remote desktop client software, written in Rust.

%prep
# we have no source, so nothing here

%build
# we have no source, so nothing here

# %global __python %{__python3}

%install

mkdir -p "%{buildroot}/usr/share/nccdesk" && cp -r ${HBB}/flutter/build/linux/x64/release/bundle/* -t "%{buildroot}/usr/share/nccdesk"
mkdir -p "%{buildroot}/usr/bin"
install -Dm 644 $HBB/res/nccdesk.service -t "%{buildroot}/usr/share/nccdesk/files"
install -Dm 644 $HBB/res/nccdesk.desktop -t "%{buildroot}/usr/share/nccdesk/files"
install -Dm 644 $HBB/res/nccdesk-link.desktop -t "%{buildroot}/usr/share/nccdesk/files"
install -Dm 644 $HBB/res/128x128@2x.png "%{buildroot}/usr/share/icons/hicolor/256x256/apps/nccdesk.png"
install -Dm 644 $HBB/res/scalable.svg "%{buildroot}/usr/share/icons/hicolor/scalable/apps/nccdesk.svg"

%files
/usr/share/nccdesk/*
/usr/share/nccdesk/files/nccdesk.service
/usr/share/icons/hicolor/256x256/apps/nccdesk.png
/usr/share/icons/hicolor/scalable/apps/nccdesk.svg
/usr/share/nccdesk/files/nccdesk.desktop
/usr/share/nccdesk/files/nccdesk-link.desktop

%changelog
# let's skip this for now

%pre
# can do something for centos7
case "$1" in
  1)
    # for install
  ;;
  2)
    # for upgrade
    systemctl stop nccdesk || true
  ;;
esac

%post
cp /usr/share/nccdesk/files/nccdesk.service /etc/systemd/system/nccdesk.service
cp /usr/share/nccdesk/files/nccdesk.desktop /usr/share/applications/
cp /usr/share/nccdesk/files/nccdesk-link.desktop /usr/share/applications/
ln -sf /usr/share/nccdesk/nccdesk /usr/bin/nccdesk
systemctl daemon-reload
systemctl enable nccdesk
systemctl start nccdesk
update-desktop-database

%preun
case "$1" in
  0)
    # for uninstall
    systemctl stop nccdesk || true
    systemctl disable nccdesk || true
    rm /etc/systemd/system/nccdesk.service || true
  ;;
  1)
    # for upgrade
  ;;
esac

%postun
case "$1" in
  0)
    # for uninstall
    rm /usr/bin/nccdesk || true
    rmdir /usr/lib/nccdesk || true
    rmdir /usr/local/nccdesk || true
    rmdir /usr/share/nccdesk || true
    rm /usr/share/applications/nccdesk.desktop || true
    rm /usr/share/applications/nccdesk-link.desktop || true
    update-desktop-database
  ;;
  1)
    # for upgrade
    rmdir /usr/lib/nccdesk || true
    rmdir /usr/local/nccdesk || true
  ;;
esac
