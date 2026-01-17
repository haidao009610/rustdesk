Name:       nccdesk
Version:    1.4.5
Release:    0
Summary:    RPM package
License:    GPL-3.0
URL:        https://rustdesk.com
Vendor:     nccdesk <info@rustdesk.com>
Requires:   gtk3 libxcb1 xdotool libXfixes3 alsa-utils libXtst6 libva2 pam gstreamer-plugins-base gstreamer-plugin-pipewire
Recommends: libayatana-appindicator3-1
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
install -Dm 644 $HBB/res/rustdesk.service -t "%{buildroot}/usr/share/nccdesk/files"
install -Dm 644 $HBB/res/rustdesk.desktop -t "%{buildroot}/usr/share/nccdesk/files"
install -Dm 644 $HBB/res/rustdesk-link.desktop -t "%{buildroot}/usr/share/nccdesk/files"
install -Dm 644 $HBB/res/128x128@2x.png "%{buildroot}/usr/share/icons/hicolor/256x256/apps/nccdesk.png"
install -Dm 644 $HBB/res/scalable.svg "%{buildroot}/usr/share/icons/hicolor/scalable/apps/nccdesk.svg"

%files
/usr/share/nccdesk/*
/usr/share/nccdesk/files/rustdesk.service
/usr/share/icons/hicolor/256x256/apps/nccdesk.png
/usr/share/icons/hicolor/scalable/apps/nccdesk.svg
/usr/share/nccdesk/files/rustdesk.desktop
/usr/share/nccdesk/files/rustdesk-link.desktop

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
cp /usr/share/nccdesk/files/rustdesk.service /etc/systemd/system/rustdesk.service
cp /usr/share/nccdesk/files/rustdesk.desktop /usr/share/applications/
cp /usr/share/nccdesk/files/rustdesk-link.desktop /usr/share/applications/
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
    rm /etc/systemd/system/rustdesk.service || true
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
    rm /usr/share/applications/rustdesk.desktop || true
    rm /usr/share/applications/rustdesk-link.desktop || true
    update-desktop-database
  ;;
  1)
    # for upgrade
    rmdir /usr/lib/nccdesk || true
    rmdir /usr/local/nccdesk || true
  ;;
esac
