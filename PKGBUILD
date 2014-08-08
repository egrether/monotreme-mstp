pkgname=monotreme-mstp
pkgver=1.0
pkgrel=2
pkgdesc="MSTP kernel module for kernel 3.12.9"
arch=("armv7h")
url="http://definium.net"
license=()
groups=("monotreme")

depends=()

provides=()
conflicts=()
replaces=()
install="mstp.install"
backup=()

options=(!emptydirs)

package() {
  mkdir -p "$pkgdir/usr/lib/modules/extra"
  mkdir -p "$pkgdir/usr/lib/modules-load.d"
  cp -av "$startdir/n_mstp.ko" "$pkgdir/usr/lib/modules/extra/"
  echo "n_mstp" > $pkgdir/usr/lib/modules-load.d/mstp.conf
}


