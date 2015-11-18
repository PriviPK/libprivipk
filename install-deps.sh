set -e

cd /tmp

deps_common="subversion python3 python3-dev python3-setuptools m4\
 libssl-dev libgmp-dev python-pyparsing flex bison\
 python-twisted python-dev"

deps1404="python3-pyparsing libpython-dev python-pytest"
deps1204="python-py"

if cat /etc/lsb-release | grep "Ubuntu 14.04"; then
    deps="$deps_common $deps1404"
else
    deps="$deps_common $deps1204"
fi

echo -e "\nInstalling deps...\n"
sudo apt-get -y install $deps

libpbc=pbc-0.5.14
if [ ! -d $libpbc/ ]; then
    tar="${libpbc}.tar.gz"
    [ ! -f $tar ] && wget http://crypto.stanford.edu/pbc/files/$tar
    tar xzf $tar
fi

echo -e "\nInstalling libpbc...\n"
prevdir=`pwd`
cd $libpbc
./configure
make
sudo make install
sudo ldconfig
cd $prevdir

echo -e "\nCloning (modified) Charm crypto libary...\n"
if [ ! -d charm/ ]; then
    git clone git@github.com:PriviPK/charm.git
    prevdir=`pwd`
    cd charm/
    git checkout 2.7-dev
    cd "$prevdir"
fi

echo -e "\nInstalling (modified) Charm...\n"
prevdir=`pwd`
cd charm/
./configure.sh
make test
sudo make install
cd $prevdir

echo -e "\nInstalled the (modified) Charm library on your machine successfully!\n"

