#!/bin/bash

dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
installdir=/usr/local/bin

# basically run it like this
# ./builder clean
# ./builder init release
# ./builder build release 6

# clean any previous builkd output
# ./builder clean

# initialize the build (install deps, run cmake etc)
# ./builder init <release>
# where <release> is either 'debug' or 'release'

# build nerva
# ./builder build <release> <threads>
# where <release> is either 'debug' or 'release'
# Where <threads> is the number of threads to use with make

function checkdistro()
{
	if [ "$(expr substr $(uname -s) 1 5)" == "Linux" ]; then

		local os_distro="unknown"
		local os_ver="unknown"

		if [ -f /etc/os-release ]; then
		    source /etc/os-release
		    os_distro=$ID
		    os_ver=$VERSION_ID
		elif [ -f /etc/lsb-release ]; then
		    source /etc/lsb-release
		    os_distro=$DISTRIB_ID
		    os_ver=$DISTRIB_RELEASE
		fi

		export NERVA_BUILD_DISTRO=${os_distro}
		export NERVA_BUILD_DISTRO_VERSION=${os_ver}
	fi
}

function install()
{
	sudo cp ${dir}/build/bin/nerva* ${installdir}
}

function uninstall()
{
	sudo rm ${installdir}/nerva*
}

function clean()
{
	cd ${dir}
	rm -rf ${dir}/build
	find -name CMakeCache.txt | xargs rm
	find -name CMakeFiles | xargs rm -rf
	find -name *.a | xargs rm
	find -name *.o | xargs rm
	find -name *.so | xargs rm
}

function init()
{
	checkdistro

	if [ $NERVA_BUILD_DISTRO == "ubuntu" ] || [ $NERVA_BUILD_DISTRO == "debian" ]; then
		sudo apt install -y \
		git build-essential cmake pkg-config libboost-all-dev libssl-dev libzmq3-dev libunbound-dev libsodium-dev \
		libminiupnpc-dev libunwind8-dev liblzma-dev libreadline6-dev libldns-dev libexpat1-dev libgtest-dev doxygen graphviz
	elif [ $NERVA_BUILD_DISTRO == "fedora" ]; then
		sudo dnf install -y \
		git make automake cmake gcc-c++ boost-devel miniupnpc-devel graphviz \
    	doxygen unbound-devel libunwind-devel pkgconfig cppzmq-devel openssl-devel libcurl-devel --setopt=install_weak_deps=False
	else
		echo "Cannot install dependencies on your system. This distro is not officially supported"	
		exit 1
	fi

	mkdir -p ${dir}/build/$1
	cd ${dir}/build/$1
	cmake -D CMAKE_BUILD_TYPE=$1 -D BUILD_SHARED_LIBS=OFF ../..
}

function build()
{
	cd ${dir}/build/$1
	make -j $2
}

$1 $2 $3
