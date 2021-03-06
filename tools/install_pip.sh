#!/usr/bin/env bash

# **install_pip.sh**

# install_pip.sh [--pip-version <version>] [--use-get-pip] [--force]
#
# Update pip and friends to a known common version

# Assumptions:
# - update pip to $INSTALL_PIP_VERSION

# Keep track of the current directory
TOOLS_DIR=$(cd $(dirname "$0") && pwd)
TOP_DIR=`cd $TOOLS_DIR/..; pwd`

# Change dir to top of devstack
cd $TOP_DIR

# Import common functions
source $TOP_DIR/functions

FILES=$TOP_DIR/files

# Handle arguments

INSTALL_PIP_VERSION=${INSTALL_PIP_VERSION:-"1.4.1"}
while [[ -n "$1" ]]; do
    case $1 in
        --force)
            FORCE=1
            ;;
        --pip-version)
            INSTALL_PIP_VERSION="$2"
            shift
            ;;
        --use-get-pip)
            USE_GET_PIP=1;
            ;;
    esac
    shift
done

PIP_GET_PIP_URL=https://raw.github.com/pypa/pip/master/contrib/get-pip.py
PIP_TAR_URL=https://pypi.python.org/packages/source/p/pip/pip-$INSTALL_PIP_VERSION.tar.gz

GetDistro
echo "Distro: $DISTRO"

function get_versions() {
    PIP=$(which pip 2>/dev/null || which pip-python 2>/dev/null)
    if [[ -n $PIP ]]; then
        PIP_VERSION=$($PIP --version | awk '{ print $2}')
        echo "pip: $PIP_VERSION"
    fi
}


function install_get_pip() {
    if [[ ! -r $FILES/get-pip.py ]]; then
        (cd $FILES; \
            curl $PIP_GET_PIP_URL; \
        )
    fi
    sudo python $FILES/get-pip.py
}

function install_pip_tarball() {
    (cd $FILES; \
        curl -O $PIP_TAR_URL; \
        tar xvfz pip-$INSTALL_PIP_VERSION.tar.gz; \
        cd pip-$INSTALL_PIP_VERSION; \
        sudo python setup.py install; \
    )
}

# Show starting versions
get_versions

# Do pip

# Eradicate any and all system packages
uninstall_package python-pip

if [[ -n "$USE_GET_PIP" ]]; then
    install_get_pip
else
    install_pip_tarball
fi

get_versions
