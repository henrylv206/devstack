#!/usr/bin/env bash

# ``stack.sh`` is an opinionated OpenStack developer installation.  It
# installs and configures various combinations of **Ceilometer**, **Cinder**,
# **Glance**, **Heat**, **Horizon**, **Keystone**, **Nova**, **Neutron**,
# **Swift**, and **Trove**

# This script allows you to specify configuration options of what git
# repositories to use, enabled services, network configuration and various
# passwords.  If you are crafty you can run the script on multiple nodes using
# shared settings for common resources (mysql, rabbitmq) and build a multi-node
# developer install.

# To keep this script simple we assume you are running on a recent **Ubuntu**
# (12.04 Precise or newer) or **Fedora** (F16 or newer) machine.  (It may work
# on other platforms but support for those platforms is left to those who added
# them to DevStack.)  It should work in a VM or physical server.  Additionally
# we maintain a list of ``apt`` and ``rpm`` dependencies and other configuration
# files in this repo.

# Learn more and get the most recent version at http://devstack.org

# Added by HenryLv
echo -e "\033[31;42m Start DevStack Install Script: stack.sh \033[0m"
read -n 1

# Make sure custom grep options don't get in the way
unset GREP_OPTIONS

# Keep track of the devstack directory
TOP_DIR=$(cd $(dirname "$0") && pwd)

# Added by HenryLv
echo -e "\033[31;42m Install dir: $TOP_DIR \033[0m"
read -n 1

# Added by HenryLv
echo -e "\033[31;42m Start import functions: $TOP_DIR/functions \033[0m"
read -n 1

# Import common functions
source $TOP_DIR/functions

# Determine what system we are running on.  This provides ``os_VENDOR``,
# ``os_RELEASE``, ``os_UPDATE``, ``os_PACKAGE``, ``os_CODENAME``
# and ``DISTRO``
GetDistro


# Global Settings
# ===============

# ``stack.sh`` is customizable by setting environment variables.  Override a
# default setting via export::
#
#     export DATABASE_PASSWORD=anothersecret
#     ./stack.sh
#
# or by setting the variable on the command line::
#
#     DATABASE_PASSWORD=simple ./stack.sh
#
# Persistent variables can be placed in a ``localrc`` file::
#
#     DATABASE_PASSWORD=anothersecret
#     DATABASE_USER=hellaroot
#
# We try to have sensible defaults, so you should be able to run ``./stack.sh``
# in most cases.  ``localrc`` is not distributed with DevStack and will never
# be overwritten by a DevStack update.
#
# DevStack distributes ``stackrc`` which contains locations for the OpenStack
# repositories, branches to configure, and other configuration defaults.
# ``stackrc`` sources ``localrc`` to allow you to safely override those settings.

# Added by HenryLv
echo -e "\033[31;42m Check file: $TOP_DIR/stackrc \033[0m"
read -n 1

if [[ ! -r $TOP_DIR/stackrc ]]; then
    log_error $LINENO "missing $TOP_DIR/stackrc - did you grab more than just stack.sh?"
fi
source $TOP_DIR/stackrc


# Local Settings
# --------------

# Make sure the proxy config is visible to sub-processes
export_proxy_variables

# Destination path for installation ``DEST``
DEST=${DEST:-/opt/stack}

# Added by HenryLv
echo -e "\033[31;42m Install dest dir: $DEST \033[0m"
read -n 1

# Sanity Check
# ------------

# Clean up last environment var cache
if [[ -r $TOP_DIR/.stackenv ]]; then
    rm $TOP_DIR/.stackenv
fi

# Added by HenryLv
echo -e "\033[31;42m Check dir: $TOP_DIR/files \033[0m"
read -n 1

# ``stack.sh`` keeps the list of ``apt`` and ``rpm`` dependencies and config
# templates and other useful files in the ``files`` subdirectory
FILES=$TOP_DIR/files
if [ ! -d $FILES ]; then
    log_error $LINENO "missing devstack/files"
fi

# Added by HenryLv
echo -e "\033[31;42m Check dir: $TOP_DIR/lib \033[0m"
read -n 1

# ``stack.sh`` keeps function libraries here
# Make sure ``$TOP_DIR/lib`` directory is present
if [ ! -d $TOP_DIR/lib ]; then
    log_error $LINENO "missing devstack/lib"
fi

# Import common services (database, message queue) configuration

# Added by HenryLv
echo -e "\033[31;42m Import database: $TOP_DIR/lib/database \033[0m"
read -n 1

source $TOP_DIR/lib/database

# Added by HenryLv
echo -e "\033[31;42m Import rpc_backend: $TOP_DIR/lib/rpc_backend \033[0m"
read -n 1

source $TOP_DIR/lib/rpc_backend

# Added by HenryLv
echo -e "\033[31;42m Disable negated services \033[0m"
read -n 1

# Remove services which were negated in ENABLED_SERVICES
# using the "-" prefix (e.g., "-rabbit") instead of
# calling disable_service().
disable_negated_services

# Warn users who aren't on an explicitly supported distro, but allow them to
# override check and attempt installation with ``FORCE=yes ./stack``
if [[ ! ${DISTRO} =~ (oneiric|precise|quantal|raring|saucy|7.0|wheezy|sid|testing|jessie|f16|f17|f18|f19|opensuse-12.2|rhel6) ]]; then
    echo "WARNING: this script has not been tested on $DISTRO"
    if [[ "$FORCE" != "yes" ]]; then
        die $LINENO "If you wish to run this script anyway run with FORCE=yes"
    fi
fi

# Added by HenryLv
echo -e "\033[31;42m Check rpc backend \033[0m"
read -n 1

# Make sure we only have one rpc backend enabled,
# and the specified rpc backend is available on your platform.
check_rpc_backend

# Added by HenryLv
echo -e "\033[31;42m What's Screen? Screen_name: $SCREEN_NAME \033[0m"
read -n 1

# Check to see if we are already running DevStack
# Note that this may fail if USE_SCREEN=False
if type -p screen >/dev/null && screen -ls | egrep -q "[0-9].$SCREEN_NAME"; then
    echo "You are already running a stack.sh session."
    echo "To rejoin this session type 'screen -x stack'."
    echo "To destroy this session, type './unstack.sh'."
    exit 1
fi

# Set up logging level
VERBOSE=$(trueorfalse True $VERBOSE)

# Added by HenryLv
echo -e "\033[31;42m Log level: $VERBOSE \033[0m"
read -n 1

# Added by HenryLv
echo -e "\033[31;42m Check os vendor: $os_VENDOR \033[0m"
read -n 1

# Additional repos
# ================

# Some distros need to add repos beyond the defaults provided by the vendor
# to pick up required packages.

# The Debian Wheezy official repositories do not contain all required packages,
# add gplhost repository.
if [[ "$os_VENDOR" =~ (Debian) ]]; then
    echo 'deb http://archive.gplhost.com/debian grizzly main' | sudo tee /etc/apt/sources.list.d/gplhost_wheezy-backports.list
    echo 'deb http://archive.gplhost.com/debian grizzly-backports main' | sudo tee -a /etc/apt/sources.list.d/gplhost_wheezy-backports.list
    apt_get update
    apt_get install --force-yes gplhost-archive-keyring
fi

if [[ is_fedora && $DISTRO =~ (rhel6) ]]; then
    # Installing Open vSwitch on RHEL6 requires enabling the RDO repo.
    RHEL6_RDO_REPO_RPM=${RHEL6_RDO_REPO_RPM:-"http://rdo.fedorapeople.org/openstack/openstack-grizzly/rdo-release-grizzly-3.noarch.rpm"}
    RHEL6_RDO_REPO_ID=${RHEL6_RDO_REPO_ID:-"openstack-grizzly"}
    if ! yum repolist enabled $RHEL6_RDO_REPO_ID | grep -q $RHEL6_RDO_REPO_ID; then
        echo "RDO repo not detected; installing"
        yum_install $RHEL6_RDO_REPO_RPM || \
            die $LINENO "Error installing RDO repo, cannot continue"
    fi

    # RHEL6 requires EPEL for many Open Stack dependencies
    RHEL6_EPEL_RPM=${RHEL6_EPEL_RPM:-"http://dl.fedoraproject.org/pub/epel/6/x86_64/epel-release-6-8.noarch.rpm"}
    if ! yum repolist enabled epel | grep -q 'epel'; then
        echo "EPEL not detected; installing"
        yum_install ${RHEL6_EPEL_RPM} || \
            die $LINENO "Error installing EPEL repo, cannot continue"
    fi
fi


# root Access
# -----------

# OpenStack is designed to be run as a non-root user; Horizon will fail to run
# as **root** since Apache will not serve content from **root** user).  If
# ``stack.sh`` is run as **root**, it automatically creates a **stack** user with
# sudo privileges and runs as that user.

# Added by HenryLv
echo -e "\033[31;42m Check EUID: $EUDI \033[0m"
read -n 1

if [[ $EUID -eq 0 ]]; then
    ROOTSLEEP=${ROOTSLEEP:-10}
    echo "You are running this script as root."
    echo "In $ROOTSLEEP seconds, we will create a user '$STACK_USER' and run as that user"
    sleep $ROOTSLEEP

    # Give the non-root user the ability to run as **root** via ``sudo``
    is_package_installed sudo || install_package sudo
    if ! getent group $STACK_USER >/dev/null; then
        echo "Creating a group called $STACK_USER"
        groupadd $STACK_USER
    fi
    if ! getent passwd $STACK_USER >/dev/null; then
        echo "Creating a user called $STACK_USER"
        useradd -g $STACK_USER -s /bin/bash -d $DEST -m $STACK_USER
    fi

    echo "Giving stack user passwordless sudo privileges"
    # UEC images ``/etc/sudoers`` does not have a ``#includedir``, add one
    grep -q "^#includedir.*/etc/sudoers.d" /etc/sudoers ||
        echo "#includedir /etc/sudoers.d" >> /etc/sudoers
    ( umask 226 && echo "$STACK_USER ALL=(ALL) NOPASSWD:ALL" \
        > /etc/sudoers.d/50_stack_sh )

    echo "Copying files to $STACK_USER user"
    STACK_DIR="$DEST/${TOP_DIR##*/}"
    cp -r -f -T "$TOP_DIR" "$STACK_DIR"
    safe_chown -R $STACK_USER "$STACK_DIR"
    cd "$STACK_DIR"
    if [[ "$SHELL_AFTER_RUN" != "no" ]]; then
        exec sudo -u $STACK_USER  bash -l -c "set -e; bash stack.sh; bash"
    else
        exec sudo -u $STACK_USER bash -l -c "set -e; source stack.sh"
    fi
    exit 1
else
    # Added by HenryLv
    echo -e "\033[31;42m Check sudo \033[0m"
    read -n 1

    # We're not **root**, make sure ``sudo`` is available
    is_package_installed sudo || die "Sudo is required.  Re-run stack.sh as root ONE TIME ONLY to set up sudo."

    # UEC images ``/etc/sudoers`` does not have a ``#includedir``, add one
    sudo grep -q "^#includedir.*/etc/sudoers.d" /etc/sudoers ||
        echo "#includedir /etc/sudoers.d" | sudo tee -a /etc/sudoers

    # Set up devstack sudoers
    TEMPFILE=`mktemp`
    echo "$STACK_USER ALL=(root) NOPASSWD:ALL" >$TEMPFILE
    # Some binaries might be under /sbin or /usr/sbin, so make sure sudo will
    # see them by forcing PATH
    echo "Defaults:$STACK_USER secure_path=/sbin:/usr/sbin:/usr/bin:/bin:/usr/local/sbin:/usr/local/bin" >> $TEMPFILE
    chmod 0440 $TEMPFILE
    sudo chown root:root $TEMPFILE
    sudo mv $TEMPFILE /etc/sudoers.d/50_stack_sh

    # Remove old file
    sudo rm -f /etc/sudoers.d/stack_sh_nova
fi

# Added by HenryLv
echo -e "\033[31;42m Create destination dir: $DEST, stack user: $STACK_USER \033[0m"
read -n 1

# Create the destination directory and ensure it is writable by the user
# and read/executable by everybody for daemons (e.g. apache run for horizon)
sudo mkdir -p $DEST
safe_chown -R $STACK_USER $DEST
safe_chmod 0755 $DEST

# a basic test for $DEST path permissions (fatal on error unless skipped)
check_path_perm_sanity ${DEST}

# Set ``OFFLINE`` to ``True`` to configure ``stack.sh`` to run cleanly without
# Internet access. ``stack.sh`` must have been previously run with Internet
# access to install prerequisites and fetch repositories.
OFFLINE=`trueorfalse False $OFFLINE`

# Added by HenryLv
echo -e "\033[31;42m Check OFFLINE: $OFFLINE \033[0m"
read -n 1

# Set ``ERROR_ON_CLONE`` to ``True`` to configure ``stack.sh`` to exit if
# the destination git repository does not exist during the ``git_clone``
# operation.
ERROR_ON_CLONE=`trueorfalse False $ERROR_ON_CLONE`

# Added by HenryLv
echo -e "\033[31;42m Check ERROR_ON_CLONE: $ERROR_ON_CLONE \033[0m"
read -n 1

# Whether to enable the debug log level in OpenStack services
ENABLE_DEBUG_LOG_LEVEL=`trueorfalse True $ENABLE_DEBUG_LOG_LEVEL`

# Added by HenryLv
echo -e "\033[31;42m Check ENABLE_DEBUG_LOG_LEVEL: $ENABLE_DEBUG_LOG_LEVEL \033[0m"
read -n 1

# Destination path for service data
DATA_DIR=${DATA_DIR:-${DEST}/data}
sudo mkdir -p $DATA_DIR
safe_chown -R $STACK_USER $DATA_DIR


# Common Configuration
# ====================

# Set fixed and floating range here so we can make sure not to use addresses
# from either range when attempting to guess the IP to use for the host.
# Note that setting FIXED_RANGE may be necessary when running DevStack
# in an OpenStack cloud that uses either of these address ranges internally.
FLOATING_RANGE=${FLOATING_RANGE:-172.24.4.224/28}
FIXED_RANGE=${FIXED_RANGE:-10.0.0.0/24}
FIXED_NETWORK_SIZE=${FIXED_NETWORK_SIZE:-256}

# Added by HenryLv
echo -e "\033[31;42m IP Config, FLOATING_RANGE: $FLOATING_RANGE, FIXED_RANGE: $FIXED_RANGE, FIXED_NETWORK_SIZE: $FIXED_NETWORK_SIZE \033[0m"
read -n 1

HOST_IP=$(get_default_host_ip $FIXED_RANGE $FLOATING_RANGE "$HOST_IP_IFACE" "$HOST_IP")

# Added by HenryLv
echo -e "\033[31;42m Check HOST_IP: $HOST_IP \033[0m"
read -n 1

if [ "$HOST_IP" == "" ]; then
    die $LINENO "Could not determine host ip address. Either localrc specified dhcp on ${HOST_IP_IFACE} or defaulted"
fi

# Allow the use of an alternate hostname (such as localhost/127.0.0.1) for service endpoints.
SERVICE_HOST=${SERVICE_HOST:-$HOST_IP}

# Allow the use of an alternate protocol (such as https) for service endpoints
SERVICE_PROTOCOL=${SERVICE_PROTOCOL:-http}

# Added by HenryLv
echo -e "\033[31;42m Check SERVICE_HOST: $SERVICE_HOST and SERVICE_PROTOCOL: $SERVICE_PROTOCOL \033[0m"
read -n 1

# Configure services to use syslog instead of writing to individual log files
SYSLOG=`trueorfalse False $SYSLOG`
SYSLOG_HOST=${SYSLOG_HOST:-$HOST_IP}
SYSLOG_PORT=${SYSLOG_PORT:-516}

# Added by HenryLv
echo -e "\033[31;42m Check syslog: SYSLOG: $SYSLOG, SYSLOG_HOST: $SYSLOG_HOST, SYSLOG_PORT: $SYSLOG_PORT \033[0m"
read -n 1

# Enable sysstat logging
SYSSTAT_FILE=${SYSSTAT_FILE:-"sysstat.dat"}
SYSSTAT_INTERVAL=${SYSSTAT_INTERVAL:-"1"}

# Added by HenryLv
echo -e "\033[31;42m Check SYSSTAT_FILE:$SYSSTAT_FILE, SYSSTAT_INTERVAL:$SYSSTAT_INTERVAL \033[0m"
read -n 1

# Use color for logging output (only available if syslog is not used)
LOG_COLOR=`trueorfalse True $LOG_COLOR`

# Added by HenryLv
echo -e "\033[31;42m Check LOG_COLOR: $LOG_COLOR \033[0m"
read -n 1

# Service startup timeout
SERVICE_TIMEOUT=${SERVICE_TIMEOUT:-60}

# Added by HenryLv
echo -e "\033[31;42m Check SERVICE_TIMEOUT: $SERVICE_TIMEOUT \033[0m"
read -n 1

# Configure Projects
# ==================

# Source project function libraries

# Added by HenryLv
echo -e "\033[31;42m Import apache: $TOP_DIR/lib/apache \033[0m"
read -n 1

source $TOP_DIR/lib/apache

# Added by HenryLv
echo -e "\033[31;42m Import tls: $TOP_DIR/lib/tls \033[0m"
read -n 1

source $TOP_DIR/lib/tls

# Added by HenryLv
echo -e "\033[31;42m Import infra: $TOP_DIR/lib/infra \033[0m"
read -n 1

source $TOP_DIR/lib/infra

# Added by HenryLv
echo -e "\033[31;42m Import oslo: $TOP_DIR/lib/oslo \033[0m"
read -n 1

source $TOP_DIR/lib/oslo

# Added by HenryLv
echo -e "\033[31;42m Import horizon: $TOP_DIR/lib/horizon \033[0m"
read -n 1

source $TOP_DIR/lib/horizon

# Added by HenryLv
echo -e "\033[31;42m Import keystone: $TOP_DIR/lib/keystone \033[0m"
read -n 1

source $TOP_DIR/lib/keystone

# Added by HenryLv
echo -e "\033[31;42m Import glance: $TOP_DIR/lib/glance \033[0m"
read -n 1

source $TOP_DIR/lib/glance

# Added by HenryLv
echo -e "\033[31;42m Import nova: $TOP_DIR/lib/nova \033[0m"
read -n 1

source $TOP_DIR/lib/nova

# Added by HenryLv
echo -e "\033[31;42m Import cinder: $TOP_DIR/lib/cinder \033[0m"
read -n 1

source $TOP_DIR/lib/cinder

# Added by HenryLv
echo -e "\033[31;42m Import swift: $TOP_DIR/lib/swift \033[0m"
read -n 1

source $TOP_DIR/lib/swift

# Added by HenryLv
echo -e "\033[31;42m Import ceilometer: $TOP_DIR/lib/ceilomemter \033[0m"
read -n 1

source $TOP_DIR/lib/ceilometer

# Added by HenryLv
echo -e "\033[31;42m Import heat: $TOP_DIR/lib/heat \033[0m"
read -n 1

source $TOP_DIR/lib/heat

# Added by HenryLv
echo -e "\033[31;42m Import neutron: $TOP_DIR/lib/neutron \033[0m"
read -n 1

source $TOP_DIR/lib/neutron

# Added by HenryLv
echo -e "\033[31;42m Import baremetal: $TOP_DIR/lib/baremetal \033[0m"
read -n 1

source $TOP_DIR/lib/baremetal

# Added by HenryLv
echo -e "\033[31;42m Import ldap: $TOP_DIR/lib/ldap \033[0m"
read -n 1

source $TOP_DIR/lib/ldap

# Added by HenryLv
echo -e "\033[31;42m Import ironic: $TOP_DIR/lib/ironic \033[0m"
read -n 1

source $TOP_DIR/lib/ironic

# Added by HenryLv
echo -e "\033[31;42m Import trove: $TOP_DIR/lib/trove \033[0m"
read -n 1

source $TOP_DIR/lib/trove

# Look for Nova hypervisor plugin
NOVA_PLUGINS=$TOP_DIR/lib/nova_plugins
if is_service_enabled nova && [[ -r $NOVA_PLUGINS/hypervisor-$VIRT_DRIVER ]]; then

    # Added by HenryLv
    echo -e "\033[31;42m Check hypervisor: $NOVA_PLUGINS/hypervisor-$VIRT_DRIVER \033[0m"
    read -n 1

    # Load plugin
    source $NOVA_PLUGINS/hypervisor-$VIRT_DRIVER
fi

# Set the destination directories for other OpenStack projects
OPENSTACKCLIENT_DIR=$DEST/python-openstackclient

# Added by HenryLv
echo -e "\033[31;42m Check OPENSTACKCLIENT: $OPENSTACKCLIENT_DIR \033[0m"
read -n 1

# Interactive Configuration
# -------------------------

# Do all interactive config up front before the logging spew begins

# Generic helper to configure passwords
function read_password {
    XTRACE=$(set +o | grep xtrace)
    set +o xtrace
    var=$1; msg=$2
    pw=${!var}

    localrc=$TOP_DIR/localrc

    # If the password is not defined yet, proceed to prompt user for a password.
    if [ ! $pw ]; then
        # If there is no localrc file, create one
        if [ ! -e $localrc ]; then
            touch $localrc
        fi

        # Presumably if we got this far it can only be that our localrc is missing
        # the required password.  Prompt user for a password and write to localrc.
        echo ''
        echo '################################################################################'
        echo $msg
        echo '################################################################################'
        echo "This value will be written to your localrc file so you don't have to enter it "
        echo "again.  Use only alphanumeric characters."
        echo "If you leave this blank, a random default value will be used."
        pw=" "
        while true; do
            echo "Enter a password now:"
            read -e $var
            pw=${!var}
            [[ "$pw" = "`echo $pw | tr -cd [:alnum:]`" ]] && break
            echo "Invalid chars in password.  Try again:"
        done
        if [ ! $pw ]; then
            pw=`openssl rand -hex 10`
        fi
        eval "$var=$pw"
        echo "$var=$pw" >> $localrc
    fi
    $XTRACE
}


# Database Configuration

# To select between database backends, add the following to ``localrc``:
#
#    disable_service mysql
#    enable_service postgresql
#
# The available database backends are listed in ``DATABASE_BACKENDS`` after
# ``lib/database`` is sourced. ``mysql`` is the default.

initialize_database_backends && echo "Using $DATABASE_TYPE database backend" || echo "No database enabled"

# Added by HenryLv
echo -e "\033[31;42m Check database type: $DATABASE_TYPE \033[0m"
read -n 1

# Queue Configuration

# Rabbit connection info
if is_service_enabled rabbit; then
    RABBIT_HOST=${RABBIT_HOST:-localhost}
    
    # Added by HenryLv
    echo -e "\033[31;42m Check rabbit host: $RABBIT_HOST \033[0m"
    read -n 1
    
    read_password RABBIT_PASSWORD "ENTER A PASSWORD TO USE FOR RABBIT."
fi


# Keystone

if is_service_enabled key; then
    # The ``SERVICE_TOKEN`` is used to bootstrap the Keystone database.  It is
    # just a string and is not a 'real' Keystone token.
    read_password SERVICE_TOKEN "ENTER A SERVICE_TOKEN TO USE FOR THE SERVICE ADMIN TOKEN."
    # Services authenticate to Identity with servicename/``SERVICE_PASSWORD``
    read_password SERVICE_PASSWORD "ENTER A SERVICE_PASSWORD TO USE FOR THE SERVICE AUTHENTICATION."
    # Horizon currently truncates usernames and passwords at 20 characters
    read_password ADMIN_PASSWORD "ENTER A PASSWORD TO USE FOR HORIZON AND KEYSTONE (20 CHARS OR LESS)."

    # Keystone can now optionally install OpenLDAP by enabling the ``ldap``
    # service in ``localrc`` (e.g. ``enable_service ldap``).
    # To clean out the Keystone contents in OpenLDAP set ``KEYSTONE_CLEAR_LDAP``
    # to ``yes`` (e.g. ``KEYSTONE_CLEAR_LDAP=yes``) in ``localrc``.  To enable the
    # Keystone Identity Driver (``keystone.identity.backends.ldap.Identity``)
    # set ``KEYSTONE_IDENTITY_BACKEND`` to ``ldap`` (e.g.
    # ``KEYSTONE_IDENTITY_BACKEND=ldap``) in ``localrc``.

    # only request ldap password if the service is enabled
    if is_service_enabled ldap; then
        read_password LDAP_PASSWORD "ENTER A PASSWORD TO USE FOR LDAP"
    fi
fi


# Swift

if is_service_enabled s-proxy; then
    # We only ask for Swift Hash if we have enabled swift service.
    # ``SWIFT_HASH`` is a random unique string for a swift cluster that
    # can never change.
    read_password SWIFT_HASH "ENTER A RANDOM SWIFT HASH."
fi


# Configure logging
# -----------------

# Draw a spinner so the user knows something is happening
function spinner() {
    local delay=0.75
    local spinstr='/-\|'
    printf "..." >&3
    while [ true ]; do
        local temp=${spinstr#?}
        printf "[%c]" "$spinstr" >&3
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b" >&3
    done
}

# Echo text to the log file, summary log file and stdout
# echo_summary "something to say"
function echo_summary() {
    if [[ -t 3 && "$VERBOSE" != "True" ]]; then
        kill >/dev/null 2>&1 $LAST_SPINNER_PID
        if [ ! -z "$LAST_SPINNER_PID" ]; then
            printf "\b\b\bdone\n" >&3
        fi
        echo -n -e $@ >&6
        spinner &
        LAST_SPINNER_PID=$!
    else
        echo -e $@ >&6
    fi
}

# Echo text only to stdout, no log files
# echo_nolog "something not for the logs"
function echo_nolog() {
    echo $@ >&3
}

# Set up logging for ``stack.sh``
# Set ``LOGFILE`` to turn on logging
# Append '.xxxxxxxx' to the given name to maintain history
# where 'xxxxxxxx' is a representation of the date the file was created
TIMESTAMP_FORMAT=${TIMESTAMP_FORMAT:-"%F-%H%M%S"}
if [[ -n "$LOGFILE" || -n "$SCREEN_LOGDIR" ]]; then
    LOGDAYS=${LOGDAYS:-7}
    CURRENT_LOG_TIME=$(date "+$TIMESTAMP_FORMAT")
fi

# Added by HenryLv
echo -e "\033[31;42m Check timestamp_format: $TIMESTAMP_FORMAT, log file: $LOGFILE, screen_logdir: $SCREEN_LOGDIR, logdays: $LOGDAYS, current log time: $CURRENT_LOG_TIME \033[0m"
read -n 1

if [[ -n "$LOGFILE" ]]; then
    # First clean up old log files.  Use the user-specified ``LOGFILE``
    # as the template to search for, appending '.*' to match the date
    # we added on earlier runs.
    LOGDIR=$(dirname "$LOGFILE")
    LOGFILENAME=$(basename "$LOGFILE")
    mkdir -p $LOGDIR
    find $LOGDIR -maxdepth 1 -name $LOGFILENAME.\* -mtime +$LOGDAYS -exec rm {} \;
    LOGFILE=$LOGFILE.${CURRENT_LOG_TIME}
    SUMFILE=$LOGFILE.${CURRENT_LOG_TIME}.summary

    # Redirect output according to config

    # Copy stdout to fd 3
    exec 3>&1
    if [[ "$VERBOSE" == "True" ]]; then
        # Redirect stdout/stderr to tee to write the log file
        exec 1> >( awk '
                {
                    cmd ="date +\"%Y-%m-%d %H:%M:%S \""
                    cmd | getline now
                    close("date +\"%Y-%m-%d %H:%M:%S \"")
                    sub(/^/, now)
                    print
                    fflush()
                }' | tee "${LOGFILE}" ) 2>&1
        # Set up a second fd for output
        exec 6> >( tee "${SUMFILE}" )
    else
        # Set fd 1 and 2 to primary logfile
        exec 1> "${LOGFILE}" 2>&1
        # Set fd 6 to summary logfile and stdout
        exec 6> >( tee "${SUMFILE}" /dev/fd/3 )
    fi

    echo_summary "stack.sh log $LOGFILE"
    # Specified logfile name always links to the most recent log
    ln -sf $LOGFILE $LOGDIR/$LOGFILENAME
    ln -sf $SUMFILE $LOGDIR/$LOGFILENAME.summary
else
    # Set up output redirection without log files
    # Copy stdout to fd 3
    exec 3>&1
    if [[ "$VERBOSE" != "True" ]]; then
        # Throw away stdout and stderr
        exec 1>/dev/null 2>&1
    fi
    # Always send summary fd to original stdout
    exec 6>&3
fi

# Set up logging of screen windows
# Set ``SCREEN_LOGDIR`` to turn on logging of screen windows to the
# directory specified in ``SCREEN_LOGDIR``, we will log to the the file
# ``screen-$SERVICE_NAME-$TIMESTAMP.log`` in that dir and have a link
# ``screen-$SERVICE_NAME.log`` to the latest log file.
# Logs are kept for as long specified in ``LOGDAYS``.
if [[ -n "$SCREEN_LOGDIR" ]]; then

    # We make sure the directory is created.
    if [[ -d "$SCREEN_LOGDIR" ]]; then
        # We cleanup the old logs
        find $SCREEN_LOGDIR -maxdepth 1 -name screen-\*.log -mtime +$LOGDAYS -exec rm {} \;
    else
        mkdir -p $SCREEN_LOGDIR
    fi
fi


# Set Up Script Execution
# -----------------------

# Kill background processes on exit
trap clean EXIT
clean() {
    local r=$?
    kill >/dev/null 2>&1 $(jobs -p)
    exit $r
}


# Exit on any errors so that errors don't compound
trap failed ERR
failed() {
    local r=$?
    kill >/dev/null 2>&1 $(jobs -p)
    set +o xtrace
    [ -n "$LOGFILE" ] && echo "${0##*/} failed: full log in $LOGFILE"
    exit $r
}

# Print the commands being run so that we can see the command that triggers
# an error.  It is also useful for following along as the install occurs.
set -o xtrace


# Install Packages
# ================

# OpenStack uses a fair number of other projects.

# Install package requirements
# Source it so the entire environment is available
echo_summary "Installing package prerequisites"

# Added by HenryLv
echo -e "\033[31;42m Installing packages prerequisites: $TOP_DIR/tools/install_prereqs.sh \033[0m"
read -n 1

source $TOP_DIR/tools/install_prereqs.sh


# Added by HenryLv
echo -e "\033[31;42m Run script: $TOP_DIR/tools/install_pip.sh \033[0m"
read -n 1

# Configure an appropriate python environment
$TOP_DIR/tools/install_pip.sh

# Added by HenryLv
echo -e "\033[31;42m Run script: $TOP_DIR/tools/fixup_stuff.sh \033[0m"
read -n 1

# Do the ugly hacks for borken packages and distros
$TOP_DIR/tools/fixup_stuff.sh

# Added by HenryLv
echo -e "\033[31;42m Install rpc backend \033[0m"
read -n 1

install_rpc_backend

if is_service_enabled $DATABASE_BACKENDS; then
    # Added by HenryLv
    echo -e "\033[31;42m Install database \033[0m"
    read -n 1
    
    install_database
fi

if is_service_enabled neutron; then
    # Added by HenryLv
    echo -e "\033[31;42m Install neutron agent packages \033[0m"
    read -n 1

    install_neutron_agent_packages
fi

TRACK_DEPENDS=${TRACK_DEPENDS:-False}

# Added by HenryLv
echo -e "\033[31;42m Check track depends: $TRACK_DEPENDS \033[0m"
read -n 1

# Install python packages into a virtualenv so that we can track them
if [[ $TRACK_DEPENDS = True ]]; then
    echo_summary "Installing Python packages into a virtualenv $DEST/.venv"
    
    # Added by HenryLv
    echo -e "\033[31;42m Installing Python packages into a virtualenv $DEST/.venv \033[0m"
    read -n 1
    
    pip_install -U virtualenv

    rm -rf $DEST/.venv
    virtualenv --system-site-packages $DEST/.venv
    source $DEST/.venv/bin/activate
    $DEST/.venv/bin/pip freeze > $DEST/requires-pre-pip
fi

# Check Out and Install Source
# ----------------------------

echo_summary "Installing OpenStack project source"

# Added by HenryLv
echo -e "\033[31;42m Installing OpenStack project source \033[0m"
read -n 1

# Install required infra support libraries
# Added by HenryLv
echo -e "\033[31;42m Install infra \033[0m"
read -n 1

install_infra

# Install oslo libraries that have graduated

# Added by HenryLv
echo -e "\033[31;42m Install oslo \033[0m"
read -n 1

install_oslo

# Install clients libraries
# Added by HenryLv
echo -e "\033[31;42m Install keystone client \033[0m"
read -n 1

install_keystoneclient

# Added by HenryLv
echo -e "\033[31;42m Install glance client \033[0m"
read -n 1

install_glanceclient

# Added by HenryLv
echo -e "\033[31;42m Install cinder client \033[0m"
read -n 1

install_cinderclient

# Added by HenryLv
echo -e "\033[31;42m Install nova client \033[0m"
read -n 1

install_novaclient
if is_service_enabled swift glance horizon; then
    # Added by HenryLv
    echo -e "\033[31;42m Install swift client \033[0m"
    read -n 1
    
    install_swiftclient
fi
if is_service_enabled neutron nova horizon; then
    # Added by HenryLv
    echo -e "\033[31;42m Install neutron client \033[0m"
    read -n 1

    install_neutronclient
fi
if is_service_enabled heat horizon; then
    # Added by HenryLv
    echo -e "\033[31;42m Install heat client \033[0m"
    read -n 1

    install_heatclient
fi

# Added by HenryLv
echo -e "\033[31;42m Check OPENSTACKCLIENT_REPO: $OPENSTACKCLIENT_REPO, OPENSTACKCLIENT_DIR: $OPENSTACKCLIENT_DIR, OPENSTACKCLIENT_BRANCH: $OPENSTACKCLIENT_BRANCH \033[0m"
read -n 1

git_clone $OPENSTACKCLIENT_REPO $OPENSTACKCLIENT_DIR $OPENSTACKCLIENT_BRANCH
setup_develop $OPENSTACKCLIENT_DIR

if is_service_enabled key; then
    
    # Added by HenryLv
    echo -e "\033[31;42m Install and config keystone \033[0m"
    read -n 1

    install_keystone
    configure_keystone
fi

if is_service_enabled s-proxy; then

    # Added by HenryLv
    echo -e "\033[31;42m Install and config swift \033[0m"
    read -n 1

    install_swift
    configure_swift

    # swift3 middleware to provide S3 emulation to Swift
    if is_service_enabled swift3; then
        # replace the nova-objectstore port by the swift port
        S3_SERVICE_PORT=8080
        git_clone $SWIFT3_REPO $SWIFT3_DIR $SWIFT3_BRANCH
        setup_develop $SWIFT3_DIR
        
        # Added by HenryLv
        echo -e "\033[31;42m Check S3, S3_SERVICE_PORT: $S3_SERVICE_PORT, SWIFT3_REPO: $SWIFT3_REPO, SWIFT3_DIR: $SWIFT3_DIR, SWIFT3_BRANCH: $SWIFT3_BRANCH \033[0m"
        read -n 1
    fi
fi

if is_service_enabled g-api n-api; then
    
    # Added by HenryLv
    echo -e "\033[31;42m Install and config glance \033[0m"
    read -n 1

    # image catalog service
    install_glance
    configure_glance
fi

if is_service_enabled cinder; then
    
    # Added by HenryLv
    echo -e "\033[31;42m Install and config cinder \033[0m"
    read -n 1

    install_cinder
    configure_cinder
fi

if is_service_enabled neutron; then
    # Added by HenryLv
    echo -e "\033[31;42m Install neutron \033[0m"
    read -n 1
        
    install_neutron
    install_neutron_third_party
fi

if is_service_enabled nova; then
    # Added by HenryLv
    echo -e "\033[31;42m Install and nova \033[0m"
    read -n 1
    
    # compute service
    install_nova
    cleanup_nova
    configure_nova
fi

if is_service_enabled n-novnc; then
    # a websockets/html5 or flash powered VNC console for vm instances
    git_clone $NOVNC_REPO $NOVNC_DIR $NOVNC_BRANCH
    
    # Added by HenryLv
    echo -e "\033[31;42m Check NOVNC_REPO: $NOVNC_REPO, NOVNC_DIR: $NOVNC_DIR, NOVNC_BRANCH: $NOVNC_BRANCH \033[0m"
    read -n 1
fi

if is_service_enabled n-spice; then
    # a websockets/html5 or flash powered SPICE console for vm instances
    git_clone $SPICE_REPO $SPICE_DIR $SPICE_BRANCH
    
    # Added by HenryLv
    echo -e "\033[31;42m Check SPICE_REPO: $SPICE_REPO, SPICE_DIR: $SPICE_REPO, SPICE_BRANCH: $SPICE_BRANCH \033[0m"
    read -n 1
fi

if is_service_enabled horizon; then
    # Added by HenryLv
    echo -e "\033[31;42m Install and config horizon \033[0m"
    read -n 1
    
    # dashboard
    install_horizon
    configure_horizon
fi

if is_service_enabled ceilometer; then
    # Added by HenryLv
    echo -e "\033[31;42m Install and config ceilometerclient and ceilometer \033[0m"
    read -n 1

    install_ceilometerclient
    install_ceilometer
    echo_summary "Configuring Ceilometer"
    configure_ceilometer
    configure_ceilometerclient
fi

if is_service_enabled heat; then
    # Added by HenryLv
    echo -e "\033[31;42m Install and config heat \033[0m"
    read -n 1
    
    install_heat
    cleanup_heat
    configure_heat
fi

if is_service_enabled trove; then
    # Added by HenryLv
    echo -e "\033[31;42m Install and config trove \033[0m"
    read -n 1
    
    install_trove
    install_troveclient
    cleanup_trove
fi

if is_service_enabled tls-proxy; then
    # Added by HenryLv
    echo -e "\033[31;42m config CA and cert \033[0m"
    read -n 1

    configure_CA
    init_CA
    init_cert
    # Add name to /etc/hosts
    # don't be naive and add to existing line!
fi

if is_service_enabled ir-api ir-cond; then
    # Added by HenryLv
    echo -e "\033[31;42m Install and config ironic \033[0m"
    read -n 1

    install_ironic
    configure_ironic
fi

# Added by HenryLv
echo -e "\033[31;42m Check TRACK_DEPENDS: $TRACK_DEPENDS \033[0m"
read -n 1

if [[ $TRACK_DEPENDS = True ]]; then
    $DEST/.venv/bin/pip freeze > $DEST/requires-post-pip
    if ! diff -Nru $DEST/requires-pre-pip $DEST/requires-post-pip > $DEST/requires.diff; then
        cat $DEST/requires.diff
    fi
    echo "Ran stack.sh in depend tracking mode, bailing out now"
    exit 0
fi


# Syslog
# ------

# Added by HenryLv
echo -e "\033[31;42m Check SYSLOG: $SYSLOG \033[0m"
read -n 1

if [[ $SYSLOG != "False" ]]; then
    if [[ "$SYSLOG_HOST" = "$HOST_IP" ]]; then
        # Configure the master host to receive
        cat <<EOF >/tmp/90-stack-m.conf
\$ModLoad imrelp
\$InputRELPServerRun $SYSLOG_PORT
EOF
        sudo mv /tmp/90-stack-m.conf /etc/rsyslog.d
    else
        # Set rsyslog to send to remote host
        cat <<EOF >/tmp/90-stack-s.conf
*.*		:omrelp:$SYSLOG_HOST:$SYSLOG_PORT
EOF
        sudo mv /tmp/90-stack-s.conf /etc/rsyslog.d
    fi

    RSYSLOGCONF="/etc/rsyslog.conf"
    if [ -f $RSYSLOGCONF ]; then
        sudo cp -b $RSYSLOGCONF $RSYSLOGCONF.bak
        if [[ $(grep '$SystemLogRateLimitBurst' $RSYSLOGCONF)  ]]; then
            sudo sed -i 's/$SystemLogRateLimitBurst\ .*/$SystemLogRateLimitBurst\ 0/' $RSYSLOGCONF
        else
            sudo sed -i '$ i $SystemLogRateLimitBurst\ 0' $RSYSLOGCONF
        fi
        if [[ $(grep '$SystemLogRateLimitInterval' $RSYSLOGCONF)  ]]; then
            sudo sed -i 's/$SystemLogRateLimitInterval\ .*/$SystemLogRateLimitInterval\ 0/' $RSYSLOGCONF
        else
            sudo sed -i '$ i $SystemLogRateLimitInterval\ 0' $RSYSLOGCONF
        fi
    fi

    echo_summary "Starting rsyslog"
    restart_service rsyslog
fi


# Finalize queue installation
# ----------------------------

# Added by HenryLv
echo -e "\033[31;42m Restart rpc backend \033[0m"
read -n 1

restart_rpc_backend


# Configure database
# ------------------

if is_service_enabled $DATABASE_BACKENDS; then
    # Added by HenryLv
    echo -e "\033[31;42m Config database \033[0m"
    read -n 1
    
    configure_database
fi


# Configure screen
# ----------------

USE_SCREEN=$(trueorfalse True $USE_SCREEN)
# Added by HenryLv
echo -e "\033[31;42m Check USE_SCREEN: $USE_SCREEN \033[0m"
read -n 1

if [[ "$USE_SCREEN" == "True" ]]; then
    # Create a new named screen to run processes in
    screen -d -m -S $SCREEN_NAME -t shell -s /bin/bash
    sleep 1

    # Set a reasonable status bar
    if [ -z "$SCREEN_HARDSTATUS" ]; then
        SCREEN_HARDSTATUS='%{= .} %-Lw%{= .}%> %n%f %t*%{= .}%+Lw%< %-=%{g}(%{d}%H/%l%{g})'
    fi
    screen -r $SCREEN_NAME -X hardstatus alwayslastline "$SCREEN_HARDSTATUS"
    screen -r $SCREEN_NAME -X setenv PROMPT_COMMAND /bin/true
fi

# Clear screen rc file
SCREENRC=$TOP_DIR/$SCREEN_NAME-screenrc
# Added by HenryLv
echo -e "\033[31;42m Check SCREENRC: $SCREENRC \033[0m"
read -n 1
    
if [[ -e $SCREENRC ]]; then
    rm -f $SCREENRC
fi

# Initialize the directory for service status check
# Added by HenryLv
echo -e "\033[31;42m Init service check \033[0m"
read -n 1

init_service_check


# Sysstat
# -------

# If enabled, systat has to start early to track OpenStack service startup.
if is_service_enabled sysstat;then
    if [[ -n ${SCREEN_LOGDIR} ]]; then
        screen_it sysstat "sar -o $SCREEN_LOGDIR/$SYSSTAT_FILE $SYSSTAT_INTERVAL"
    else
        screen_it sysstat "sar $SYSSTAT_INTERVAL"
    fi
fi


# Keystone
# --------

if is_service_enabled key; then
    echo_summary "Starting Keystone"
    
    # Added by HenryLv
    echo -e "\033[31;42m Init and start keystone \033[0m"
    read -n 1
    
    init_keystone
    start_keystone

    # Set up a temporary admin URI for Keystone
    SERVICE_ENDPOINT=$KEYSTONE_SERVICE_PROTOCOL://$KEYSTONE_AUTH_HOST:$KEYSTONE_AUTH_PORT/v2.0

    # Added by HenryLv
    echo -e "\033[31;42m Check SERVICE_ENDPOINT: $SERVICE_ENDPOINT \033[0m"
    read -n 1

    if is_service_enabled tls-proxy; then
        export OS_CACERT=$INT_CA_DIR/ca-chain.pem
        # Until the client support is fixed, just use the internal endpoint
        SERVICE_ENDPOINT=http://$KEYSTONE_AUTH_HOST:$KEYSTONE_AUTH_PORT_INT/v2.0
        
        # Added by HenryLv
        echo -e "\033[31;42m Check OS_CACERT: $OS_CACERT, SERVICE_ENDPOINT: $SERVICE_ENDPOINT \033[0m"
        read -n 1
        
    fi

    # Do the keystone-specific bits from keystone_data.sh
    export OS_SERVICE_TOKEN=$SERVICE_TOKEN
    export OS_SERVICE_ENDPOINT=$SERVICE_ENDPOINT
    
    # Added by HenryLv
    echo -e "\033[31;42m Check OS_SERVICE_TOKEN: $OS_SERVICE_TOKEN, OS_SERVICE_ENDPOINT: $OS_SERVICE_ENDPOINT \033[0m"
    read -n 1
    
    # Added by HenryLv
    echo -e "\033[31;42m Create keystone accounts \033[0m"
    read -n 1
    
    create_keystone_accounts
    
    # Added by HenryLv
    echo -e "\033[31;42m Create nova accounts \033[0m"
    read -n 1
    
    create_nova_accounts
    
    # Added by HenryLv
    echo -e "\033[31;42m Create cinder accounts \033[0m"
    read -n 1
    
    create_cinder_accounts
    
    # Added by HenryLv
    echo -e "\033[31;42m Create neutron accounts \033[0m"
    read -n 1
    
    create_neutron_accounts

    if is_service_enabled trove; then
        # Added by HenryLv
        echo -e "\033[31;42m Create trove accounts \033[0m"
        read -n 1
        
        create_trove_accounts
    fi

    if is_service_enabled swift || is_service_enabled s-proxy; then
        # Added by HenryLv
        echo -e "\033[31;42m Create swift accounts \033[0m"
        read -n 1
    
        create_swift_accounts
    fi

    # Added by HenryLv
    echo -e "\033[31;42m Run script: $FILES/keystone_data.sh \033[0m"
    read -n 1

    # ``keystone_data.sh`` creates services, admin and demo users, and roles.
    ADMIN_PASSWORD=$ADMIN_PASSWORD SERVICE_TENANT_NAME=$SERVICE_TENANT_NAME SERVICE_PASSWORD=$SERVICE_PASSWORD \
    SERVICE_TOKEN=$SERVICE_TOKEN SERVICE_ENDPOINT=$SERVICE_ENDPOINT SERVICE_HOST=$SERVICE_HOST \
    S3_SERVICE_PORT=$S3_SERVICE_PORT KEYSTONE_CATALOG_BACKEND=$KEYSTONE_CATALOG_BACKEND \
    DEVSTACK_DIR=$TOP_DIR ENABLED_SERVICES=$ENABLED_SERVICES HEAT_API_CFN_PORT=$HEAT_API_CFN_PORT \
    HEAT_API_PORT=$HEAT_API_PORT \
        bash -x $FILES/keystone_data.sh

    # Set up auth creds now that keystone is bootstrapped
    export OS_AUTH_URL=$SERVICE_ENDPOINT
    export OS_TENANT_NAME=admin
    export OS_USERNAME=admin
    export OS_PASSWORD=$ADMIN_PASSWORD
    
    # Added by HenryLv
    echo -e "\033[31;42m Check OS_AUTH_URL: $OS_AUTH_URL, OS_TENANT_NAME: $OS_TENANT_NAME, OS_USERNAME: $OS_USERNAME, OS_PASSWORD: $OS_PASSWORD, OS_SERVICE_TOKEN: $OS_SERVICE_TOKEN, OS_SERVICE_ENDPOINT: $OS_SERVICE_ENDPOINT \033[0m"
    read -n 1
    
    unset OS_SERVICE_TOKEN OS_SERVICE_ENDPOINT
fi


# Horizon
# -------

# Set up the django horizon application to serve via apache/wsgi

if is_service_enabled horizon; then
    echo_summary "Configuring and starting Horizon"
    
    # Added by HenryLv
    echo -e "\033[31;42m Init and start horizon \033[0m"
    read -n 1
    
    init_horizon
    start_horizon
fi


# Glance
# ------

if is_service_enabled g-reg; then
    echo_summary "Configuring Glance"
    
    # Added by HenryLv
    echo -e "\033[31;42m Init glance \033[0m"
    read -n 1
    
    init_glance
fi

# Ironic
# ------

if is_service_enabled ir-api ir-cond; then
    echo_summary "Configuring Ironic"
    
    # Added by HenryLv
    echo -e "\033[31;42m Init ironic \033[0m"
    read -n 1
    
    init_ironic
fi



# Neutron
# -------

if is_service_enabled neutron; then
    echo_summary "Configuring Neutron"

    # Added by HenryLv
    echo -e "\033[31;42m Config neutron \033[0m"
    read -n 1

    configure_neutron
    # Run init_neutron only on the node hosting the neutron API server
    if is_service_enabled $DATABASE_BACKENDS && is_service_enabled q-svc; then
        # Added by HenryLv
        echo -e "\033[31;42m Init neutron \033[0m"
        read -n 1
    
        init_neutron
    fi
fi

# Some Neutron plugins require network controllers which are not
# a part of the OpenStack project. Configure and start them.
if is_service_enabled neutron; then
    # Added by HenryLv
    echo -e "\033[31;42m Config, init and start neutron \033[0m"
    read -n 1
    
    configure_neutron_third_party
    init_neutron_third_party
    start_neutron_third_party
fi


# Nova
# ----

if is_service_enabled nova; then
    echo_summary "Configuring Nova"
    # Added by HenryLv
    echo -e "\033[31;42m Config nova \033[0m"
    read -n 1
    
    configure_nova
fi

if is_service_enabled n-net q-dhcp; then
    # Delete traces of nova networks from prior runs
    # Do not kill any dnsmasq instance spawned by NetworkManager
    netman_pid=$(pidof NetworkManager || true)
    
    # Added by HenryLv
    echo -e "\033[31;42m Check netman_pid: $netman_pid \033[0m"
    read -n 1
    
    if [ -z "$netman_pid" ]; then
        sudo killall dnsmasq || true
    else
        sudo ps h -o pid,ppid -C dnsmasq | grep -v $netman_pid | awk '{print $1}' | sudo xargs kill || true
    fi

    clean_iptables
    rm -rf ${NOVA_STATE_PATH}/networks
    sudo mkdir -p ${NOVA_STATE_PATH}/networks
    safe_chown -R ${USER} ${NOVA_STATE_PATH}/networks
    # Force IP forwarding on, just in case
    sudo sysctl -w net.ipv4.ip_forward=1
fi


# Storage Service
# ---------------

if is_service_enabled s-proxy; then
    echo_summary "Configuring Swift"
    
    # Added by HenryLv
    echo -e "\033[31;42m Init swift \033[0m"
    read -n 1
    
    init_swift
fi


# Volume Service
# --------------

if is_service_enabled cinder; then
    echo_summary "Configuring Cinder"
    
    # Added by HenryLv
    echo -e "\033[31;42m Init cinder \033[0m"
    read -n 1
    
    init_cinder
fi


# Compute Service
# ---------------

if is_service_enabled nova; then
    echo_summary "Configuring Nova"
    # Rebuild the config file from scratch
    
    # Added by HenryLv
    echo -e "\033[31;42m config and init nova \033[0m"
    read -n 1
    
    create_nova_conf
    init_nova

    # Additional Nova configuration that is dependent on other services
    if is_service_enabled neutron; then
        create_nova_conf_neutron
    elif is_service_enabled n-net; then
        create_nova_conf_nova_network
    fi

    # Added by HenryLv
    echo -e "\033[31;42m Check can read from $NOVA_PLUGINS/hypervisor-$VIRT_DRIVER \033[0m"
    read -n 1

    if [[ -r $NOVA_PLUGINS/hypervisor-$VIRT_DRIVER ]]; then
        # Configure hypervisor plugin
        
        # Added by HenryLv
        echo -e "\033[31;42m Config nova hypervisor \033[0m"
        read -n 1
        
        configure_nova_hypervisor


    # XenServer
    # ---------

    elif [ "$VIRT_DRIVER" = 'xenserver' ]; then
        echo_summary "Using XenServer virtualization driver"
        if [ -z "$XENAPI_CONNECTION_URL" ]; then
            die $LINENO "XENAPI_CONNECTION_URL is not specified"
        fi
        read_password XENAPI_PASSWORD "ENTER A PASSWORD TO USE FOR XEN."
        iniset $NOVA_CONF DEFAULT compute_driver "xenapi.XenAPIDriver"
        iniset $NOVA_CONF DEFAULT xenapi_connection_url "$XENAPI_CONNECTION_URL"
        iniset $NOVA_CONF DEFAULT xenapi_connection_username "$XENAPI_USER"
        iniset $NOVA_CONF DEFAULT xenapi_connection_password "$XENAPI_PASSWORD"
        iniset $NOVA_CONF DEFAULT flat_injected "False"
        # Need to avoid crash due to new firewall support
        XEN_FIREWALL_DRIVER=${XEN_FIREWALL_DRIVER:-"nova.virt.firewall.IptablesFirewallDriver"}
        iniset $NOVA_CONF DEFAULT firewall_driver "$XEN_FIREWALL_DRIVER"


    # OpenVZ
    # ------

    elif [ "$VIRT_DRIVER" = 'openvz' ]; then
        echo_summary "Using OpenVZ virtualization driver"
        iniset $NOVA_CONF DEFAULT compute_driver "openvz.OpenVzDriver"
        iniset $NOVA_CONF DEFAULT connection_type "openvz"
        LIBVIRT_FIREWALL_DRIVER=${LIBVIRT_FIREWALL_DRIVER:-"nova.virt.libvirt.firewall.IptablesFirewallDriver"}
        iniset $NOVA_CONF DEFAULT firewall_driver "$LIBVIRT_FIREWALL_DRIVER"


    # Bare Metal
    # ----------

    elif [ "$VIRT_DRIVER" = 'baremetal' ]; then
        echo_summary "Using BareMetal driver"
        LIBVIRT_FIREWALL_DRIVER=${LIBVIRT_FIREWALL_DRIVER:-"nova.virt.firewall.NoopFirewallDriver"}
        iniset $NOVA_CONF DEFAULT compute_driver nova.virt.baremetal.driver.BareMetalDriver
        iniset $NOVA_CONF DEFAULT firewall_driver $LIBVIRT_FIREWALL_DRIVER
        iniset $NOVA_CONF DEFAULT scheduler_host_manager nova.scheduler.baremetal_host_manager.BaremetalHostManager
        iniset $NOVA_CONF DEFAULT ram_allocation_ratio 1.0
        iniset $NOVA_CONF DEFAULT reserved_host_memory_mb 0
        iniset $NOVA_CONF baremetal instance_type_extra_specs cpu_arch:$BM_CPU_ARCH
        iniset $NOVA_CONF baremetal driver $BM_DRIVER
        iniset $NOVA_CONF baremetal power_manager $BM_POWER_MANAGER
        iniset $NOVA_CONF baremetal tftp_root /tftpboot
        if [[ "$BM_DNSMASQ_FROM_NOVA_NETWORK" = "True" ]]; then
            BM_DNSMASQ_CONF=$NOVA_CONF_DIR/dnsmasq-for-baremetal-from-nova-network.conf
            sudo cp "$FILES/dnsmasq-for-baremetal-from-nova-network.conf" "$BM_DNSMASQ_CONF"
            iniset $NOVA_CONF DEFAULT dnsmasq_config_file "$BM_DNSMASQ_CONF"
        fi

        # Define extra baremetal nova conf flags by defining the array ``EXTRA_BAREMETAL_OPTS``.
        for I in "${EXTRA_BAREMETAL_OPTS[@]}"; do
           # Attempt to convert flags to options
           iniset $NOVA_CONF baremetal ${I/=/ }
        done


   # PowerVM
   # -------

    elif [ "$VIRT_DRIVER" = 'powervm' ]; then
        echo_summary "Using PowerVM driver"
        POWERVM_MGR_TYPE=${POWERVM_MGR_TYPE:-"ivm"}
        POWERVM_MGR_HOST=${POWERVM_MGR_HOST:-"powervm.host"}
        POWERVM_MGR_USER=${POWERVM_MGR_USER:-"padmin"}
        POWERVM_MGR_PASSWD=${POWERVM_MGR_PASSWD:-"password"}
        POWERVM_IMG_REMOTE_PATH=${POWERVM_IMG_REMOTE_PATH:-"/tmp"}
        POWERVM_IMG_LOCAL_PATH=${POWERVM_IMG_LOCAL_PATH:-"/tmp"}
        iniset $NOVA_CONF DEFAULT compute_driver nova.virt.powervm.PowerVMDriver
        iniset $NOVA_CONF DEFAULT powervm_mgr_type $POWERVM_MGR_TYPE
        iniset $NOVA_CONF DEFAULT powervm_mgr $POWERVM_MGR_HOST
        iniset $NOVA_CONF DEFAULT powervm_mgr_user $POWERVM_MGR_USER
        iniset $NOVA_CONF DEFAULT powervm_mgr_passwd $POWERVM_MGR_PASSWD
        iniset $NOVA_CONF DEFAULT powervm_img_remote_path $POWERVM_IMG_REMOTE_PATH
        iniset $NOVA_CONF DEFAULT powervm_img_local_path $POWERVM_IMG_LOCAL_PATH


    # vSphere API
    # -----------

    elif [ "$VIRT_DRIVER" = 'vsphere' ]; then
        echo_summary "Using VMware vCenter driver"
        iniset $NOVA_CONF DEFAULT compute_driver "vmwareapi.VMwareVCDriver"
        VMWAREAPI_USER=${VMWAREAPI_USER:-"root"}
        iniset $NOVA_CONF vmware host_ip "$VMWAREAPI_IP"
        iniset $NOVA_CONF vmware host_username "$VMWAREAPI_USER"
        iniset $NOVA_CONF vmware host_password "$VMWAREAPI_PASSWORD"
        iniset $NOVA_CONF vmware cluster_name "$VMWAREAPI_CLUSTER"
        if is_service_enabled neutron; then
            iniset $NOVA_CONF vmware integration_bridge $OVS_BRIDGE
        fi

    # fake
    # ----

    elif [ "$VIRT_DRIVER" = 'fake' ]; then
        echo_summary "Using fake Virt driver"
        iniset $NOVA_CONF DEFAULT compute_driver "nova.virt.fake.FakeDriver"
        # Disable arbitrary limits
        iniset $NOVA_CONF DEFAULT quota_instances -1
        iniset $NOVA_CONF DEFAULT quota_cores -1
        iniset $NOVA_CONF DEFAULT quota_ram -1
        iniset $NOVA_CONF DEFAULT quota_floating_ips -1
        iniset $NOVA_CONF DEFAULT quota_fixed_ips -1
        iniset $NOVA_CONF DEFAULT quota_metadata_items -1
        iniset $NOVA_CONF DEFAULT quota_injected_files -1
        iniset $NOVA_CONF DEFAULT quota_injected_file_path_bytes -1
        iniset $NOVA_CONF DEFAULT quota_security_groups -1
        iniset $NOVA_CONF DEFAULT quota_security_group_rules -1
        iniset $NOVA_CONF DEFAULT quota_key_pairs -1
        iniset $NOVA_CONF DEFAULT scheduler_default_filters "RetryFilter,AvailabilityZoneFilter,ComputeFilter,ComputeCapabilitiesFilter,ImagePropertiesFilter"


    # Default libvirt
    # ---------------

    else
        # Added by HenryLv
        echo -e "\033[31;42m Using libvirt virtualization driver \033[0m"
        read -n 1
        
        echo_summary "Using libvirt virtualization driver"
        iniset $NOVA_CONF DEFAULT compute_driver "libvirt.LibvirtDriver"
        LIBVIRT_FIREWALL_DRIVER=${LIBVIRT_FIREWALL_DRIVER:-"nova.virt.libvirt.firewall.IptablesFirewallDriver"}
        iniset $NOVA_CONF DEFAULT firewall_driver "$LIBVIRT_FIREWALL_DRIVER"
        # Power architecture currently does not support graphical consoles.
        if is_arch "ppc64"; then
            iniset $NOVA_CONF DEFAULT vnc_enabled "false"
        fi
        
        # Added by HenryLv
        echo -e "\033[31;42m Check NOVA_CONF: $NOVA_CONF, LIBVIRT_FIREWALL_DRIVER: $LIBVIRT_FIREWALL_DRIVER \033[0m"
        read -n 1
    fi

    # Added by HenryLv
    echo -e "\033[31;42m Init nova cells \033[0m"
    read -n 1

    init_nova_cells
fi

# Extra things to prepare nova for baremetal, before nova starts
if is_service_enabled nova && is_baremetal; then
    echo_summary "Preparing for nova baremetal"
    prepare_baremetal_toolchain
    configure_baremetal_nova_dirs
    if [[ "$BM_USE_FAKE_ENV" = "True" ]]; then
       create_fake_baremetal_env
    fi
fi


# Launch Services
# ===============

# Only run the services specified in ``ENABLED_SERVICES``

# Launch Swift Services
if is_service_enabled s-proxy; then
    echo_summary "Starting Swift"
    
    # Added by HenryLv
    echo -e "\033[31;42m Starting Swift \033[0m"
    read -n 1
    
    start_swift
fi

# Launch the Glance services
if is_service_enabled g-api g-reg; then
    echo_summary "Starting Glance"
    
    # Added by HenryLv
    echo -e "\033[31;42m Starting Glance \033[0m"
    read -n 1
    
    start_glance
fi

# Launch the Ironic services
if is_service_enabled ir-api ir-cond; then
    echo_summary "Starting Ironic"
    
    # Added by HenryLv
    echo -e "\033[31;42m Starting Ironic \033[0m"
    read -n 1
    
    start_ironic
fi

# Create an access key and secret key for nova ec2 register image
if is_service_enabled key && is_service_enabled swift3 && is_service_enabled nova; then
    NOVA_USER_ID=$(keystone user-list | grep ' nova ' | get_field 1)
    NOVA_TENANT_ID=$(keystone tenant-list | grep " $SERVICE_TENANT_NAME " | get_field 1)
    CREDS=$(keystone ec2-credentials-create --user_id $NOVA_USER_ID --tenant_id $NOVA_TENANT_ID)
    ACCESS_KEY=$(echo "$CREDS" | awk '/ access / { print $4 }')
    SECRET_KEY=$(echo "$CREDS" | awk '/ secret / { print $4 }')
    iniset $NOVA_CONF DEFAULT s3_access_key "$ACCESS_KEY"
    iniset $NOVA_CONF DEFAULT s3_secret_key "$SECRET_KEY"
    iniset $NOVA_CONF DEFAULT s3_affix_tenant "True"
    
    # Added by HenryLv
    echo -e "\033[31;42m Check NOVA_USER_ID: $NOVA_USER_ID, NOVA_TENANT_ID: $NOVA_TENANT_ID, CREDS: $CREDS, ACCESS_KEY: $ACCESS_KEY, SECRET_KEY: $SECRET_KEY \033[0m"
    read -n 1
fi

if is_service_enabled zeromq; then
    echo_summary "Starting zermomq receiver"
    
    # Added by HenryLv
    echo -e "\033[31;42m Starting zermomq receiver \033[0m"
    read -n 1
    
    screen_it zeromq "cd $NOVA_DIR && $NOVA_BIN_DIR/nova-rpc-zmq-receiver"
fi

# Launch the nova-api and wait for it to answer before continuing
if is_service_enabled n-api; then
    echo_summary "Starting Nova API"
    
    # Added by HenryLv
    echo -e "\033[31;42m Starting Nova API \033[0m"
    read -n 1
    
    start_nova_api
fi

if is_service_enabled q-svc; then
    echo_summary "Starting Neutron"

    start_neutron_service_and_check
    create_neutron_initial_network
    setup_neutron_debug
elif is_service_enabled $DATABASE_BACKENDS && is_service_enabled n-net; then
    NM_CONF=${NOVA_CONF}
    if is_service_enabled n-cell; then
        NM_CONF=${NOVA_CELLS_CONF}
    fi

    # Added by HenryLv
    echo -e "\033[31;42m Check NM_CONF: $NM_CONF, NOVA_BIN_DIR: $NOVA_BIN_DIR \033[0m"
    read -n 1

    # Create a small network
    $NOVA_BIN_DIR/nova-manage --config-file $NM_CONF network create "$PRIVATE_NETWORK_NAME" $FIXED_RANGE 1 $FIXED_NETWORK_SIZE $NETWORK_CREATE_ARGS

    # Create some floating ips
    $NOVA_BIN_DIR/nova-manage --config-file $NM_CONF floating create $FLOATING_RANGE --pool=$PUBLIC_NETWORK_NAME

    # Create a second pool
    $NOVA_BIN_DIR/nova-manage --config-file $NM_CONF floating create --ip_range=$TEST_FLOATING_RANGE --pool=$TEST_FLOATING_POOL
fi

if is_service_enabled neutron; then
    # Added by HenryLv
    echo -e "\033[31;42m Starting neutron agents \033[0m"
    read -n 1

    start_neutron_agents
fi
if is_service_enabled nova; then
    echo_summary "Starting Nova"
    # Added by HenryLv
    echo -e "\033[31;42m Starting Nova \033[0m"
    read -n 1
    start_nova
fi
if is_service_enabled cinder; then
    echo_summary "Starting Cinder"
    # Added by HenryLv
    echo -e "\033[31;42m Starting Cinder \033[0m"
    read -n 1
    start_cinder
fi
if is_service_enabled ceilometer; then
    echo_summary "Starting Ceilometer"
    
    # Added by HenryLv
    echo -e "\033[31;42m Starting Ceilometer \033[0m"
    read -n 1
    
    init_ceilometer
    start_ceilometer
fi

# Configure and launch heat engine, api and metadata
if is_service_enabled heat; then
    # Added by HenryLv
    echo -e "\033[31;42m Config and start heat \033[0m"
    read -n 1
    # Initialize heat, including replacing nova flavors
    echo_summary "Configuring Heat"
    init_heat
    echo_summary "Starting Heat"
    start_heat
fi

# Configure and launch the trove service api, and taskmanager
if is_service_enabled trove; then
    # Added by HenryLv
    echo -e "\033[31;42m Config and start trove \033[0m"
    read -n 1
    
    # Initialize trove
    echo_summary "Configuring Trove"
    configure_troveclient
    configure_trove
    init_trove

    # Start the trove API and trove taskmgr components
    echo_summary "Starting Trove"
    start_trove
fi

# Create account rc files
# =======================

# Creates source able script files for easier user switching.
# This step also creates certificates for tenants and users,
# which is helpful in image bundle steps.

if is_service_enabled nova && is_service_enabled key; then
    # Added by HenryLv
    echo -e "\033[31;42m create rc files \033[0m"
    read -n 1

    $TOP_DIR/tools/create_userrc.sh -PA --target-dir $TOP_DIR/accrc
fi


# Install Images
# ==============

# Upload an image to glance.
#
# The default image is cirros, a small testing image which lets you login as **root**
# cirros has a ``cloud-init`` analog supporting login via keypair and sending
# scripts as userdata.
# See https://help.ubuntu.com/community/CloudInit for more on cloud-init
#
# Override ``IMAGE_URLS`` with a comma-separated list of UEC images.
#  * **oneiric**: http://uec-images.ubuntu.com/oneiric/current/oneiric-server-cloudimg-amd64.tar.gz
#  * **precise**: http://uec-images.ubuntu.com/precise/current/precise-server-cloudimg-amd64.tar.gz

if is_service_enabled g-reg; then
    TOKEN=$(keystone token-get | grep ' id ' | get_field 2)

    # Added by HenryLv
    echo -e "\033[31;42m Check TOKEN: $TOKEN \033[0m"
    read -n 1


    if is_baremetal; then
       echo_summary "Creating and uploading baremetal images"

       # build and upload separate deploy kernel & ramdisk
       upload_baremetal_deploy $TOKEN

       # upload images, separating out the kernel & ramdisk for PXE boot
       for image_url in ${IMAGE_URLS//,/ }; do
           upload_baremetal_image $image_url $TOKEN
       done
    else
       echo_summary "Uploading images"

       # Option to upload legacy ami-tty, which works with xenserver
       if [[ -n "$UPLOAD_LEGACY_TTY" ]]; then
           IMAGE_URLS="${IMAGE_URLS:+${IMAGE_URLS},}https://github.com/downloads/citrix-openstack/warehouse/tty.tgz"
       fi

       for image_url in ${IMAGE_URLS//,/ }; do
           upload_image $image_url $TOKEN
       done
    fi
fi

# If we are running nova with baremetal driver, there are a few
# last-mile configuration bits to attend to, which must happen
# after n-api and n-sch have started.
# Also, creating the baremetal flavor must happen after images
# are loaded into glance, though just knowing the IDs is sufficient here
if is_service_enabled nova && is_baremetal; then
    # create special flavor for baremetal if we know what images to associate
    [[ -n "$BM_DEPLOY_KERNEL_ID" ]] && [[ -n "$BM_DEPLOY_RAMDISK_ID" ]] && \
       create_baremetal_flavor $BM_DEPLOY_KERNEL_ID $BM_DEPLOY_RAMDISK_ID

    # otherwise user can manually add it later by calling nova-baremetal-manage
    [[ -n "$BM_FIRST_MAC" ]] && add_baremetal_node

    if [[ "$BM_DNSMASQ_FROM_NOVA_NETWORK" = "False" ]]; then
        # NOTE: we do this here to ensure that our copy of dnsmasq is running
        sudo pkill dnsmasq || true
        sudo dnsmasq --conf-file= --port=0 --enable-tftp --tftp-root=/tftpboot \
            --dhcp-boot=pxelinux.0 --bind-interfaces --pid-file=/var/run/dnsmasq.pid \
            --interface=$BM_DNSMASQ_IFACE --dhcp-range=$BM_DNSMASQ_RANGE \
            ${BM_DNSMASQ_DNS:+--dhcp-option=option:dns-server,$BM_DNSMASQ_DNS}
    fi
    # ensure callback daemon is running
    sudo pkill nova-baremetal-deploy-helper || true
    screen_it baremetal "nova-baremetal-deploy-helper"
fi

# Added by HenryLv
echo -e "\033[31;42m Save some values \033[0m"
read -n 1

# Save some values we generated for later use
CURRENT_RUN_TIME=$(date "+$TIMESTAMP_FORMAT")
echo "# $CURRENT_RUN_TIME" >$TOP_DIR/.stackenv
for i in BASE_SQL_CONN ENABLED_SERVICES HOST_IP LOGFILE \
  SERVICE_HOST SERVICE_PROTOCOL STACK_USER TLS_IP; do
    echo $i=${!i} >>$TOP_DIR/.stackenv
done


# Run extras
# ==========

# Added by HenryLv
echo -e "\033[31;42m Run extras \033[0m"
read -n 1

if [[ -d $TOP_DIR/extras.d ]]; then
    for i in $TOP_DIR/extras.d/*.sh; do
        [[ -r $i ]] && source $i stack
    done
fi


# Run local script
# ================

# Run ``local.sh`` if it exists to perform user-managed tasks
if [[ -x $TOP_DIR/local.sh ]]; then
    echo "Running user script $TOP_DIR/local.sh"
    $TOP_DIR/local.sh
fi

# Check the status of running services

# Added by HenryLv
echo -e "\033[31;42m Service check \033[0m"
read -n 1

service_check


# Fin
# ===

# Added by HenryLv
echo -e "\033[31;42m Finish install openstack \033[0m"
read -n 1

set +o xtrace

if [[ -n "$LOGFILE" ]]; then
    exec 1>&3
    # Force all output to stdout and logs now
    exec 1> >( tee -a "${LOGFILE}" ) 2>&1
else
    # Force all output to stdout now
    exec 1>&3
fi


# Using the cloud
# ---------------

echo ""
echo ""
echo ""

# If you installed Horizon on this server you should be able
# to access the site using your browser.
if is_service_enabled horizon; then
    echo "Horizon is now available at http://$SERVICE_HOST/"
fi

# Warn that the default flavors have been changed by Heat
if is_service_enabled heat; then
    echo "Heat has replaced the default flavors. View by running: nova flavor-list"
fi

# If Keystone is present you can point ``nova`` cli to this server
if is_service_enabled key; then
    echo "Keystone is serving at $KEYSTONE_AUTH_PROTOCOL://$SERVICE_HOST:$KEYSTONE_SERVICE_PORT/v2.0/"
    echo "Examples on using novaclient command line is in exercise.sh"
    echo "The default users are: admin and demo"
    echo "The password: $ADMIN_PASSWORD"
fi

# Echo ``HOST_IP`` - useful for ``build_uec.sh``, which uses dhcp to give the instance an address
echo "This is your host ip: $HOST_IP"

# Warn that a deprecated feature was used
if [[ -n "$DEPRECATED_TEXT" ]]; then
    echo_summary "WARNING: $DEPRECATED_TEXT"
fi

# Indicate how long this took to run (bash maintained variable ``SECONDS``)
echo_summary "stack.sh completed in $SECONDS seconds."
