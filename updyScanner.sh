#!/bin/bash
# ==================================== USAGE ====================================
# Multi-Linux Support: Fedora, Oracle Linux, CentOS, RedHat, Amazon Linux 2, Raspbian, Debian, Ubuntu, alpine, openSUSE, SUSE Enterprise.

LOGFILE="./updy_scan.log"

function usage { 
    echo "Usage: $0 [-k import_key] [-i site_id] [-t user_tag] [-n hostname]
            -k                  Optional user import key. If both import key and site ID are present, the script will automatically upload scanned results; otherwise a scanResults.json file is generated for manual upload.
            -i                  Optional site ID that the scanned machine belongs to. If both import key and site ID are present, the script will automatically upload scanned results; otherwise a scanResults.json file is generated for manual upload.
            -t                  Optional user tag for the scanned machine.
            -n                  Optional name for the scanned machine, hostname is used if this is not provided.
    " 1>&2; 
    exit 1; 
}

function log {
    echo -n `date`
    echo " | "$*
    echo -n `date` >> $LOGFILE
    echo " | "$* >> $LOGFILE
}

function fail {
    log " Failed:"$1
    echo $1
    exit 1
}

function trim {
    TRIMED=`echo "$1" | sed -n 's/^[[:blank:]]*\(.*\)/\1/ ; s/[[:blank:]]*$//p'`
}

function trim_and_to_lower {
    TRIMED=`echo "$1" | sed -n 's/^[[:blank:]]*\(.*\)/\L\1/ ; s/[[:blank:]]*$//p'`
}

function split_lines {
    SAVEIFS=$IFS
    IFS=$'\n'
    SPLITED=($1)
    IFS=$SAVEIFS
}

function split_version {
    SAVEIFS=$IFS
    IFS=$'. \t\n'
    SPLITED=($1)
    IFS=$SAVEIFS
}

function stringContain { [ -z "$1" ] || { [ -z "${2##*$1*}" ] && [ -n "$2" ];};}


function detectRedhatBased {
    #   ========Fedora Detection========
    RELCHECK=`cat /etc/fedora-release 2>/dev/null`
    RET=$? # returns 0 if path exists, else return 1
    if [ $RET -eq 0 ]; then
        #   e.g.
		#   Fedora release 32 (Thirty Two)
        log "/etc/fedora-release = ${RELCHECK}"
        trim_and_to_lower "${RELCHECK}"
        RELARR=(${TRIMED})
        if [ ${#RELARR[@]} -gt 2 ] && [ "${RELARR[0]}" == "fedora" ]; then
            OSNAME="fedora"
            OSVER=`echo "${RELCHECK}" | sed -n 's/^.*release[[:space:]]\+\([[:alnum:].]\+\).*$/\1/p'`
            PKGFORMAT=rpm
            return
        else
            log "Failed to parse Fedora version: ${RELCHECK}"
            OSNAME="fedora"
            OSVER="version_unknown"
            PKGFORMAT=rpm
            return
        fi
    fi
    #   ======== Oracle Detection========
    #   Need to discover Oracle Linux first, because it provides an
	#   /etc/redhat-release that matches the upstream distribution
    RELCHECK=`cat /etc/oracle-release 2>/dev/null`
    RET=$? # returns 0 if path exists, else return 2
    if [ $RET -eq 0 ]; then
        #   e.g.
		#   Oracle Linux Server release 8.2
        log "/etc/oracle-release = ${RELCHECK}"
        REGEX_MATCHES=`echo "${RELCHECK}" | sed -n 's/^\(.*\)[[:space:]]release[[:space:]]\([[:digit:]][[:digit:].]*\).*/\1\n\2/p'`
        split_lines "${REGEX_MATCHES}"
        if [ ${#SPLITED[@]} -eq 2 ]; then
            OSNAME="oracle"
            OSVER="${SPLITED[1]}"
            PKGFORMAT=rpm
            return
        else
            log "Failed to parse Oracle version: ${RELCHECK}"
            OSNAME="oracle"
            OSVER="version_unknown"
            return
        fi
    fi

    #   ======== CentOS cloud image Detection========
    RELCHECK=`cat /etc/centos-release 2>/dev/null`
    RET=$? # returns 0 if path exists, else return 2
    if [ $RET -eq 0 ]; then
        log "/etc/centos-release = ${RELCHECK}"
        REGEX_MATCHES=`echo "${RELCHECK}" | sed -n 's/^\(.*\)[[:space:]]release[[:space:]]\([[:digit:]][[:digit:].]*\).*/\1\n\2/p'`
        trim_and_to_lower "${REGEX_MATCHES}"
        split_lines "${TRIMED}"
        if [ ${#SPLITED[@]} -eq 2 ]; then
            if [ "${SPLITED[0]}" == "centos" ] || [ "${SPLITED[0]}" == "centos linux" ]; then
                OSNAME="centos"
                OSVER="${SPLITED[1]}"
                PKGFORMAT=rpm
                return
            else
                log "Failed to parse CentOS: ${RELCHECK}"
            fi
        else
            log "Failed to parse CentOS version: ${RELCHECK}"
            OSNAME="centos"
            OSVER= "version_unknown"
            PKGFORMAT=rpm
            return
        fi
    fi

    #   ======== Red Hat Detection========
    RELCHECK=`cat /etc/redhat-release 2>/dev/null`
    RET=$? # returns 0 if path exists, else return 2
    if [ $RET -eq 0 ]; then
        #   e.g.
		#   Oracle Linux Server release 8.2
        log "/etc/redhat-release = ${RELCHECK}"
        REGEX_MATCHES=`echo "${RELCHECK}" | sed -n 's/^\(.*\)[[:space:]]release[[:space:]]\([[:digit:]][[:digit:].]*\).*/\1\n\2/p'`
        trim_and_to_lower "${REGEX_MATCHES}"
        split_lines "${TRIMED}"
        if [ ${#SPLITED[@]} -eq 2 ]; then
            if [ "${SPLITED[0]}" == "centos" ] || [ "${SPLITED[0]}" == "centos linux" ]; then
                OSNAME="centos"
                OSVER="${SPLITED[1]}"
                PKGFORMAT=rpm
                return
            else
                OSNAME="redhat"
                OSVER="${SPLITED[1]}"
                PKGFORMAT=rpm
                return
            fi
        else
            log "Failed to parse RedHat/CentOS version: ${RELCHECK}"
            OSNAME="centos"
            OSVER="version_unknown"
            PKGFORMAT=rpm
            return
        fi
    fi

    #   ======== Amazon Linux 2 Detection========
    RELCHECK=`cat /etc/system-release 2>/dev/null`
    RET=$?
    if [ $RET -eq 0 ]; then
        #   e.g.
        #   Amazon Linux release 2 (Karoo)
        log "/etc/system-release = ${RELCHECK}"
        RELARR=(${RELCHECK})
        if [[ ${#RELARR[@]} -ge 4 ]] && [[ "${RELARR[@]:0:4}" == "Amazon Linux release 2" ]]; then
            OSNAME="amazon"
            OSVER="${RELARR[@]:3:2}"
            PKGFORMAT=rpm
            return
        elif [[ ${#RELARR[@]} -ge 3 ]] && [[ "${RELARR[@]:0:3}" == "Amazon Linux 2" ]]; then
            OSNAME="amazon"
            OSVER="${RELARR[@]:2}"
            PKGFORMAT=rpm
            return
        elif [[ ${#RELARR[@]} -eq 5 ]]; then
            OSNAME="amazon"
            OSVER="${RELARR[4]}"
            PKGFORMAT=rpm
            return
        fi
    fi

    log "Not Redhat-based Linux."
}

function detectDebianBased {
    DEBCHECK=`ls /etc/debian_version 2>/dev/null`
    RET=$?
    if [ $RET -eq 0 ]; then
        #   ========Raspbian Detection========
        #   lsb_release in Raspbian Jessie returns 'Distributor ID: Raspbian'.
        #   However, lsb_release in Raspbian Wheezy returns 'Distributor ID: Debian'.
        ISSCHECK=`cat /etc/issue 2>/dev/null`
        #   e.g.
		#   Raspbian GNU/Linux 7 \n \l
        RET=$?
        if [ $RET -eq 0 ]; then
            log "/etc/issue = ${ISSCHECK}"
            ISSARR=(${ISSCHECK})
            if [ ${#ISSARR[@]} -gt 2 ] && [ "${ISSARR[0]}" == "raspbian" ]; then
                trim_and_to_lower "${ISSARR[0]}"
                OSNAME="${TRIMED}"
                trim "${ISSARR[2]}"
                OSVER="${TRIMED}"
                PKGFORMAT="dpkg"
                return
            fi
        fi
        #  ========lsb_release Debian Detection========
		#  e.g. 
        #  root@fa3ec524be43:/# lsb_release -ir
		#  Distributor ID:	Ubuntu
		#  Release:	14.04
        LSBRELCHECK=`lsb_release -ir 2>/dev/null`
        RET=$?
        if [ $RET -eq 0 ]; then
            log "lsb_release -ir = ${LSBRELCHECK}"
            trim "${LSBRELCHECK}"
            LSBRELCHECK="${TRIMED}"
            REGEX_MATCHES=`echo "${LSBRELCHECK}" | sed -n 'N;s/^Distributor ID:[[:space:]]*\(.\+\?\)\n*Release:[[:space:]]*\(.\+\?\)$/\1\2/p'`
            split_lines "${REGEX_MATCHES}"
            if [ ${#SPLITED[@]} -eq 0 ]; then
                OSNAME="debian/ubuntu"
                OSVER="unknown"
                PKGFORMAT="dpkg"
                log "Unknown Debian/Ubuntu version. lsb_release -ir: ${LSBRELCHECK}"
            else
                trim_and_to_lower "${SPLITED[0]}"
                OSNAME="${TRIMED}"
                trim "${SPLITED[1]}"
                OSVER="${TRIMED}"
                PKGFORMAT="dpkg"
            fi
            return
        fi
        #  ========cat /etc/lsb-release Debian Detection========
		#  e.g.
		#  DISTRIB_ID=Ubuntu
		#  DISTRIB_RELEASE=14.04
		#  DISTRIB_CODENAME=trusty
		#  DISTRIB_DESCRIPTION="Ubuntu 14.04.2 LTS"
        LSBCATCHECK=`cat /etc/lsb-release 2>/dev/null`
        RET=$?
        if [ $RET -eq 0 ]; then
            log "/etc/lsb-release = ${LSBCATCHECK}"
            trim "${LSBCATCHECK}"
            LSBCATCHECK="${TRIMED}"
            REGEX_MATCHES=`echo "${LSBCATCHECK}" | sed -n 'N;s/^DISTRIB_ID=\(.\+\?\)\n*DISTRIB_RELEASE=\(.\+\?\)\n*$/\1\2/p'`
            split_lines "${REGEX_MATCHES}"
            if [ ${#SPLITED[@]} -eq 0 ]; then
                OSNAME="debian/ubuntu"
                OSVER="unknown"
                PKGFORMAT="dpkg"
                log "Unknown Debian/Ubuntu. cat /etc/lsb-release: ${LSBCATCHECK}"
            else
                trim_and_to_lower "${SPLITED[0]}"
                OSNAME="${TRIMED}"
                trim "${SPLITED[1]}"
                OSVER="${TRIMED}"
                PKGFORMAT="dpkg"
            fi
            return
        fi
        #  ========cat /etc/debian_version Debian Detection========
		#  e.g.
		#  buster/sid
        DEBVERCHECK=`cat /etc/debian_version 2>/dev/null`
        RET=$?
        if [ $RET -eq 0 ]; then
            log "/etc/debian_version = ${DEBVERCHECK}"
            trim "${DEBVERCHECK}"
            DEBVERCHECK="${TRIMED}"
            OSNAME="debian"
            OSVER="${DEBVERCHECK}"
            PKGFORMAT="dpkg"
            return
        fi
    else
        log "Not Debian like Linux."
    fi
}

function detectAlpine {
    #  ========Alpine Detection========
    #  e.g. 3.12.0
    #  TODO test alpine
    ALPINECHECK=`cat /etc/alpine-release 2>/dev/null`
    RET=$?
    if [ $RET -eq 0 ]; then
        log "/etc/alpine-release = ${ALPINECHECK}"
        trim "${ALPINECHECK}"
        OSNAME="alpine"
        OSVER="${TRIMED}"
        PKGFORMAT="apk"
        return
    else
        log "Not Alpine Linux."
    fi
}

function detectSUSE {
    RELCHECK=`ls /etc/os-release 2>/dev/null`
    RET=$?
    SUSERELCHECK=`ls /etc/SuSE-release 2>/dev/null`
    RET2=$?
    if [ $RET -eq 0 ]; then
        ZYPPER=`zypper -V 2>/dev/null`
        RET=$?
        if [ $RET -eq 0 ]; then
            log "zypper -V = ${ZYPPER}"
            RELCHECK=`cat /etc/os-release 2>/dev/null`
            RET=$?
            if [ $RET -eq 0 ]; then
                log "/etc/os-release = ${RELCHECK}"
                if stringContain "opensuse" "${RELCHECK}"; then
                    #=============== OpenSuse Example ============
                    # NAME="openSUSE Leap"
                    # VERSION="15.0"
                    # ID="opensuse-leap"
                    # ID_LIKE="suse opensuse"
                    # VERSION_ID="15.0"
                    # PRETTY_NAME="openSUSE Leap 15.0"
                    # ANSI_COLOR="0;32"
                    # CPE_NAME="cpe:/o:opensuse:leap:15.0"
                    # BUG_REPORT_URL="https://bugs.opensuse.org"
                    # HOME_URL="https://www.opensuse.org/"
                    OSNAME="opensuse"
                elif stringContain "NAME=\"SLES\"" "${RELCHECK}"; then
                    #=============== SUSE Linux Enterprise Example ============
                    # NAME="SLES"
                    # VERSION="12"
                    # VERSION_ID="12"
                    # PRETTY_NAME="SUSE Linux Enterprise Server 12"
                    # ID="sles"
                    # ANSI_COLOR="0;32"
                    # CPE_NAME="cpe:/o:suse:sles:12"
                    OSNAME="suse.linux.enterprise.server"
                elif stringContain "NAME=\"SLES_SAP\"" "${RELCHECK}"; then
                    OSNAME="suse.linux.enterprise.server"
                else
                    log "Failed to parse SUSE edition: ${RELCHECK}"
                    return
                fi
                REGEX_MATCHES=`echo "${RELCHECK}" | sed -n 's/.*VERSION_ID=\"\(.\+\)\".*/\1/p'`
                MATCHEARR=("${REGEX_MATCHES}")
                if [ "${#MATCHEARR[@]}" -eq 0 ]; then
                    log "Failed to parse SUSE Linux version: ${RELCHECK}"
                    return
                fi
                OSVER="${MATCHEARR[0]}"
                PKGFORMAT="rpm"
            fi
        fi
    elif [ $RET2 -eq 0 ]; then
        ZYPPER=`zypper -V 2>/dev/null`
        RET=$?
        if [ $RET -eq 0 ]; then
            log "zypper -V = ${ZYPPER}"
            SUSERELCHECK=`cat /etc/SuSE-release 2>/dev/null`
            RET=$?
            if [ $RET -eq 0 ]; then
                log "/etc/SuSE-release = ${SUSERELCHECK}"
                REGEX_MATCHES=`echo "${SUSERELCHECK}" | sed -n 's/.*openSUSE \([[:digit:]]\+[[:digit:].]*\).*/\1/p'`
                MATCHEARR=("${REGEX_MATCHES}")
                if [ "${#MATCHEARR[@]}" -gt 0 ]; then
                    OSNAME="opensuse"
                    OSVER="${MATCHEARR[0]}"
                    PKGFORMAT="rpm"
                    return
                fi
                VERSION_MATCH=`echo "${SUSERELCHECK}" | sed -n 's/.*VERSION = \([[:digit:]]\+\).*/\1/p'`
                VERSIONARR=("${VERSION_MATCH}")
                if [ "${#VERSIONARR[@]}" -gt 0 ]; then
                    PATCH_MATCH=`echo "${SUSERELCHECK}" | sed -n 's/.*PATCHLEVEL = \([[:digit:]]\+\).*/\1/p'`
                    PATCHARR=("${PATCH_MATCH}")
                    if [ "${#PATCHARR[@]}" -gt 0 ]; then
                        OSNAME="suse.linux.enterprise.server"
                        OSVER="${VERSIONARR[0]}.${PATCHARR[0]}"
                        PKGFORMAT="rpm"
                        return
                    fi
                fi
                log "Failed to parse SUSE Linux version: ${SUSERELCHECK}"
                return
            fi
        fi
    fi
    log "Not SUSE Linux."
}

function get_hostname {
    PROFILENAME=`cat /proc/sys/kernel/hostname 2>/dev/null`
    RET=$?
    if [ $RET -ne 0 ]; then
        log "Failed to read hostname: ${PROFILENAME}"
        PROFILENAME="unknown_hostname"
    fi
}

function get_machineid {
    MACHINEID=`cat /etc/machine-id 2>/dev/null`
    RET=$?
    if [ $RET -ne 0 ]; then
        log "Failed to read machine id: ${MACHINEID}"
        MACHINEID="unknown_machineID"
    fi
}

function dpkg_scan_package {
    log "Scanning installed packages with dpkg-query."
    if [ $PKGFORMAT == 'dpkg' ]; then
        dpkgQuery=$(dpkg-query -W -f="\${binary:Package},\${db:Status-Abbrev},\${Version},\${Source},\${source:Version}\n")
        PACKAGE_ATTRIBUTES=`echo "${dpkgQuery}" | sed -n '$ ! s/\([^,]\+\),\([^,]\+\),\([^,]\+\),\([^,]*\),\([^,]\+\)$/\t\t{\n\t\t\t"name": "\1",\n\t\t\t"version": "\3"\n\t\t},/p; $ s/\([^,]\+\),\([^,]\+\),\([^,]\+\),\([^,]*\),\([^,]\+\)$/\t\t{\n\t\t\t"name": "\1",\n\t\t\t"version": "\3"\n\t\t}/p'`
    fi
}

function rpm_scan_package {
    log "Scanning installed packages with rpm."
    if [ "$PKGFORMAT" == 'rpm' ]; then
        if [ "${OSNAME}" == "suse.linux.enterprise.server" ]; then
            split_version "${OSVER}"
            if [ ${#SPLITED[@]} -gt 0 ] && [[ ${SPLITED[0]} =~ ^-?[0-9]+$ ]] && [ ${SPLITED[0]} -lt 12 ]; then
                RPMRESULT=$(rpm -qa --queryformat "%{NAME};%{EPOCH};%{VERSION};%{RELEASE};%{ARCH}\n")
                PACKAGE_ATTRIBUTES=`echo "${RPMRESULT}" | sed -n '$ ! s/\([^;]*\);\([^;]*\);\([^;]*\);\([^;]*\);\([^;]*\).*$/\t\t{\n\t\t\t"name": "\1",\n\t\t\t"version": "\3"\n\t\t},/p; $ s/\([^;]*\);\([^;]*\);\([^;]*\);\([^;]*\);\([^;]*\).*/\t\t{\n\t\t\t"name": "\1",\n\t\t\t"version": "\3"\n\t\t}/p'`
            else
                RPMRESULT=$(rpm -qa --queryformat "%{NAME};%{EPOCHNUM};%{VERSION};%{RELEASE};%{ARCH}\n")
                PACKAGE_ATTRIBUTES=`echo "${RPMRESULT}" | sed -n '$ ! s/\([^;]*\);\([^;]*\);\([^;]*\);\([^;]*\);\([^;]*\).*$/\t\t{\n\t\t\t"name": "\1",\n\t\t\t"version": "\3"\n\t\t},/p; $ s/\([^;]*\);\([^;]*\);\([^;]*\);\([^;]*\);\([^;]*\).*/\t\t{\n\t\t\t"name": "\1",\n\t\t\t"version": "\3"\n\t\t}/p'`
            fi
        else
            split_version "${OSVER}"
            if [ ${#SPLITED[@]} -gt 0 ] && [[ ${SPLITED[0]} =~ ^-?[0-9]+$ ]] && [ ${SPLITED[0]} -lt 6 ]; then
                RPMRESULT=$(rpm -qa --queryformat "%{NAME};%{EPOCH};%{VERSION};%{RELEASE};%{ARCH}\n")
                PACKAGE_ATTRIBUTES=`echo "${RPMRESULT}" | sed -n '$ ! s/\([^;]*\);\([^;]*\);\([^;]*\);\([^;]*\);\([^;]*\).*$/\t\t{\n\t\t\t"name": "\1",\n\t\t\t"version": "\3"\n\t\t},/p; $ s/\([^;]*\);\([^;]*\);\([^;]*\);\([^;]*\);\([^;]*\).*/\t\t{\n\t\t\t"name": "\1",\n\t\t\t"version": "\3"\n\t\t}/p'`
            else
                RPMRESULT=$(rpm -qa --queryformat "%{NAME};%{EPOCHNUM};%{VERSION};%{RELEASE};%{ARCH}\n")
                PACKAGE_ATTRIBUTES=`echo "${RPMRESULT}" | sed -n '$ ! s/\([^;]*\);\([^;]*\);\([^;]*\);\([^;]*\);\([^;]*\).*$/\t\t{\n\t\t\t"name": "\1",\n\t\t\t"version": "\3"\n\t\t},/p; $ s/\([^;]*\);\([^;]*\);\([^;]*\);\([^;]*\);\([^;]*\).*/\t\t{\n\t\t\t"name": "\1",\n\t\t\t"version": "\3"\n\t\t}/p'`
            fi
        fi
    fi
}

function apk_scan_package {
    log "Scanning installed packages with apk."
    if [ $PKGFORMAT == 'apk' ]; then
        apkQuery=$(apk info -v)
        PACKAGE_ATTRIBUTES=`echo "${apkQuery}" | sed -n '$ ! s/\(.*\)-\([[:alnum:].]*\)-\([[:alnum:].]*\)$/\t\t{\n\t\t\t"name": "\1",\n\t\t\t"version": "\2-\3"\n\t\t}/p'`
    fi
}


function make_upload_json_file {
    log "Creating scan results file for upload."
    # PACKAGE_ATTRIBUTES
    # { 
    #   "name": "accountsservice",
    #   "version": "0.6.45-1ubuntu1",
    # }
    JSON="{
    \"name\": \"${PROFILENAME}-${MACHINEID}\",
    \"os\": \"${OSNAME}-${OSVER}\",
    \"packages\":
        [
${PACKAGE_ATTRIBUTES}
        ],
    \"tags\": [
        \"${TAGS}\"
    ]
}"
    echo "$JSON" > scanResults.json
}

function installCurl {
    #
    # Ensure curl is available
    #
    type curl > /dev/null 2>&1
    if [[ $? != 0 ]]; then
        log "Curl not installed"
        log "Installing curl"
        if [[ "$PKGFORMAT" == 'rpm' ]]; then
            type zypper &>/dev/null
            if [[ $? -eq 0 ]]; then
                # sles based
                stdbuf -o 0 zypper in -y -l curl 2>&1 | tee -a ${LOGFILE}
            else
                stdbuf -o 0 yum install -y curl 2>&1 | tee -a ${LOGFILE}
            fi
        elif [[ "$PKGFORMAT" == 'dpkg' ]]; then
            apt-get install -y curl 2>&1 | tee -a  ${LOGFILE}
        elif [[ "$PKGFORMAT" == 'apk' ]]; then
            apk add curl 2>&1 | tee -a  ${LOGFILE}
        fi
    fi
    # Re-check
    type curl > /dev/null 2>&1

    if [[ $? != 0 ]]; then
        fail "Curl installation failed"
    fi
}

function upload_profile {
    log "Uploading scan results with curl."
    IMPORT_URL="http://import.10.0.2.100.nip.io/?site_id=${SITE_ID}"
    CURLRET=$(curl -H "X-IMPORT-KEY: ${IMPORT_KEY}" --request POST --data @scanResults.json --cookie-jar cookies.txt "${IMPORT_URL}")
    PROFILEID=`echo "${CURLRET}" | sed -n 's/.*\("id":\)"\([[:alnum:]-]*\)".*/\2/p'`
}

function scan_and_upload {
    if [[ "${OSNAME}" == "unknown" ]]; then
        detectDebianBased
    fi
    if [[ "${OSNAME}" == "unknown" ]]; then
        detectRedhatBased
    fi
    if [[ "${OSNAME}" == "unknown" ]]; then
        detectAlpine
    fi
    if [[ "${OSNAME}" == "unknown" ]]; then
        detectSUSE
    fi
    log "OS Detection Results:"
    log "OSNAME=${OSNAME}"
    log "OSVER=${OSVER}"
    log "PKGFORMAT=${PKGFORMAT}"

    if [[ "${PKGFORMAT}" == "dpkg" ]]; then
        dpkg_scan_package
    elif [[ "${PKGFORMAT}" == "rpm" ]]; then
        rpm_scan_package
    elif [[ "${PKGFORMAT}" == "apk" ]]; then
        apk_scan_package
    fi

    if [ "${PACKAGE_ATTRIBUTES}" != "unknown" ]; then
        make_upload_json_file
        if [ "${MODE}" != "manual" ]; then
            installCurl
            upload_profile
            if [ -z "${PROFILEID}" ]; then
                log "Failed to obtain the returned profile ID."
                log "========================================================"
                log "| Please upload ./scanResults.json to updy.io manually |"
                log "========================================================"
            else
                log "Scan and upload succesful."
                log "This machine's assigned profile ID: ${PROFILEID}"
            fi
        else
            log "Scan completes"
            log "========================================================"
            log "| Please upload ./scanResults.json to updy.io manually |"
            log "========================================================"
        fi
    fi
}

#====================Parse Arguments===================
while getopts "k:i:t:n:" o; do
    case "${o}" in
        k)
            IMPORT_KEY=${OPTARG}
            ;;
        i)
            SITE_ID=${OPTARG}
            ;;
        t)
            TAGS=${OPTARG}
            ;;
        n)
            PROFILENAME=${OPTARG}
            ;;        
        *)
            usage
            ;;
    esac
done
shift $((OPTIND-1))


if [ -z "${IMPORT_KEY}" ] || [ -z "${SITE_ID}" ]; then
    log "NOTE: Without providing [import key] and [site ID] parameters, scan results need to be uploaded to updy.io web portal manually."
    MODE="manual"
else
    log "IMPORT_KEY = ${IMPORT_KEY}"
    log "SITE_ID = ${SITE_ID}"
    log "Received [import key] and [site ID] parameters, scan results will be uploaded automatically."
fi
if [ ! -z "${TAGS}" ]; then
    log "Scan results will be given the user tag '${TAGS}'"
fi
if [ ! -z "${PROFILENAME}" ]; then
    log "User defined hostname '${PROFILENAME}' is given to override scanned hostname."
fi

#====================Initialize Variables===================
OSNAME="unknown"
OSVER="unknown"
PKGFORMAT="unknown"
PACKAGE_ATTRIBUTES="unknown"

#==================== Scan and Upload ===================
if [ -z "${PROFILENAME}" ]; then
    get_hostname
fi
get_machineid
scan_and_upload