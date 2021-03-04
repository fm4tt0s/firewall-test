#!/usr/bin/env bash
#
# author    : felipe mattos
# date      : sep-20
# version   : 0.5
# tested on : linux/sunos
# language  : pirate and bash
#
# purpose   : test firewall rules
# remarks   : check readme
# require   : common sense
#

badword () 
{ 
    echo "${1}
    ${2}"
}

function ncat () {
    [[ $# -eq 0 ]] && badword "Ye Sunk Yer Scallywag" "${FUNCNAME[0]} host:port|host port" && return 1
    local _addr=${1}
    local _port=${2}
    local _timeout="timeout 2"
    if [[ $(echo "${_addr}" | grep -c ":" | bc) -eq 1 ]]; then
        _port=$(echo "${_addr}" | cut -d":" -f2)
        _addr=$(echo "${_addr}" | cut -d":" -f1)
    fi
    [[ -z "${_port}" ]] && badword "Ye Sunk Yer Scallywag" "${FUNCNAME[0]} host:port|host port" && return 1
    # small makeshift to overcome timeout not present on MacOS
    ! [[ $(LC_ALL=C type -t timeout) =~ ^(file|function)$ ]] && unset _timeout
    ${_timeout} bash -c "cat < /dev/null > /dev/tcp/${_addr}/${_port}" 2> /dev/null
}

fwtest () 
{ 
    local _privkey && _privkey=$(grep "BEGIN.*PRIVATE KEY" "${HOME}"/.ssh/id_*);
    [[ -z "${_privkey}" ]] && badword "Aint nay pieces of eight" "Get private keys or walk the plank, mate" && return 1;
    
    local _fwfile="${1}";
    [[ -z "${_fwfile}" ]] && badword "Ye Sunk Yer Scallywag" "${FUNCNAME[0]} firewall_rules_file" && return 1;
    [[ "${#}" -ne 1 ]] && badword "Ye Sunk Yer Scallywag" "${FUNCNAME[0]} firewall_rules_file" && return 1
    [[ ! -f "${_fwfile}" ]] && badword "Ye Sunk Yer Scallywag" "If it only exists" && return 1;
    
    [[ $(grep -o ';' "${_fwfile}" | wc -l | bc) -ne $(echo "$(wc -l < "${_fwfile}" | bc) * 2" | bc) ]] && badword "Avast Ye Mate" "${_fwfile} is barnacle-covered (malformed)" && return 1;
    [[ $(grep -c " " "${_fwfile}") -ne 0 ]] && badword "Avast Ye Mate" "${_fwfile} is barnacle-covered (malformed)" && return 1;
    
    local _elapsed_time && SECONDS=0;
    local _totalCount=0 _openCount=0 _closedCount=0 _refusedCound=0 _unkCount=0 _unreachCount=0 _noaccCount=0;
    local _logfile && _logfile="${HOME}/result.fwtest.$(uuidgen -t | cut -d'-' -f1).log";
    for _irule in $(grep -v '^ *#' "${_fwfile}");
    do
        _source=$(echo "${_irule}" | cut -d\; -f1 | tr '[:upper:]' '[:lower:]');
        _dest=$(echo "${_irule}" | cut -d\; -f2 | tr '[:upper:]' '[:lower:]');
        _port=$(echo "${_irule}" | cut -d\; -f3);
        if [[ "${_source}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            _sip="${_source}";
        else
            _sip=$(nslookup "${_source}" | grep Address | tail -1 | cut -d':' -f2- | tr -d " ");
        fi;
        [[ $(echo "${_source}" | grep -ic "^...a") -ne 0 ]] && _sourceAIX="1";
        if [[ "${_dest}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            _dip="${_dest}";
        else
            _dip=$(nslookup "${_dest}" | grep Address | tail -1 | cut -d':' -f2- | tr -d " ");
        fi;
        export _source _dip _sip _dest _port;
	if [[ "${_sip}" =~ \#53$ ]]; then
            _sip="DNS ERROR"
        fi

        if [[ "${_sip}" =~ \#53$ ]]; then
            _dip="DNS ERROR"
        fi

        printf "%s" "${_source} (${_sip}) > ${_dest}(${_dip}):${_port} - ";
        printf "%s" "${_source} (${_sip}) > ${_dest}(${_dip}):${_port} - " >> "${_logfile}";

	if [[ "${_sip}" ==  "DNS ERROR" ]]; then
            echo "ERROR: ${_source} is unreacheable" | tee -a "${_logfile}"
            ((_unreachCount++))
            ((_totalCount++))
            continue
        fi

        if [[ "${_dip}" ==  "DNS ERROR" ]]; then
            echo "ERROR: ${_dest} is unreacheable" | tee -a "${_logfile}"
            ((_unreachCount++))
            ((_totalCount++))
            continue
        fi
        
        if ! ncat "${_source}:22"; then
            echo "ERROR: ${_source} is unreacheable" | tee -a "${_logfile}";
            ((_unreachCount++));
            ((_totalCount++));
            continue;
        fi;
        if [[ "${_sourceAIX}" -eq 1 ]]; then
            _sockRes=$(/usr/bin/timeout 3s ssh -q -oLogLevel=QUIET -oStrictHostKeyChecking=no -oLogLevel=QUIET -oPreferredAuthentications=publickey -oPasswordAuthentication=no -oPubkeyAuthentication=yes "${_source}" "export TERM=vt100; echo -e '\035\nquit' | telnet $_dip $_port && return 0 || return 124 2>&1");
            unset _sourceAIX;
        else
            _sockRes=$(/usr/bin/timeout 3s ssh -q -oLogLevel=QUIET -oStrictHostKeyChecking=no -oLogLevel=QUIET -oPreferredAuthentications=publickey -oPasswordAuthentication=no -oPubkeyAuthentication=yes "${_source}" "bash -c 'cat < /dev/null > /dev/tcp/$_dip/$_port' 2>&1");
        fi;
        case $? in 
            0)
                echo "open/connected" && echo "open/connected" >> "${_logfile}";
                ((_openCount++))
            ;;
            124)
                echo "closed/timeout" && echo "closed/timeout" >> "${_logfile}";
                ((_closedCount++))
            ;;
            1)
                if [[ $(echo "${_sockRes}" | grep -c "Connection refused" | bc) -ge 1 ]]; then
                    echo "open/refused" && echo "open/refused" >> "${_logfile}";
                    ((_refusedCound++));
                else
                    echo "$? unknown ${_sockRes}";
                    ((_unkCount++)) && echo "unknown ${_sockRes}" >> "${_logfile}";
                fi
            ;;
            255)
                if [[ -z "${_sockRes}" ]]; then
                    echo "not tested/no access to source" && echo "not tested/no access to source" >> "${_logfile}";
                    ((_noaccCount++));
                fi
            ;;
            *)
                echo "$? unknown ${_sockRes}" && echo "unknown ${_sockRes}" >> "${_logfile}";
                ((_unkCount++))
            ;;
        esac;
        ((_totalCount++));
    done;
    
    unset _source _dip _sip _dest _port;
    
    _elapsed_time="${SECONDS}";
    
    echo | tee -a "${_logfile}";
    echo "-------------- fwtest  results -------------" | tee -a "${_logfile}";
    echo "--------------------------------------------" | tee -a "${_logfile}";
    echo "rules tested              ${_totalCount}" | tee -a "${_logfile}";
    echo "elapsed                   $((_elapsed_time / 60))m $((_elapsed_time % 60))s" | tee -a "${_logfile}";
    echo "--------------------------------------------" | tee -a "${_logfile}";
    echo "open/connected            ${_openCount}" | tee -a "${_logfile}";
    echo "open/refused              ${_refusedCound}" | tee -a "${_logfile}";
    echo "closed/timeout            ${_closedCount}" | tee -a "${_logfile}";
    echo "--------------------------------------------" | tee -a "${_logfile}";
    echo "source unreacheable       ${_unreachCount}" | tee -a "${_logfile}";
    echo "not tested/no access      ${_noaccCount}" | tee -a "${_logfile}";
    echo "unknown                   ${_unkCount}" | tee -a "${_logfile}";
    echo "--------------------------------------------" | tee -a "${_logfile}";
    echo "log file: ${_logfile}" | tee -a "${_logfile}";
    echo "--------------------------------------------" | tee -a "${_logfile}";
    echo | tee -a "${_logfile}"
}

fwtest "${1}"
