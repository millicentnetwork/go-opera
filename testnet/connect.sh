#!/usr/bin/env bash
cd $(dirname $0)
. ./_params.sh

set -e

attach_and_exec() {
    local i=$1
    local CMD=$2
    local RPCP=$(($RPCP_BASE+$i))

    for attempt in $(seq 40)
    do
        if (( attempt > 5 ));
        then 
            echo "  - attempt ${attempt}: " >&2
        fi;

        res=$(../build/demo_opera --exec "${CMD}" attach http://127.0.0.1:${RPCP} 2> /dev/null)
        if [ $? -eq 0 ]
        then
            #echo "success" >&2
            echo $res
            return 0
        else
            #echo "wait" >&2
            sleep 1
        fi
    done
    echo "failed RPC connection to ${NAME}" >&2
    return 1
}

i=$1
j=$2

echo -e "\nConnecting node$i to node$j:\n"

enode=$(attach_and_exec $j 'admin.nodeInfo.enode')
echo "    node$j p2p address = ${enode}"


res=$(attach_and_exec $i "admin.addPeer(${enode})")
echo "    result = ${res}"
