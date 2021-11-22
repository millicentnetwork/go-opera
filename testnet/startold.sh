#!/usr/bin/env bash
cd $(dirname $0)
. ./_params.sh

set -e

attach_and_exec() {
    local i=$1
    local CMD=$2
    local RPCP=$(($RPCP_BASE+$i))

    echo "i = " 
    echo $i
    echo "CMD "
    echo $CMD
    echo "RPCP "
    echo $RPCP

    for attempt in $(seq 40)
    do
        if (( attempt > 5 ));
        then 
            echo "  - attempt ${attempt}: " >&2
        fi;

        res=$(../build/opera --exec "${CMD}" attach http://127.0.0.1:${RPCP} 2> /dev/null)
        echo "setting up res"
	echo $res
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
echo -e "\nStart node$i:\n"

go build -o ../build/opera ../cmd/opera



DATADIR="${PWD}/opera$i.datadir"
rm -fr ${DATADIR}
mkdir -p ${DATADIR}
echo " i === "
echo $i
IP=$(curl --silent checkip.amazonaws.com)
PORT=$(($PORT_BASE+$i))
RPCP=$(($RPCP_BASE+$i))
WSP=$(($WSP_BASE+$i))
ACC=$(($i+1))
(../build/opera \
--datadir=${DATADIR} \
--genesis="/tmp/genesis.g" \
--fakenet=${ACC}/$N \
--port=${PORT} \
--nat extip:${IP} \
--http --http.addr="0.0.0.0" --http.port=${RPCP} --http.corsdomain="*" --http.api="eth,debug,net,admin,web3,personal,txpool,ftm,dag" \
--ws --ws.addr="0.0.0.0" --ws.port=${WSP} --ws.origins="*" --ws.api="eth,debug,net,admin,web3,personal,txpool,ftm,dag" \
--nousb --verbosity=3 --tracing &>> opera$i.log)&

echo -e "\tnode$i Ok"

enode=$(attach_and_exec $i 'admin.nodeInfo.enode')
echo "    p2p address = ${enode}"
    
    
