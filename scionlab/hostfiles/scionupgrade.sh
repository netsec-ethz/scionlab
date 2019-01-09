#!/bin/bash

ACCOUNT_ID=$(<"$SC/gen/account_id")
ACCOUNT_SECRET=$(<"$SC/gen/account_secret")
IA=$(<"$SC/gen/ia")

wget https://raw.githubusercontent.com/netsec-ethz/scion-coord/master/scion_upgrade_script.sh -O upgrade.sh
chmod +x upgrade.sh

./upgrade.sh $ACCOUNT_ID $ACCOUNT_SECRET $IA
