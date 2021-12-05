#!/bin/bash

KCADM=$JBOSS_HOME/bin/kcadm.sh
REALM_NAME=demorealm
CLIENT_ID=ipax_client_id
CLIENT_SECRET=ipax_client_secret
USER_NAME=demo
USER_PASS=demo

for i in {1..10}; do
    $KCADM config credentials --server http://localhost:8080/auth --realm master --user $KEYCLOAK_USER --password $KEYCLOAK_PASSWORD
    custom_realm=$($KCADM get realms/$REALM_NAME)
    if [ -z "$custom_realm" ]; then
        $KCADM create realms -s realm="${REALM_NAME}" -s enabled=true -s registrationAllowed=true

        $KCADM create clients -r $REALM_NAME -s clientId=$CLIENT_ID -s secret=$CLIENT_SECRET -s 'redirectUris=["http://localhost/redirect_uri","http://localhost/logoutSuccess"]'

        $KCADM create users -r $REALM_NAME -s username=$USER_NAME -s enabled=true
        $KCADM set-password -r $REALM_NAME --username $USER_NAME --new-password $USER_PASS
    else
        echo "The custom realm already exists."
        exit
    fi
    sleep 5s
done
