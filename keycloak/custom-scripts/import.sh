#!/bin/bash

KCADM=$JBOSS_HOME/bin/kcadm.sh
REALM_NAME=demorealm

for i in {1..10}; do
    $KCADM config credentials --server http://localhost:8080/auth --realm master --user $KEYCLOAK_USER --password $KEYCLOAK_PASSWORD
    custom_realm=$($KCADM get realms/$REALM_NAME)
    if [ -z "$custom_realm" ]; then
        echo "Importing custom realm."
        $KCADM create realms -f /opt/jboss/keycloak/objects/realm.json

        echo "Importing clients."
        for f in /opt/jboss/keycloak/objects/clients/*.json; do
            $KCADM create clients -r $REALM_NAME -f $f
        done

        echo "Importing users."
        for f in /opt/jboss/keycloak/objects/users/*.json; do
            $KCADM create users -r $REALM_NAME -f $f
        done
    else
        echo "Custom realm $REALM_NAME already exists."
        exit
    fi
    sleep 5s
done
