#!/bin/bash

echo "start import in its own process"
/opt/jboss/custom-scripts/import.sh &> /dev/null & disown
