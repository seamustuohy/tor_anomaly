#!/usr/bin/env bash
#
# This file is part of tor_anomaly, a rewite of tor's detector codebase focused on readability.
# Copyright © 2015 seamus tuohy, <stuohy@internews.org>
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the included LICENSE file for details.

# Setup

#Bash should terminate in case a command or chain of command finishes with a non-zero exit status.
#Terminate the script in case an uninitialized variable is accessed.
#See: https://github.com/azet/community_bash_style_guide#style-conventions
set -e
set -u
set -x

# Read Only variables

readonly PROG_DIR=$(readlink -m $(dirname $0))
#readonly readonly PROGNAME=$(basename )
#readonly PROGDIR=$(readlink -m $(dirname ))




main() {
    cd $PROG_DIR
    git checkout data
    git pull
    mkdir -p data
    cd data
    curl -O https://metrics.torproject.org/stats/clients.csv
    cd $PROG_DIR
    date
    python detector.py -i data/clients.csv -o data/userstats_ranges.csv -v
    date
    python split_countries.py -i data/userstats_ranges.csv -o data -v
    git add .
    CUR_DATE=$(date)
    git commit -m "Updated Data to reflect latest as of $CUR_DATE"
    git push
    git checkout master
}

main
