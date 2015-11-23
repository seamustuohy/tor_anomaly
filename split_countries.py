#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# This file is part of tor_anomaly, a .
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

import argparse
import pandas as pd

import logging
logging.basicConfig(level=logging.ERROR)
log = logging.getLogger(__name__)

#    python split_countries.py -i data/userstats_ranges.csv -o data -v
def main():
    args = parse_arguments()
    set_logging(args.verbose, args.debug)
    db = pd.read_csv(args.full_ranges_file,
                     parse_dates=['date'],
                     index_col='date')
    countries = db.country.unique()
    for c in countries:
        log.info("splitting {0}".format(c))
        db[db.country == c].to_csv("{0}/{1}.tsv".format(args.country_range_folder, c), mode="w+", header=True)


# Command Line Functions below this point

def set_logging(verbose=False, debug=False):
    if debug == True:
        log.setLevel("DEBUG")
    elif verbose == True:
        log.setLevel("INFO")

def parse_arguments():
    parser = argparse.ArgumentParser("Get a summary of some text")
    parser.add_argument("--verbose", "-v",
                        help="Turn verbosity on",
                        action='store_true')
    parser.add_argument("--debug", "-d",
                        help="Turn debugging on",
                        action='store_true')
    parser.add_argument("--full_ranges_file", "-i",
                        help="Path to CSV file to read user ranges from.",
                        required=True)
    parser.add_argument("--country_range_folder", "-o",
                        help="The folder to output country files to.",
                        required=True)
    args = parser.parse_args()
    return args

def usage():
    print("TODO: usage needed")

if __name__ == '__main__':
    main()
