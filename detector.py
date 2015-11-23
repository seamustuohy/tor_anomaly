#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# This file is part of metrics-web.
# Copyright © 2015 seamus tuohy, <stuohy@internews.org>
# Copyright (c) 2011 George Danezis <gdane@microsoft.com>
#
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted (subject to the limitations in the
#  disclaimer below) provided that the following conditions are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the
#     distribution.
#
#   * Neither the name of <Owner Organization> nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
#  NO EXPRESS OR IMPLIED LICENSES TO ANY PARTY'S PATENT RIGHTS ARE
#  GRANTED BY THIS LICENSE.  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT
#  HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
#  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
#  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
#  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
#  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
#  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
#  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
#  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
#  OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
#  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#  (Clear BSD license: http://labs.metacarta.com/license-explanation.html#license)



# The detector works on aggregate number of users connecting to a fraction of directory
# servers per day. That set of statistics are gathered and provided by the Tor project in a sanitised
# form to minimise the potential for harm to active users. The data collection has been historically
# patchy, introducing wild variations over time that is not due to censorship. The detector is
# based on a simple model of the number of users per day per jurisdiction. That model is used to
# assess whether the number of users we observe is typical, too high, or too low. In a nutshell the
# prediction on any day is based on activity of previous days locally as well as worldwide.


# References
# https://lists.torproject.org/pipermail/tor-dev/2013-May/004803.html
# https://research.torproject.org/techreports/detector-2011-09-09.pdf
# https://trac.torproject.org/projects/tor/ticket/2718


import argparse
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
import csv
from scipy.stats.distributions import poisson
from scipy.stats.distributions import norm

# Country code -> Country names
import country_info

import statsmodels.api as sm

#Logging
import logging
logging.basicConfig(level=logging.ERROR)
log = logging.getLogger(__name__)




def detect(CSV_FILE = "userstats.csv",
           output_file = "userstats-ranges.csv",
           interval = 7,
           scoring_interval = 1,
           num_comparison_regions = 50,
           REPORT = True,
           report_file = 'short_censorship_report.txt'):
    """
    The detector uses time series of user connections to directory servers to detect censorship.

    Args:
        CSV_FILE (string): Path to CSV file to read user stats from.
        output_file (string): The file to write the CSV report on the minimum/maximum users of each country per date.
        interval (int): The time interval of days to model connection rates (i.e. t[i] - t[i-1] = 7 days)
        notification_days (int): The number of days for the Short Censorship Report to provide alerts on.
        num_comparison_regions (int): The number of jurisditions used to model ratios of normal changes in usage.
        REPORT (bool): If the Short Censorship Report should be created.
        report_file (string): Where to write the Short Censorship Report.
    """
    log.info("Initiating Detector....")
    # userstats initial CSV columns
    # date,node,country,transport,version,frac,users
    raw_data = pd.read_csv(CSV_FILE,
                              parse_dates=['date'],
                              index_col='date')

    # We are only looking at relay data
    # NOTE: If pluggable transports are to examined in the future you would want to add bridges here.
    raw_data = raw_data[raw_data.node=="relay"]

    # Create a more easily manipulatable table
    # country        ??  a1  a2   ad    ae   af   ag
    # date
    # 2015-09-19  10665  24   4  195  7205  598  125
    global_rates = pd.DataFrame(raw_data[['country', 'clients']]).reset_index()
    global_rates = global_rates.pivot_table(index='date', columns='country', values='clients')

    # Resampling to the day to recover any sample days with no data
    global_rates = global_rates.resample("D")

    global_min, global_max = get_interdomain_trends(global_rates,
                                                    num_comparison_regions,
                                                    interval)
    log.info("Writing Userstats Report....")
    write_censorship_analysis(global_rates, global_min, global_max, output_file, interval)

    # TODO
    if REPORT:
        log.info("Writing Report....")
        # Make our short report; only consider events of the last day
        write_short_report(report_file, output_file, notification_days)
    else:
        log.debug("Skipping Report....")


def get_interdomain_trends(global_rates, num_comparison_regions, interval):
    """
        [Modelling inter-domain trends] It turns out there is significant variance between jurisdictions as to whether the trends of users are going up and down from one time to another. Therefore we look at the trends of the 50 jurisdictions with the most users, eliminate outliers, and define a normal distribution fitting the rest of the trends (as a percentage change). This is part of our model for predicting the number of users at any specific jurisdiction: from one time period to the next the numbers should fluctuate within the plausible range of the global trend -- i.e. within the most likely values (probability 0.9999) of this normal distribution.

    Args:
        global_rates (pandas.core.frame.DataFrame): The global daily rates of users of tor per country. See:http://pandas.pydata.org/pandas-docs/stable/dsintro.html#dataframe
        num_comparison_regions (int): The number of jurisditions used to model ratios of normal changes in usage.
        interval (int): The time interval of days to model connection rates (i.e. t[i] - t[i-1] = 7 days)
    """
    log.debug("Gathering interdomain trends.")

    comparison_regions = id_largest_locations(global_rates, num_comparison_regions=num_comparison_regions).tolist()

    log.debug("Comparing the following {0} regions of the requested {1} number of regions: {2}".format(len(comparison_regions), num_comparison_regions, comparison_regions))

    # Gather only the data from the largest regions
    largest_locations = global_rates.filter(comparison_regions)

    log.debug("Gathering minimum and maximum user trends from the top {0} regions.".format(num_comparison_regions))

    global_tendencies = get_minmax_tendencies(largest_locations, interval)
    global_min = global_tendencies['min']
    global_max = global_tendencies['max']

    return global_min, global_max




def id_largest_locations(user_data, num_comparison_regions=50, time_range=1):
    """Identifies the regions with the most users have this use the last [time_range] days.

    We use the 50 largest jurisdictions to build our models of typical ratios of traffic over time—as expected most of them are in countries where no mass censorship has been reported. This strengthens the model as describing “normal” Tor connection patterns.


    Args:
        user_data (pandas.core.frame.DataFrame): The global daily rates of users of tor per country. See:http://pandas.pydata.org/pandas-docs/stable/dsintro.html#dataframe
        num_comparison_regions (int): The number of jurisditions used to model ratios of normal changes in usage.
        time_range (int): Number of days of of historic data to take into consideration when calculating largest user bases for Tor.

    """
    log.debug("Identifying largest locations")

    # Get a sub-range of data that only represents the past X days
    user_usage_range = user_data.ix[(user_data.index[-1] - pd.offsets.Day(time_range-1)):]

    # Get the sum of all users per country within the usage range
    country_sums = user_usage_range.sum()
    log.debug("The following country sums were found for the last {0} days: {1}".format(time_range, country_sums))

    # Get an array of the top X countries by users
    # This currently drops unknown countries
    # TODO: Do we also wish to drop the 'a1' & 'a2' values
    country_data = country_sums.drop('??').to_frame()
    # If this is to work  with PT's we need to remove the drop("??")
    # country_data = country_sums.to_frame()
    largest_countries = country_data.sort(0).dropna().tail(num_comparison_regions)

    # We only want the list of largest countries, not their data.
    country_list = largest_countries.index

    log.debug("The countries with the most users in the last {0} days is: {1}".format(time_range, country_list))

    return country_list


def get_minmax_tendencies(country_data, interval = 1):
    """ Main model: computes the expected min / max range of number of users for a set of locations.

    Uses the countries with the largest number of users as a model for usage globally. The deployed model considers a time interval of seven (7) days to model connection rates (i.e.  ti - ti−1 = 7 days). The key reason for a weekly model is our observation that some jurisdictions exhibit weekly patterns.

    ARGS:
        country_data (pandas.core.frame.DataFrame) : A data frame containing full time series' from X countries with the largest number of connected users overall. See:http://pandas.pydata.org/pandas-docs/stable/dsintro.html#dataframe
        interval (int): Number of days to include in each interval.

    """
    log.debug("Getting minimum and maximum tendencies")

    # Country data format
    # country       hk     za    ie    ae    no    il    ve    bg    dk    cl
    # date
    # 2015-09-19  6015   5970  6400  7205  6633  8397  7240  6601  6935  6180

    # iteritem gives the entire range of dates for a single country
    row_iterator = country_data.iteritems()
    relative_change = pd.Series()
    for country_code, row in row_iterator:
        # row = pandas Series of all dates for a country
        # See: http://pandas.pydata.org/pandas-docs/stable/generated/pandas.Series.html

        # Concatinate a duplicate DataFrame that has been shifted forward by one interval
        # This allows us to operate on those two values quickly
        _date_range = pd.concat([row, row.shift(periods=interval)], axis=1)

        _date_range = _date_range.apply(get_difference_if_exist, axis=1)

        _date_range.name = country_code # Add country name as a column name

        # Append each new series to the combined set
        if relative_change.any:
            relative_change = pd.concat([relative_change, _date_range], axis=1)
        else:
            relative_change = _date_range

    min_max = relative_change.apply(get_minmax, axis=1)

    log.debug("The global minimum for tor usage is: {0}".format(min_max['min']))
    log.debug("The global maximum for tor usage is: {0}".format(min_max['max']))

    return min_max

def get_minmax(sample, min_samples = 8):
    """

    We consider that a ratio of connections is typical if it falls within the 99.99 % percentile of the Normal distribution N(m, v) modelling ratios. This ensures that the expected rate of false alarms is about 1/10000, and therefore only a handful a week (given the large number of jurisdictions). Similarly, we infer the range of the rate of usage from each jurisdiction (given Ci j) to be the 99.99 % percentile range of a Poisson distribution with parameter Ci j. This full range must be within the typical range of ratios to avoid raising an alarm.

    Args:
        sample (pandas.core.series.Series): A series containing the relative change values for a set of countries.
    """

    log.debug("Getting min and max for a sample on {0}'s data: {1}".format(sample.name, sample))
    initial_sample_len = len(sample)

    if initial_sample_len > min_samples:
        sample = drop_outliers(sample)

        num_outliers = initial_sample_len - len(sample)
        log.debug("Sample had {0} outliers removed. Current sample: {1}".format(num_outliers, sample))

        if len(sample) > min_samples:
            mu, signma = norm.fit(sample)
            sample_max = norm.ppf(0.9999, mu, signma)
            sample_min = norm.ppf(1 - 0.9999, mu, signma)

            log.debug("Sample min == {0}, Sample max == {1}".format(sample_min, sample_max))

            return pd.Series({"max":sample_max, "min":sample_min})
        else:
            log.debug("After removing outliers the sample was a length of {0}. This is shorter than acceptable minimum length of {1}.".format(len(sample), min_samples))

            return pd.Series({"max":None, "min":None})
    else:
        log.debug("Sample with length of {0} is shorter than acceptable minimum length of {1}.".format(initial_sample_len, min_samples))

        return pd.Series({"max":None, "min":None})


def get_difference_if_exist(item):
    """ Return an int containing the difference in users for a time delta of 'days' determined by the series passed to it.

    Args:
        item (pandas.core.series.Series): A series containing user stats (as numpy.float64) from two dates one [interval length] apart. See:http://pandas.pydata.org/pandas-docs/stable/generated/pandas.Series.html
        e.g:
            hk    5582
            hk    6043
            Name: 2015-09-26T20:00:00.000000000-0400, dtype: float64
    """

    log.debug("Getting difference between sample dates of {0}".format(item))

    # If either user stat (numpy.float64) is nan we do not wish to operate on it
    if np.isnan(item[0]) or np.isnan(item[1]):
        return None
    if item[1] == 0:
        # Don't try to divide by zero
        return None
    else:
        # Operate on each item as a float to match original implementation
        # Operating on the numpy.float64 numbers will result in a different value
        # This +/- 0.01 caused me no end of pain in debugging
        return float(item[0]) / float(item[1])


def drop_outliers(sample):
    """Remove extreme/unrepresentative observations from a series containing the relitive change values of countries.

    We remove any outliers that fall outside four inter-quartile ranges of the median. This ensures that a jurisdiction with a very high or very low ratio does not influence the model of ratios (and can be subsequently detected as abnormal).

    Args:
        sample (pandas.core.series.Series): A series containing the relative change values for a set of countries.

    """
    log.debug("Dropping ouliers in sample {0}.".format(sample))

    vals = sorted(sample)
    mid = len(vals)
    mid = mid/2
    median = vals[mid]

    log.debug("Median of sample: {0}".format(median))

    lower_quartile = np.median(vals[:mid])

    log.debug("Lower Quartile: {0}".format(lower_quartile))

    if (len(vals) % 2 == 0):
        upper_quartile = np.median(vals[mid:])
    else:
        upper_quartile = np.median(vals[mid+1:])

    log.debug("Upper Quartile: {0}".format(upper_quartile))

    # Calculate the Interquartile range (IQR)
    # IQR is a measure of statistical dispersion, being equal to the difference between the upper and lower quartiles,[1][2] IQR = Q3 −  Q1
    interquartile_range = upper_quartile - lower_quartile

    log.debug("IQR: {0}".format(interquartile_range))

    # Outlier ranges that could make John Turkey cry
    # Using +/-IQD*4 instead of +/-Q[1,3]*1.5
    # http://stats.stackexchange.com/questions/13086/is-there-a-boxplot-variant-for-poisson-distributed-data#13429
    var_rng = interquartile_range * 4
    # Drop any value that does not fit in range of med+/-QD*4
    normal_ranges = [v for v in vals if median - var_rng < v and  v < median + var_rng]

    log.debug("Range with outliers dropped: {0}".format(normal_ranges))

    return normal_ranges

def write_censorship_analysis(global_data, global_min, global_max, output_file, interval=7, known_only=False):
    """Write a CSV report on the minimum/maximum range users of each country per date, and possible censorship.

    ARGS:
        global_data (pandas.core.frame.DataFrame): The global daily rates of users of tor per country. See:http://pandas.pydata.org/pandas-docs/stable/dsintro.html#dataframe
        global_min (pandas.core.series.Series): A time series list of the global minimum tendencies for tor users.
        global_max (pandas.core.series.Series): A time series list of the global maximum tendencies for tor users.
        output_file (string): The file to write the CSV report on the minimum/maximum users of each country per date.
        interval (int): The time interval of days to model connection rates (i.e. t[i] - t[i-1] = 7 days)
        known_only (bool): If ONLY countries found in the country_info file should be used
    """

    log.info("Calculating and writing probability of min/max users in each country per date.")
    log.debug("writing global data to CSV output file {0}".format(output_file))

    with open(output_file, "w+") as ranges_file:
        csvw = csv.writer(ranges_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        csvw.writerow(["date", "country", "event_censor", "event_spike", "max_user_range", "min_user_range", "actual_users"])

    # iteritem gives the entire range of dates for a single country
    row_iterator = global_data.iteritems()
    relative_change = pd.Series()
    for country_code, row in row_iterator:
        # row = pandas Series of all dates for a country
        # See: http://pandas.pydata.org/pandas-docs/stable/generated/pandas.Series.html
        country_name = get_country_name(country_code)
        if not country_name and known_only:
            # The known_only check only allows countries found in the country_info file to be output
            # This makes the output of userstats-ranges inconsistant with the old code
            # Therefore known_only is off by default.
            log.warn("Skipping country {0} because it is not in the country list.".format(country_code))
            continue
        else:
            log.debug("country {0} not found in country list.".format(country_code))

        # Concatinate a duplicate DataFrame that has been shifted forward by one interval
        # This allows us to operate on those two values quickly
        _date_range = pd.concat([row, row.shift(periods=interval)], axis=1)

        _date_range = _date_range.apply(get_poisson_distribution, axis=1, args=(country_code, global_min, global_max))

        # We drop empty dates when exporting for presentation ONLY
        # If we drop days with NaN data it can impact our range based calculations
        _date_range = _date_range.dropna()

        # UTF issues in python prevent this logging, and I don't have time to fix it.
        # log.debug("Writing data for {0}".format(country_name))
        _date_range.to_csv(output_file, mode="a+", header=False)

def get_country_name(country_code):
    try:
        # Check to see if the country is in our list of countries to examine
        country_name = country_info.countries[country_code]
        return country_name
    except KeyError as _err:
        log.warn("country {0} not found in country list.".format(country_code))
        return False
    # We should never reach this
    log.warn("An unexpected state was reached in get_country_name: country_code {0}, did not raise an exception, but did not return the country name {1}".format(country_code, country_name))
    return False



def get_poisson_distribution(date_range, country_code, global_min, global_max):
    """
    Args:
        date_range (pandas.core.series.Series): The date range of country data for the poisson distribution to be applied to.
        country_code (string): The country code of the country being explored.
        global_min (pandas.core.series.Series): A time series list of the global minimum tendencies for tor users.
        global_max (pandas.core.series.Series): A time series list of the global maximum tendencies for tor users.


    """
    current_date = date_range[0]
    comparison_date = date_range[1]
    #print(date_range)

    # If there is not a global min or a global max on the day in question then don't even try
    if pd.isnull(global_min[date_range.name]) or pd.isnull(global_max[date_range.name]):
        return pd.Series({"country":country_code,"min":None, "max":None})

    # We can't do this without both dates
    if np.isnan(comparison_date) or np.isnan(current_date):
        return pd.Series({"country":country_code,"min":None, "max":None})
    else:
        down_score = 0
        up_score = 0
        # poisson.ppf(plausable_range, shape_params)
        min_range = global_min[date_range.name] * poisson.ppf(1-0.9999, comparison_date)
        max_range = global_max[date_range.name] * poisson.ppf(0.9999, comparison_date)
        if current_date < min_range:
            down_score = 1
        if current_date > max_range:
            up_score = 1

        return pd.Series({"country":country_code,"min":min_range, "max":max_range, "users":current_date, "event_censor":down_score, "event_spike":up_score})


def write_short_report(report_file, country_range_file, notification_days=1):
    """
    Args:
        report_file (string): The location to write the short report to.
        country_rage_file (string) The location of the country ranges file created by "write_censorship_analysis"
        notification_days (int): The number of days for the Short Censorship Report to provide alerts on.
    """



    # Country Range file columns
    # date,country,event_censor,event_spike,max_user_range,min_user_range,actual_users
    raw_data = pd.read_csv(country_range_file,
                              parse_dates=['date'],
                              index_col='date')

    # Limit the range of dates to only those within the last number of *notification_days*
    try:
        period_end = str(raw_data.ix[-1].name.strftime('%Y-%m-%d'))
        period_start = str(raw_data.ix[-notification_days].name.strftime('%Y-%m-%d'))
        notification_period = raw_data.loc[period_start:period_end]
    except IndexError as _e:
        log.warn("No items in csv {0}. Report cannot be written if given no data.".format(country_range_file))
        return False

    censorship_events = notification_period[(notification_period.event_censor > 0)
                                            & (notification_period.event_spike == 0)]

    spike_events = notification_period[(notification_period.event_spike > 0)
                                        & (notification_period.event_censor == 0)]

    with open(report_file, "w+") as report:

        # Create text strings for report
        flash_str = "=======================\n"
        if notification_days == 1:
            date_string = period_end
        else:
            date_string = "{0} to {1}".format(period_start, period_end)

        report.write(flash_str)
        if (len(spike_events) == 0) and (len(censorship_events) == 0):
            # If there are no events then write it and return
            report.write("No events detected for {0}\n".format(date_string))
            report.write(flash_str + "\n")
            return False
        else:
            report.write("Automatic Anomoly Detection Report for {0}\n".format(date_string))
            report.write(flash_str + "\n")


        write_event_summary(report, "Censorship", censorship_events)
        write_event_summary(report, "Spike", spike_events)

def write_event_summary(report, event_type, events):
        # Write Censorship Data
        report.write("\n=== Possible {0} Events ===\n".format(event_type))
        countries = events.drop_duplicates(['country']).country.tolist()

        for country_code in countries:
            # Get country name if possible
            country_name = get_country_name(country_code) or country_code

            # Get all events for the current country
            country_events = events[events.country == country_code]
            report.write("\nWe detected {0} potential {1} events in {2}:\n".format(len(country_events), event_type.lower(), country_name))

            for date, event in country_events.iterrows():

                if event_type.lower() == "spike":
                    over_max = event.actual_users - event.max_user_range
                    report.write("{0}: {1} was {2} users higher than the daily maximum boundry of {3}\n".format(date.strftime('%Y-%m-%d'),
                                                                                                         int(event.actual_users),
                                                                                                         int(over_max),
                                                                                                         int(event.max_user_range)))
                elif event_type.lower() == "censorship":
                    under_min = event.min_user_range - event.actual_users
                    report.write("{0}: {1} was {2} users lower than the daily minimum boundry of {3}\n".format(date.strftime('%Y-%m-%d'),
                                                                                                         int(event.actual_users),
                                                                                                         int(under_min),
                                                                                                         int(event.min_user_range)))



def main():
    args = parse_arguments()
    set_logging(args.verbose, args.debug)
    log.info("Starting...")

    # Setting defaults & setting any CLI args
    _stats_file = "userstats.csv"
    if args.user_stats_file:
        _stats_file = args.user_stats_file

    _ranges_file = "userstats-ranges.csv"
    if args.country_range_file:
        _ranges_file = args.country_range_file

    _report = False
    if args.report:
        _report = True

    _report_file = 'short_censorship_report.txt'
    if args.report_file:
        _report_file = args.report_file

    detect(CSV_FILE = _stats_file,
           output_file = _ranges_file,
           REPORT = _report,
           report_file = _report_file)


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
    parser.add_argument("--user_stats_file", "-i",
                        help="Path to CSV file to read user stats from.")
    parser.add_argument("--country_range_file", "-o",
                        help="Where to write CSV report on the minimum/maximum users of each country per date.")
    parser.add_argument("--report", "-r",
                        help="If the Short Censorship Report should be created.",
                        action='store_true')
    parser.add_argument("--report_file", "-R",
                        help="Where to write the Short Censorship Report.")

    args = parser.parse_args()
    return args

if __name__ == '__main__':
    main()
