# tor_anomaly

Tor anomaly detection based off of the detect.py script from the tor-web repository: [A simple visualization page is included.](http://seamustuohy.com/tor_anomaly/) The page is not fully done yet but, it does the basic visualization of where censorship and spikes occur. I also added cute little date-range specific twitter and google news searches when you click on one of the censorship or spike anomalies.

- [Website for viewing results:](http://seamustuohy.com/tor_anomaly/)
- [Branch with website code:](https://github.com/elationfoundation/tor_anomaly/tree/gh-pages)
- [Branch containing data:](https://github.com/elationfoundation/tor_anomaly/tree/data/data)
  - Note: Data is updated manually using the [update data script]( https://github.com/elationfoundation/tor_anomaly/blob/master/update_data.sh)
- [Repo with original code](https://gitweb.torproject.org/metrics-web.git/)


## Overview

I have been updating the detector scripts in metrics-web with a goal towards making it easier for others (hopefully with more statistical knowledge than I) to work with and build on the code. It has been a substantial rewrite that relies heavily on the python pandas library. I have just reached the point where I can accurately duplicate the functionality of the original code as it is called in the 80-run-clients-stats.sh file. This code also removes the need for pre-processing the data as done by the userstats-detector.R script.

Sadly, My expertise is not in the statistical analysis, but in open source software development. This is why I focused on making the existing code cleaner and more cleanly documented and structured.

If you are a statistician who has some experience in anomaly detection I would be happy to work with you to implement a better algorithm. The current algorithm is over-zealous is it's classification.

I would also appreciate tickets on what restructuring would be needed for models to be more easily tested and implemented within this code base so that it is easier for any future statistician to implement new algorithms without my assistance.

### Changes in output

Below is a quick overview of the changes in output that may impact other programs, or consumers of this information. I will write up a much more in-depth overview of functionality when I submit the actual pull request. I am thinking of getting basic PT anomaly detection added before this before I submit the pull request. This should be much easier with the new code.

### [Comparison of the old and new output](https://gist.github.com/elationfoundation/1714e0f1e9f8728eddb1)

- [NEW_ranges_file_SUBSET.csv](https://github.com/elationfoundation/tor_anomaly/blob/master/update_data.sh)
- [OLD_ranges_file_SUBSET.csv](https://gist.github.com/elationfoundation/1714e0f1e9f8728eddb1#file-old_ranges_file_subset-csv)

  - The output from write_all function [now called write_censorship_analysis()] has had some fields added to it. The old code had some duplicate processing that was built into it. The new code identifies the censorship and spike events the first time it runs through the time series so that the other functions can just read from the ranges output.

  - I have also changed the names of some of the fields.This will impact any code that is currently parsing this output. I can either change the field names back, write a seperate file that only has the currently formatted data and heading in it for further processing, or whatever code process' this output can be updated to parse this properly.

- [NEW_short_censorship_report.txt](https://gist.github.com/elationfoundation/1714e0f1e9f8728eddb1#file-new_short_censorship_report-txt)
- [OLD_short_censorship_report.txt](https://gist.github.com/elationfoundation/1714e0f1e9f8728eddb1#file-old_short_censorship_report-txt)

  - I have slightly modified the short censorship report produced by write_ml_report() which is now called write_short_report(). The changes are merely cosmetic, but I think there is a lot that can be done to eventually make the short report a more useful document (e.g. putting it in a structured format that will allow others to scrape and incorporate it into a threat feed).
