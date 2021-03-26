#!/usr/bin/env bash

# This script runs a basic nanoPU Firesim test.

resultsdir=nanoPU-results
testname=lnic_test

# clean the results directory
rm -rf $resultsdir/$testname

echo "#################################"
echo "Running simulation: $testname"
echo "#################################"
config=workloads/lnic-evaluation/config_${testname}_runtime.ini  

# setup and run simulation
firesim -c $config infrasetup
firesim -c $config runworkload

# move the results directory
cd results-workload/
files=(*lnic-evaluation*)
cd ..
originaldir=${files[-1]}
mv results-workload/$originaldir $resultsdir/$testname

# parse the switchlog
./switchlog2csv.py $resultsdir/$testname/switch0/switchlog

echo "#################################"
echo "Simulation Complete!"
echo "#################################"

