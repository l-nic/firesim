#!/usr/bin/env bash

# This script runs all the nanoPU Firesim simulations

resultsdir=nanoPU-results

# clean the results directory
rm -rf $resultsdir/
mkdir $resultsdir

#######################
# Run Microbenchmarks #
#######################

tests=( lnic_scheduling timer_scheduling bounded_scheduling unbounded_scheduling rss jbsq jbsq_pre )

for testname in "${tests[@]}"
do
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
done

################
# Run MICA Sim #
################
echo "#################################"
echo "Running simulation: MICA"
echo "#################################"
config=workloads/lnic-multi-core-mica/config_lnic_mica_runtime.ini

# setup and run simulation
firesim -c $config infrasetup
firesim -c $config runworkload

# move the results directory
cd results-workload/
files=(*lnic-multi-core-mica*)
cd ..
originaldir=${files[-1]}
mv results-workload/$originaldir $resultsdir/mica

# parse the switchlog
./switchlog2csv.py $resultsdir/mica/switch0/switchlog

############################
# Run Set Intersection Sim #
############################
echo "####################################"
echo "Running simulation: Set Intersection"
echo "####################################"
config=workloads/lnic-intersect/config_lnic_intersect_runtime.ini

# setup and run simulation
firesim -c $config infrasetup
firesim -c $config runworkload

# move the results directory
cd results-workload/
files=(*lnic-intersect*)
cd ..
originaldir=${files[-1]}
mv results-workload/$originaldir $resultsdir/set_intersect

# parse the switchlog
./switchlog2csv.py $resultsdir/set_intersect/switch0/switchlog

