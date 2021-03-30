#!/usr/bin/env bash

# This script just copies over Firesim config files that we want to use
# as the default settings.

cp workloads/lnic-evaluation/config_build_lnic.ini config_build.ini
cp workloads/lnic-evaluation/config_build_recipes_lnic.ini config_build_recipes.ini
cp workloads/lnic-evaluation/config_hwdb_lnic.ini config_hwdb.ini

