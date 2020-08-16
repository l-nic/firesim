#!/usr/bin/env bash

docker run --rm -d -v $(pwd):/home/jovyan/work -p 8888:8888 --name jupyter-rpy2 mshahbaz/jupyter-rpy2
docker exec jupyter-rpy2 Rscript /home/jovyan/work/install_packages.r
docker exec jupyter-rpy2 jupyter notebook list
