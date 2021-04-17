#!/usr/bin/env python2

import os
import argparse
import pandas as pd

def parse_uartlog(uartlog):
    with open(uartlog, 'r') as f:
            readlines = f.readlines()
    stats = {}
    for line in readlines:
        if "&&CSV&&" in line:
            data = line.split(',')
            stats[data[1]] = map(float, data[2:])
    return stats

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('uartlog', type=str, help='The uartlog to parse')
    args = parser.parse_args()

    stats = parse_uartlog(args.uartlog)

    # write stats to CSV files
    outdir = os.path.dirname(args.uartlog)
    df = pd.DataFrame(stats, dtype=float)
    with open(os.path.join(outdir, 'latency.csv'), 'w') as f:
        f.write(df.to_csv(index=False))

if __name__ == '__main__':
    main()

