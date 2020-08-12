#!/usr/bin/env python2

import os
import argparse
import pandas as pd

def parse_switchlog(switchlog):
    with open(switchlog, 'r') as f:
            readlines = f.readlines()
    qsize_stats = {"time":[], "port":[], "hp_bytes":[], "lp_bytes":[]}
    event_stats = {"event":[], "time":[], "port":[]}
    # stats logged by load generator
    resp_time_stats = {"service_time":[], "resp_time":[], "sent_time":[], "recv_time":[], "time":[], "context":[], "mean_service_time":[], "mean_arrival_time":[]}
    req_stats = {"sent_time":[], "service_time":[], "context":[], "mean_service_time":[], "mean_arrival_time":[]}
    for line in readlines:
        if "&&CSV&&QueueSize" in line:
            data = line.split(',')
            qsize_stats["time"].append(float(data[1]))
            qsize_stats["port"].append(float(data[2]))
            qsize_stats["hp_bytes"].append(float(data[3]))
            qsize_stats["lp_bytes"].append(float(data[4]))
        elif "&&CSV&&Events" in line:
            data = line.split(',')
            event_stats["event"].append(data[1])
            event_stats["time"].append(float(data[2]))
            event_stats["port"].append(float(data[3]))
        elif "&&CSV&&ResponseTimes" in line:
            data = line.split(',')
            resp_time_stats["service_time"].append(float(data[1]))
            resp_time_stats["resp_time"].append(float(data[2]))
            resp_time_stats["sent_time"].append(float(data[3]))
            resp_time_stats["recv_time"].append(float(data[4]))
            resp_time_stats["time"].append(float(data[5]))
            resp_time_stats["context"].append(float(data[6]))
            resp_time_stats["mean_service_time"].append(float(data[7]))
            resp_time_stats["mean_arrival_time"].append(float(data[8]))
        elif "&&CSV&&RequestStats" in line:
            data = line.split(',')
            req_stats["sent_time"].append(float(data[1]))
            req_stats["service_time"].append(float(data[2]))
            req_stats["context"].append(float(data[3]))
            req_stats["mean_service_time"].append(float(data[4]))
            req_stats["mean_arrival_time"].append(float(data[5]))
    return qsize_stats, event_stats, resp_time_stats, req_stats

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('switchlog', type=str, help='The switchlog to parse')
    args = parser.parse_args()

    qsize_stats, event_stats, resp_time_stats, req_stats = parse_switchlog(args.switchlog)

    # write stats to CSV files
    outdir = os.path.dirname(args.switchlog)
    qsize_df = pd.DataFrame(qsize_stats, dtype=float)
    event_df = pd.DataFrame(event_stats, dtype=float)
    resp_time_df = pd.DataFrame(resp_time_stats, dtype=float)
    req_stats_df = pd.DataFrame(req_stats, dtype=float)
    with open(os.path.join(outdir, 'qsize.csv'), 'w') as f:
        f.write(qsize_df.to_csv(index=False))
    with open(os.path.join(outdir, 'events.csv'), 'w') as f:
        f.write(event_df.to_csv(index=False))
    with open(os.path.join(outdir, 'resp_time.csv'), 'w') as f:
        f.write(resp_time_df.to_csv(index=False))
    with open(os.path.join(outdir, 'req_stats.csv'), 'w') as f:
        f.write(req_stats_df.to_csv(index=False))

if __name__ == '__main__':
    main()

