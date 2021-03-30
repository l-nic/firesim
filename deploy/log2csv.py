#!/usr/bin/env python2

import os
import argparse
import pandas as pd

def parse_switchlog(switchlog):
    with open(switchlog, 'r') as f:
            readlines = f.readlines()
    qsize_stats = {"time":[], "port":[], "hp_bytes":[], "lp_bytes":[]}
    event_stats = {"event":[], "time":[], "port":[]}
    pkt_trace_stats = {"time":[], "src_ip":[], "src_context":[], "dst_ip":[], "dst_context":[], "proto":[], "flags":[], "msg_len_bytes":[], "pkt_offset":[]}
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
        elif "&&CSV&&PktTrace" in line:
            data = line.split(',')
            pkt_trace_stats["time"].append(float(data[1]))
            pkt_trace_stats["src_ip"].append(data[2])
            pkt_trace_stats["src_context"].append(int(data[3]))
            pkt_trace_stats["dst_ip"].append(data[4])
            pkt_trace_stats["dst_context"].append(int(data[5]))
            pkt_trace_stats["proto"].append(data[6])
            pkt_trace_stats["flags"].append(data[7])
            pkt_trace_stats["msg_len_bytes"].append(float(data[8]))
            pkt_trace_stats["pkt_offset"].append(int(data[9]))
    return qsize_stats, event_stats, resp_time_stats, req_stats, pkt_trace_stats

def parse_uartlog(uartlog_dir):
    msg_trace_stats = {"event": [], "time":[], "client_id":[], "msg_len_bytes":[]}

    for (dirpath, _, filenames) in os.walk(uartlog_dir, followlinks=True):
        for filename is filenames:
            if ('uartlog' not in filename):
                continue

            with open(os.path.join(dirpath, filename), 'r') as f:
                readlines = f.readlines()

            for line in readlines:
                if ("&&CSV&&MsgSent" in line) or ("&&CSV&&MsgRcvd" in line):
                    data = line.split(',')
                    if ("&&CSV&&MsgSent" in line):
                        msg_trace_stats["event"].append("+")
                    elif ("&&CSV&&MsgRcvd" in line):
                        msg_trace_stats["event"].append("-")
                    else:
                        msg_trace_stats["event"].append(".")
                    msg_trace_stats["time"].append(float(data[1]))
                    msg_trace_stats["client_id"].append(float(data[2]))
                    msg_trace_stats["msg_len_bytes"].append(float(data[3]))

    return msg_trace_stats

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--switchlog', type=str, help='The switchlog to parse')
    parser.add_argument('--uartlog_dir', type=str, 
                        help='The directory that includes subdirectories of uartlog to parse')
    args = parser.parse_args()

    if (args.switchlog):
        switchlog_stats = parse_switchlog(args.switchlog)
        qsize_stats = switchlog_stats[0]
        event_stats = switchlog_stats[1]
        resp_time_stats = switchlog_stats[2]
        req_stats = switchlog_stats[3]
        pkt_trace_stats = switchlog_stats[4]

        # write stats to CSV files
        outdir = os.path.dirname(args.switchlog)
        qsize_df = pd.DataFrame(qsize_stats, dtype=float)
        event_df = pd.DataFrame(event_stats, dtype=float)
        resp_time_df = pd.DataFrame(resp_time_stats, dtype=float)
        req_stats_df = pd.DataFrame(req_stats, dtype=float)
        pkt_trace_stats_df = pd.DataFrame(pkt_trace_stats, dtype=float)
        with open(os.path.join(outdir, 'qsize.csv'), 'w') as f:
            f.write(qsize_df.to_csv(index=False))
        with open(os.path.join(outdir, 'events.csv'), 'w') as f:
            f.write(event_df.to_csv(index=False))
        with open(os.path.join(outdir, 'resp_time.csv'), 'w') as f:
            f.write(resp_time_df.to_csv(index=False))
        with open(os.path.join(outdir, 'req_stats.csv'), 'w') as f:
            f.write(req_stats_df.to_csv(index=False))
        with open(os.path.join(outdir, 'pkt_trace_stats.csv'), 'w') as f:
            f.write(pkt_trace_stats_df.to_csv(index=False))

    if (args.uartlog_dir):
        msg_trace_stats = parse_uartlog(args.uartlog_dir)

        # write stats to CSV files
        outdir = os.path.dirname(args.uartlog_dir)
        msg_trace_stats_df = pd.DataFrame(msg_trace_stats, dtype=float)
        with open(os.path.join(outdir, 'msgTrace.csv'), 'w') as f:
            f.write(msg_trace_stats_df.to_csv(index=False))

if __name__ == '__main__':
    main()

