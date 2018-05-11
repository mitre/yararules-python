#!/usr/bin/env python
"""
Scan files with Yara rules from multiple sources with ease!

https://github.com/MITRE/yararules-python


Copyright (c) 2018, The MITRE Corporation. All rights reserved.
"""

from __future__ import print_function

import os
import sys
import csv
#import hashlib
import binascii

import yararules


def main(args):
    if not args.files:
        return
    # get sig files
    sigfiles = []
    if args.sigfiles:
        # copy the list
        sigfiles = list(args.sigfiles)
    if args.sigdirs:
        for d in args.sigdirs:
            # TODO: find files and apply args.filter
            # TODO: recurse if args.recurse
            for root, dirs, files in os.walk(d):
                for name in files:
                    filepath = os.path.join(root, name)
                    #print('INFO: adding sig {}'.format(filepath))
                    #namespace = hashlib.md5(filepath).hexdigest()[:16]
                    sigfiles.append(filepath)
                # ignore git dir
                if '.git' in dirs:
                    dirs.remove('.git')
    if args.listfiles:
        for lf in args.listfiles:
            with open(lf, 'r') as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        sigfiles.append(line)
    if args.csv:
        csv_writer = csv.writer(sys.stdout)
    for match, filepath in yararules.match_files(
            args.files,
            sigfiles,
            raise_on_warn=args.error_on_warn):
        if args.only_matches and match.rule is None:
            continue
        if args.csv:
            csv_writer.writerow([match.rule, match.namespace, filepath])
        else:
            print(match.rule, match.namespace, filepath)
            if args.print_strings and match.strings:
                for s in match.strings:
                    print('0x%x:%s: %s' % (
                        s[0],
                        s[1],
                        binascii.b2a_qp(s[2]).replace('=', '\\x')
                        ))

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', dest='sigdirs', help='Directory containing rules', action='append')
    #parser.add_argument('-r',dest='recurse',help='Recurse SIGDIR directory',action='store_true')
    #parser.add_argument('--filter',dest='filter',help='Filename filter')
    parser.add_argument(
        '-f',
        dest='sigfiles',
        help='rule file (allowed multiple times for list)',
        action='append')
    parser.add_argument(
        '-l',
        dest='listfiles',
        help='file containing path to rule files, one per line',
        action='append')
    parser.add_argument('-v', dest='verbose', help='verbose output', action='count')
    parser.add_argument('--csv', dest='csv', help='output in CSV format', action='store_true')
    parser.add_argument('-m', dest='only_matches', help='only show matches', action='store_true')
    parser.add_argument('files', metavar='FILE', nargs='+', help='file(s) to scan')
    parser.add_argument(
        '--quiet',
        '-q',
        help='only display match/none, no informational messages',
        action='store_true')
    parser.add_argument(
        '--init',
        action='store_true',
        help='Create a blank config (default: ~/.yara/)')
    parser.add_argument(
        '--config-dir',
        dest='configdir',
        help='Use/create configuration in given directory.')
    parser.add_argument(
        '--fail-on-warnings',
        dest='error_on_warn',
        action='store_true',
        default=False,
        help="Error on warnings during rule compilation")
    parser.add_argument(
        '--print-strings',
        dest='print_strings',
        action='store_true',
        default=False,
        help="Print strings in offset:var:string format")
    args = parser.parse_args()
    config_base = os.path.join(os.path.expanduser('~'), '.yara')
    if args.configdir:
        config_base = args.configdir
    if args.init:
        os.makedirs(os.path.join(config_base, 'rulesets'))
        os.makedirs(os.path.join(config_base, 'blacklists'))
        sys.exit(0)
    # if no rules given on command line
    if not args.sigdirs and not args.sigfiles and not args.listfiles:
        # check for sets in user dir
        if not args.quiet:
            print('No rulesets given; checking user-specific config...')
        sets_dir = os.path.join(config_base, 'rulesets')
        if os.path.exists(sets_dir):
            args.listfiles = []
            for root, dirs, files in os.walk(sets_dir):
                for name in files:
                    filepath = os.path.join(root, name)
                    args.listfiles.append(filepath)
            if args.listfiles and not args.quiet:
                print('Rulesets found: {}'.format(len(args.listfiles)))
            if not args.listfiles and not args.quiet:
                print('No Rulesets found in {}'.format(config_base))
        else:
            if not args.quiet:
                print('Configuration directory not found!')
            sys.exit(1)
    main(args)
