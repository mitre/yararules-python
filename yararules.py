#!/usr/bin/env python
"""
yararules makes using multiple sources of Yara rules easier
by using sane defaults for externals and placing each rule
file into its own namespace to avoid rule name conflicts.

https://github.com/MITRE/yararules-python


Copyright (c) 2018-2020, The MITRE Corporation. All rights reserved.
"""


from __future__ import print_function

import os
import sys
import yara


class FakeMatch(object):
    """A fake Match class that mimics the yara Match object.
    Used to indicate no match.
    """
    rule = None
    namespace = None

def make_externals(filepath='', filename='', fileext='', dirname='', base_externals=None):
    """Given a file name, extension, and dir OR a full file path string, return
    a dictionary suitable for the yara match() function externals argument.
    If base_externals dictionary provided, then initialize the externals with it.

    The externals created by this function are:
        filepath
        filename
        extension
    """
    # initialize return dict with optionally given values
    d = dict()
    if base_externals:
        d.update(base_externals)
    # if not filepath, but we do have filename and dirname
    if not filepath and filename and dirname:
        filepath = os.path.join(dirname, filename)
    # if no extension, but do have filename or filepath
    if not fileext:
        if filename:
            _, fileext = os.path.splitext(filename)
        elif filepath:
            _, fileext = os.path.splitext(filepath)
    # if no filename, but we have filepath
    if not filename and filepath:
        _, filename = os.path.split(filepath)
    # update return dict with common externals when processing a file
    d.update({'filepath': filepath, 'filename': filename, 'extension': fileext})
    # return the computed externals
    return d


def yara_matches(compiled_sigs, filepath, externals=None):
    try:
        if externals:
            matches = compiled_sigs.match(filepath, externals=externals)
        else:
            matches = compiled_sigs.match(filepath)
    except yara.Error:
        print('Exception matching on file "{}"'.format(filepath), file=sys.stderr)
        raise
    if not matches:
        yield FakeMatch(), filepath
    for m in matches:
        yield m, filepath


def compile_files(rule_files, externals=None):
    """Given a list of files containing rules, return a list of warnings
       and a compiled object as one would receive from yara.compile().
       The rules from each file are put into their own namespaces.  For
       example, all of the rules in the '/tmp/alice.yara' file will be
       compiled into the '/tmp/alice.yara' namespace.  This prevents
       rule name collisions.
    """
    if not rule_files:
        return (None, None)
    # compile rules
    rules = {}
    warnings = list()
    for filepath in rule_files:
        rules[filepath] = filepath
    try:
        compiled_rules = yara.compile(
            filepaths=rules,
            externals=make_externals(base_externals=externals),
            error_on_warning=True
            )
    except yara.WarningError as e:
        compiled_rules = yara.compile(
            filepaths=rules,
            externals=make_externals(base_externals=externals)
            )
        warnings.append('{}'.format(e))
    except yara.Error as e:
        print('Error compiling {} rules: {}'.format(
            len(rules),
            ' '.join([rules[i] for i in rules])
            ), file=sys.stderr)
        raise
    return warnings, compiled_rules


def match_files(files, rule_files=None, compiled_rules=None, externals=None, raise_on_warn=False):
    """Given iterator of files to match against and either a list of files
    containing rules or a compiled rules object,
    YIELD a tuple of matches and filename.

    Optionally, if given an externals dict, use that as the initial
    externals values.  This function will add the following definitions:
        filename    :   name of file without directories
        filepath    :   full path including directories and filename
        extension   :   the filename's extension, if present
    """
    if not compiled_rules:
        # compile rules
        try:
            warnings, compiled_rules = compile_files(
                rule_files,
                make_externals(base_externals=externals)
                )
        except yara.Error as e:
            print(
                'Error compiling {} rule files: {}'.format(len(rule_files), e),
                file=sys.stderr
                )
            raise
        if warnings and raise_on_warn:
            raise Exception('\n'.join(warnings))
        if not compiled_rules:
            raise Exception('Rules not compiled')
    # iterate files to scan
    for fname in files:
        if os.path.isdir(fname):
            for root, _, walk_files in os.walk(fname):
                for name in walk_files:
                    filepath = os.path.join(root, name)
                    extern_d = make_externals(
                        filename=name,
                        filepath=filepath,
                        base_externals=externals
                        )
                    for m, f in yara_matches(compiled_rules, filepath, extern_d):
                        yield m, f
        else:
            extern_d = make_externals(filepath=fname, base_externals=externals)
            for m, f in yara_matches(compiled_rules, fname, extern_d):
                yield m, f
