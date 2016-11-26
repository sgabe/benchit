#!/usr/bin/env python

"""
BenchIT is a simple Python script for security auditing purposes.

It is the most useful for auditing systems by analyzing files collected from
remote hosts. It allows you to check certain system settings stored in
configuration files by using regular expressions. The simplest check will
determine if a pattern matches. However, with capturing groups it is also
possible to determine whether the actual value matches the expected or the
default value. Results are summarized in a HTML report and also stored in a
CSV file.

Regular expressions must be stored in a CSV file containing the following
columns separated by a semicolon (;):
  - Boolean value which determines whether we expect a match or not ("True").
  - Name of the file ("sshd_config").
  - Regular expression to evaluate ("^Protocol[ \t]+(\d)$").
  - Number of the chaper in the given CIS guideline ("9.2.1").
  - Title of the chapter in the given CIS guideline ("Set SSH Protocol to 2").
  - Short summary of the chapter ("SSH supports two different protocols...").
  - Default value of the setting ("2,1").
  - Expected value of the setting ("2").

system requirements:
  - GnuWin32 with ports of the necessary tools
        http://getgnuwin32.sourceforge.net/
  - Q to execute SQL-like queries on CSV files
        http://harelba.github.io/q/
  - The following Python libraries:
        dominate, configobj
"""

__description__ = 'Simple Python script for security auditing purposes.'
__author__ = 'Gabor Seljan'
__version__ = '0.1.7'
__date__ = '2016/11/26'

import io
import os
import re
import csv
import ast
import sys
import time
import binascii
import textwrap
import dominate

from argparse import *
from dominate.tags import *
from configobj import ConfigObj
from subprocess import check_output

banner = """
                     ____                  _     _____ _______
                    |  _ \     v{}     | |   |_   _|__   __|
                    | |_) | ___ _ __   ___| |__   | |    | |
                    |  _ < / _ \ '_ \ / __| '_ \  | |    | |
                    | |_) |  __/ | | | (__| | | |_| |_   | |
                    |____/ \___|_| |_|\___|_| |_|_____|  |_|
""".format(__version__)

print(banner)

parser = ArgumentParser(
    formatter_class=RawDescriptionHelpFormatter,
    description=__doc__,
    prog='benchit'
)

module = parser.add_mutually_exclusive_group(required=True)
module.add_argument('-d, --database', dest='d', action='store_true',
                    help='audit Oracle database')
module.add_argument('-l, --linux', dest='l', action='store_true',
                    help='audit Linux system')
module.add_argument('-w, --windows', dest='w', action='store_true',
                    help='audit Windows system')

parser.add_argument('-o, --output', dest='o', default='results',
                    help='output filename (default results_{timestamp}.html)')
parser.add_argument('-p, --path', dest='p', default='.',
                    help='base path to target directory (default .)')
parser.add_argument('-v, --verbose', dest='v', action='store_true',
                    help='run in verbose mode')
parser.add_argument('-s, --skip-dirlist', dest='s', action='store_true',
                    help='skip directory list checking (default false)')
parser.add_argument('--debug', action='store_true',
                    help='run in debug mode (default false)')

args = parser.parse_args()

items = {}
audit = {}
results = []
total = 0
passed = 0
failed = 0
errors = 0

headers = [
    'Chapter',
    'Title',
    'Summary',
    'Default',
    'Actual',
    'Expected',
    'Result'
]


def main():
    global audit, results, total, passed, failed, errors

    config = ConfigObj('benchit.ini')

    if args.d:
        print('[+] Oracle detected!')
        audit = config['Database']['Oracle']
    elif args.w:
        print('[+] Windows detected!')
        audit = config['Windows']['2012']
    elif args.l:
        for l in ['RedHat', 'SuSe', 'LSB', 'Debian']:
            if os.path.isfile('%s/etc/%s-release' % (args.p, l)):
                print('[+] %s Linux detected!' % l)
                audit = config['Linux'][l]
                break

    if audit is None:
        print('[!] Nothing to audit...')
        exit(1)

    with open(audit['csv'], mode='r') as infile:
        reader = csv.reader(infile, delimiter=';')
        for row in reader:
            i = row[0]
            n = row[1]
            if i in items:
                if n in items[i]:
                    items[i][n].append(tuple(row[2:]))
                else:
                    items[i][n] = [tuple(row[2:])]
            else:
                items[i] = {row[1]: [tuple(row[2:])]}

    print('[*] Audit in progress, this can take a while...')

    for r, d in items.items():
        print('[*]   Checking %s items...' % r)
        if r != 'None':
            for f, i in d.items():
                print('[+]     Processing %s' % f)
                path = '/'.join([args.p, f])
                if args.d:
                    check_item_database(path, i, ast.literal_eval(r))
                elif args.l or args.w:
                    check_item_os(path, i, ast.literal_eval(r))
        else:
            for f, i in d.items():
                try:
                    for c, n, t, d, *_ in i:
                        total += 1
                        if not os.path.isfile('/'.join([args.p, f])):
                            raise IOError('{} not found!'.format(f))
                        c = c.format(args.p)
                        print('[+]     Executing {}'.format(c))
                        output = check_output(c, shell=True)
                        if output:
                            failed += 1
                            r = 'Fail'
                        else:
                            passed += 1
                            r = 'Pass'
                        results.append((n, t, d, '', '', '', r))
                except (IOError, OSError) as err:
                    print('[!] Error: {}'.format(err))
                    for c, n, t, d, *_ in i:
                        errors += 1
                        results.append((n, t, d, '', '', '', 'Error'))

    timestamp = time.strftime("%Y%m%dT%H%M%S")
    filename = '{}_{}'.format(args.o, timestamp)
    create_html_report('{}.html'.format(filename))
    create_csv_report('{}.csv'.format(filename))

    print('[*] Audit finished!')


def check_item_os(filename, items, expected):
    """Checks every regex pattern listed in the loaded CSV file."""
    global results, total, passed, failed, errors
    # Convert UTF-16 encoded files (created by reg export) to UTF-8
    if args.w:
        try:
            with io.open(filename, 'r', encoding='utf-16') as f:
                text = f.read()
            with io.open(filename, 'w', encoding='utf-8') as f:
                f.write(text)
        except (UnicodeError, UnicodeDecodeError, IOError) as e:
            pass
    if args.l and args.s and ('dirlist.txt' in filename):
        return
    try:
        with open(filename, 'r', encoding='utf8') as f:
            s = f.read().replace('\\', '\\\\')
            for p, n, t, b, d, e in items:
                total += 1
                m = re.search(p, s, re.M)
                e = 'N/A' if len(e) == 0 else e
                m = 'N/A' if m is None or len(m.groups()) == 0 else m.group(1)
                # Convert null-terminated strings from HEX to ASCII
                if args.w and m.startswith('hex'):
                    m = re.sub('(00,?|[\s,]|\\\\)', '', m[7:])
                    m = binascii.unhexlify(m)
                    m = str(m)[2:-1]
                # We expect a match
                if expected:
                    # We found a match
                    if m != 'N/A':
                        # Any value is accepted
                        if e == 'N/A':
                            passed += 1
                            r = 'Pass'
                        # Check relational (>, <, =) values
                        elif check_item_relational(m, e):
                            passed += 1
                            r = 'Pass'
                        else:
                            failed += 1
                            r = 'Fail'
                    # We have a default value
                    elif len(d) != 0 and check_item_default(d, e):
                            passed += 1
                            r = 'Pass'
                    else:
                        failed += 1
                        r = 'Fail'
                # We don't expect a match
                elif m == 'N/A' and not expected:
                    passed += 1
                    r = 'Pass'
                else:
                    failed += 1
                    r = 'Fail'
                results.append((n, t, b, d, m, e, r))
                if args.debug:
                    msg = 'N:{}\tD:{}\tM:{}\tE:{}\tR:{}'.format(n, d, m, e, r)
                    print('        {}'.format(msg))
    except IOError as err:
        print('[!] Error: %s not found!' % filename)
        if err.errno is 2:
            for p, n, t, b, d, e in items:
                total += 1
                m = 'N/F'
                if len(d) != 0:
                    if check_item_default(d, e):
                        passed += 1
                        r = 'Pass'
                    else:
                        failed += 1
                        r = 'Fail'
                else:
                    errors += 1
                    r = 'Error'
                results.append((n, t, b, d, m, e, r))
                if args.debug:
                    msg = 'N:{}\tD:{}\tM:{}\tE:{}\tR:{}'.format(n, d, m, e, r)
                    print('        {}'.format(msg))
        return


def check_item_default(d, e):
    """Checks the default value when the specific setting is not available."""
    if e[:1] in ['>', '<'] and d not in ['Not defined', 'Not configured']:
        return check_item_relational(d, e)
    elif d == e:
        return True
    else:
        return False


def check_item_relational(a, e):
    """Checks for acceptable lesser or greather values."""
    if e[:1] == '>' and int(a) >= int(e[1:]):
        return True
    elif e[:1] == '<' and int(a) <= int(e[1:]):
        return True
    elif a == e:
        return True
    else:
        return False


def check_item_database(filename, items, expected):
    """Checks every query listed in the loaded CSV file."""
    global results, total, passed, failed, errors
    try:
        for q, n, t, b, d, e in items:
            if args.v:
                print('[+]            {}'.format(q))
            if not os.path.isfile(filename):
                raise IOError('{} not found!'.format(filename))
            total += 1
            params = ['q', '-H', '-d', ';', q.format(filename)]
            o = str(check_output(params, shell=True).strip())
            if o.startswith('b\''):
                o = o[2:-1]
            if o and e:
                if args.debug:
                    print(
                        'o: {:s} {:s} e: {:s} {:s}'.format(
                            o.strip(),
                            type(o.strip()),
                            e.strip(),
                            type(e.strip())
                            )
                        )
                if o != e:
                    failed += 1
                    results.append((n, t, b, d, o, e, 'Fail'))
                else:
                    passed += 1
                    results.append((n, t, b, d, o, e, 'Pass'))
            elif bool(o) is not expected:
                failed += 1
                results.append((n, t, b, d, '', '', 'Fail'))
            else:
                passed += 1
                results.append((n, t, b, d, '', '', 'Pass'))
    except (IOError, OSError) as err:
        print('[!] Error: {}'.format(err))
        for q, n, t, b, d, e in items:
            total += 1
            errors += 1
            results.append((n, t, b, d, '', e, 'Error'))
        return


def create_html_report(filename):
    """Creates a nice HTML report from the results."""
    title = 'Security Audit Report ({})'.format(time.strftime('%m/%d/%Y'))
    doc = dominate.document(title=title)
    with doc:
        styles = [
            'margin:0;padding:0;',
            'border:1px solid black;',
            'margin-top:0;',
            'margin-bottom:0',
        ]
        colors = {
            'Pass': 'lime',
            'Fail': 'red',
            'Error': 'yellow',
        }

        for line in banner.splitlines():
            line = re.sub(r' {20}', '     ', line)
            pre(line, style='margin:0;font-size:16px;font-weight:bold')
        h1(title, style=styles[3])
        h4(audit['benchmark'], style=styles[0])

        p('Performed %d tests in total:' % total, style=styles[3])
        l = ul(style=styles[2])
        l += li('Pass = {} ({:.0f}%)'.format(passed, passed/float(total)*100))
        l += li('Fail = {} ({:.0f}%)'.format(failed, failed/float(total)*100))
        l += li('Error = {} ({:.0f}%)'.format(errors, errors/float(total)*100))

        t = table(
            border=1,
            width='100%',
            cellspacing='0',
            cellpadding='3',
            style=styles[1]
        )

        with t.add(thead(border=1, style=styles[1])):
            l = tr()
            for header in headers:
                l += th(header, bgcolor='black', style='color:white')
        with t.add(tbody(border=1, style=styles[1])):
            for n, t, b, d, a, e, r in sorted(set(results), key=lambda x: tuple(map(int, x[0].split('.')))):
                l = tr(style='border:1px solid black')
                l += td(n, align='left', width='5%', style=styles[1])
                l += td(t, align='left', width='32%', style=styles[1])
                l += td(b, align='left', width='30%', style=styles[1])
                l += td(d, align='left', width='10%', style=styles[1])
                l += td(a, align='left', width='10%', style=styles[1])
                l += td(e, align='left', width='10%', style=styles[1])
                l += td(r, align='center', bgcolor=colors[r], style=styles[1])

    with open(filename, 'w') as f:
        f.write(str(doc))
        print('[+]   Created %s' % filename)


def create_csv_report(filename):
    """Creates a CSV report from the results."""
    with open(filename, 'w', newline='') as f:
        w = csv.writer(f, delimiter=';')
        w.writerow(headers)
        for n, t, b, d, a, e, r in sorted(set(results), key=lambda x: tuple(map(int, x[0].split('.')))):
            w.writerow([n, t, b, d, a, e, r])
        print('[+]   Created %s' % filename)


if __name__ == "__main__":
        main()
