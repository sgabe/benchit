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
__version__ = '0.2.2'
__date__ = '2016/12/15'

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
from subprocess import check_call
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
module.add_argument('-d, --database', dest='database', action='store_true',
                    help='audit Oracle database')
module.add_argument('-l, --linux', dest='linux', action='store_true',
                    help='audit Linux system')
module.add_argument('-w, --windows', dest='windows', action='store_true',
                    help='audit Windows system')

parser.add_argument('-o, --output', dest='output', default='results',
                    help='output filename (default results_{timestamp}.html)')
parser.add_argument('-p, --path', dest='path', default='.',
                    help='base path to target directory (default .)')
parser.add_argument('-v, --verbose', dest='verbose', action='store_true',
                    help='run in verbose mode')
parser.add_argument('-s, --skip-dirlist', dest='skipdirlist', action='store_true',
                    help='skip directory list checking (default false)')
parser.add_argument('--debug', dest='debug', action='store_true',
                    help='run in debug mode (default false)')
parser.add_argument('--no-color', dest='nocolor', action='store_true',
                    help='disable colored output (default false)')
parser.add_argument('-i, --ignore-case', dest='ignorecase', action='store_true',
                    help='perform case-insensitive matching (default false)')

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

if args.nocolor:
    WHITE = ''
    GREY = ''
    RED = ''
    GREEN = ''
    BLUE = ''
else:
    WHITE = '\033[0m'
    GREY = '\033[90m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    BLUE = '\033[94m'


def main():
    global audit, results, total, passed, failed, errors

    start_time = time.time()

    config = ConfigObj('benchit.ini')

    if args.database:
        print_info('Oracle detected!')
        audit = config['Database']['Oracle']
    elif args.windows:
        print_info('Windows detected!')
        audit = config['Windows']['2012']
    elif args.linux:
        for distro in ['CentOS', 'RedHat', 'SuSe', 'LSB', 'Debian']:
            if os.path.isfile('{}/etc/{}-release'.format(args.path, distro)):
                print_info('{} Linux detected!', distro)
                audit = config['Linux'][distro]
                break

    if audit is None:
        print_warning('Nothing to audit...')
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

    print_info('Audit in progress, this can take a while...')

    for category, records in items.items():
        print_info('  Checking items in category {}...', category)
        category = ast.literal_eval(category)
        for filepath, checks in records.items():
            fullpath = '/'.join([args.path, filepath])
            check_item_preprocess(fullpath)
            if category is not None:
                print_status('    Processing {}', filepath)
                if args.verbose:
                    print()
                if args.database:
                    check_item_database(fullpath, checks, category)
                elif args.linux or args.windows:
                    check_item_os(fullpath, checks, category)
            else:
                for command, number, title, description, *_ in checks:
                    try:
                        total += 1
                        print_status('    Processing {}', filepath)
                        if not os.path.isfile('/'.join([args.path, filepath])):
                            raise IOError()
                        command = command.format(args.path)
                        if args.verbose:
                            print()
                            print_verbose('    Executing {}', command)
                        output = check_output(command, shell=True)
                        if not args.verbose:
                            print_good('OK!')
                        if output:
                            failed += 1
                            result = 'Fail'
                        else:
                            passed += 1
                            result = 'Pass'
                    except (IOError, OSError) as e:
                        print_error('Not found!')
                        errors += 1
                        result = 'Error'
                    results.append((
                        number,
                        title,
                        description,
                        '',  # default
                        '',  # actual
                        '',  # expected
                        result))

    print_info('Audit finished in {:f} seconds!', time.time() - start_time)

    timestamp = time.strftime("%Y%m%dT%H%M%S")
    filename = '{}_{}'.format(args.output, timestamp)
    create_html_report('{}.html'.format(filename))
    create_csv_report('{}.csv'.format(filename))


def check_item_preprocess(filepath):
    # Convert UTF-16 encoded files (created by reg export) to UTF-8
    if args.windows and '.reg' in filepath:
        try:
            with io.open(filepath, 'r', encoding='utf-16') as f:
                text = f.read()
            with io.open(filepath, 'w', encoding='utf-8') as f:
                f.write(text)
        except (UnicodeError, UnicodeDecodeError, IOError) as e:
            pass
    # Processing large directory content lists ("ls -Ral /") can be very slow.
    # Copy out the necessary directory lists into smaller files.
    if args.linux and 'dirlist-' in filepath and not os.path.isfile(filepath):
        command = 'grep -P "^/{0}:[\s\S]*" -A500 {1} | sed -e "/^$/,$d" > {2}'
        command = command.format(
            filepath[filepath.index('-')+1:-4].replace('-', '/'),
            filepath[:filepath.index('-'):] + '.txt',
            filepath
        )
        check_call(command, shell=True)


def check_item_os(filename, items, category):
    """Checks every regex pattern listed in the loaded CSV file."""
    global results, total, passed, failed, errors
    if args.linux and args.skipdirlist and ('dirlist.txt' in filename):
        return
    try:
        with open(filename, 'r', encoding='utf8') as f:
            string = f.read().replace('\\', '\\\\')
            for pattern, number, title, summary, default, expected in items:
                total += 1
                flags = (re.M | re.I) if args.ignorecase else re.M
                match = re.search(pattern, string, flags)
                if len(expected) == 0:
                    expected = 'N/A'
                # We did not find anything to work with
                if not match:
                    match = 'N/F'
                # We found a match and we are not interested in the details
                elif len(match.groups()) == 0:
                    match = 'N/A'
                # We found a match and we have a subgroup to check
                else:
                    match = match.group(1)
                # Convert null-terminated strings from HEX to ASCII
                if args.windows and match.startswith('hex'):
                    match = re.sub('(00,?|[\s,]|\\\\)', '', match[7:])
                    match = binascii.unhexlify(match)
                    match = str(match)[2:-1]
                # We expect a match
                if category is True:
                    # We found a match
                    if match != 'N/F':
                        # Any value is accepted
                        if expected == 'N/A':
                            passed += 1
                            result = 'Pass'
                        # Check relational (>, <, =) values
                        elif check_item_relational(match, expected):
                            passed += 1
                            result = 'Pass'
                        else:
                            failed += 1
                            result = 'Fail'
                    # We have a default value
                    elif len(default) != 0 and check_item_default(default, expected):
                            passed += 1
                            result = 'Pass'
                    else:
                        failed += 1
                        result = 'Fail'
                # We don't expect a match
                elif category is False and match == 'N/F':
                    passed += 1
                    result = 'Pass'
                else:
                    failed += 1
                    result = 'Fail'
                results.append((
                    number,
                    title,
                    summary,
                    default,
                    match,
                    expected,
                    result
                ))
                if args.verbose:
                    print_verbose(
                        '        '
                        'N:{:15.15s}'
                        'D:{:20.20s}'
                        'M:{:20.20s}'
                        'E:{:20.20s}'
                        'R:{:5.5s}'.format(
                            number,
                            default,
                            match,
                            expected,
                            result
                        ))
            if not args.verbose:
                print_good('OK!')
    except IOError as err:
        if err.errno is 2:
            if not args.verbose:
                print_error('Not found!')
            for pattern, number, title, summary, default, expected in items:
                total += 1
                match = 'N/F'
                if len(default) != 0:
                    if check_item_default(default, expected):
                        passed += 1
                        result = 'Pass'
                    else:
                        failed += 1
                        result = 'Fail'
                else:
                    errors += 1
                    result = 'Error'
                results.append((
                    number,
                    title,
                    summary,
                    default,
                    match,
                    expected,
                    result
                ))
                if args.verbose:
                    print_verbose(
                        '        '
                        'N:{:15.15s}'
                        'D:{:20.20s}'
                        'M:{:20.20s}'
                        'E:{:20.20s}'
                        'R:{:5.5s}'.format(
                            number,
                            default,
                            match,
                            expected,
                            result
                        ))
        return


def check_item_default(default, expected):
    """Checks the default value when the specific setting is not available."""
    if expected[:1] in ['>', '<'] and not default.startswith('Not '):
        return check_item_relational(default, expected)
    elif default == expected:
        return True
    else:
        return False


def check_item_relational(actual, expected):
    """Checks for acceptable lesser or greather values."""
    if expected[:1] == '>' and int(actual) >= int(expected[1:]):
        return True
    elif expected[:1] == '<' and int(actual) <= int(expected[1:]):
        return True
    elif actual == expected:
        return True
    else:
        return False


def check_item_database(filename, items, category):
    """Checks every query listed in the loaded CSV file."""
    global results, total, passed, failed, errors
    try:
        for query, number, title, summary, default, expected in items:
            query = query.format(filename)
            if args.verbose:
                print_verbose('      {}'.format(query))
            if not os.path.isfile(filename):
                raise IOError('{} not found!'.format(filename))
            total += 1
            params = ['q', '-H', '-d', ';', query]
            output = str(check_output(params, shell=True).strip())
            if output.startswith('b\''):
                output = output[2:-1]
            if category is True:
                if output == expected:
                    passed += 1
                    result = 'Pass'
                else:
                    failed += 1
                    result = 'Fail'
            elif category is False:
                if output:
                    failed += 1
                    result = 'Fail'
                else:
                    passed += 1
                    result = 'Pass'
            results.append((
                number,
                title,
                summary,
                default,
                output,
                expected,
                result
            ))
        if not args.verbose:
            print_good('OK!')
    except (IOError, OSError) as err:
        print_error('Error: {}'.format(err))
        for query, number, title, summary, default, expected in items:
            total += 1
            errors += 1
            results.append((
                number,
                title,
                summary,
                default,
                '',
                expected,
                'Error'
            ))
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
            for number, title, summary, default, actual, expected, result in sorted(set(results), key=lambda x: tuple(map(int, x[0].split('.')))):
                l = tr(style='border:1px solid black')
                l += td(number, align='left', width='5%', style=styles[1])
                l += td(title, align='left', width='32%', style=styles[1])
                l += td(summary, align='left', width='30%', style=styles[1])
                l += td(default, align='left', width='10%', style=styles[1])
                l += td(actual, align='left', width='10%', style=styles[1])
                l += td(expected, align='left', width='10%', style=styles[1])
                l += td(result, align='center', bgcolor=colors[result], style=styles[1])

    print_status('  Creating {}', filename)
    with open(filename, 'w') as f:
        f.write(str(doc))
        print_good('OK!')


def create_csv_report(filename):
    """Creates a CSV report from the results."""
    print_status('  Creating {}', filename)
    with open(filename, 'w', newline='') as f:
        w = csv.writer(f, delimiter=';')
        w.writerow(headers)
        for number, title, summary, default, actual, expected, result in sorted(set(results), key=lambda x: tuple(map(int, x[0].split('.')))):
            w.writerow([number, title, summary, default, actual, expected, result])
        print_good('OK!')


def print_info(info_msg, format_string=''):
    print(BLUE + '[*] ' + info_msg.format(format_string) + WHITE)


def print_status(status_msg, format_string=''):
    print(WHITE + '[+] ' + status_msg.format(format_string) + WHITE, end='')


def print_good(good_msg, format_string=''):
    print(' ' + GREEN + good_msg.format(format_string) + WHITE)


def print_error(error_msg, format_string=''):
    print(' ' + RED + error_msg.format(format_string) + WHITE)


def print_warning(warning_msg, format_string=''):
    print(RED + '[!] ' + warning_msg.format(format_string) + WHITE)


def print_verbose(verbose_msg, format_string=''):
    print(GREY + '[V] ' + verbose_msg.format(format_string) + WHITE)


if __name__ == "__main__":
    main()
