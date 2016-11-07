BenchIT
===============

**BenchIT** is a simple Python script for security auditing purposes. It is the most useful for auditing systems by analyzing files collected from remote hosts. It allows you to check certain system settings stored in configuration files by using regular expressions. The simplest check will determine if a pattern matches. However, with capturing groups it is also possible to determine whether the actual value matches the expected or the default value. Results are summarized in a HTML report and also stored in a CSV file.

Regular expressions must be stored in a CSV file containing the following columns separated by a semicolon (;):
  - Boolean value which determines whether we expect a match or not ("True").
  - Name of the file ("sshd_config").
  - Regular expression to evaluate ("^Protocol[ \t]+(\d)$").
  - Number of the chaper in the given CIS guideline ("9.2.1").
  - Title of the chapter in the given CIS guideline ("Set SSH Protocol to 2").
  - Short summary of the chapter ("SSH supports two different protocols...").
  - Default value of the setting ("2,1").
  - Expected value of the setting ("2").

## Usage

Choose target system (`-w` for Windows, `-l` for Linux and `-d` for Database) and specify the path to the directory (`-p`) containing the configuration files. Some information will be displayed on the console, however, the results will be summarized in a HTML report and also saved to a CSV file.

### Options
```
$ python benchit.py -h
                     ____                  _     _____ _______
                    |  _ \     v0.1.5     | |   |_   _|__   __|
                    | |_) | ___ _ __   ___| |__   | |    | |
                    |  _ < / _ \ '_ \ / __| '_ \  | |    | |
                    | |_) |  __/ | | | (__| | | |_| |_   | |
                    |____/ \___|_| |_|\___|_| |_|_____|  |_|

usage: benchit [-h] (-d, --database | -l, --linux | -w, --windows)
               [-o, --output O] [-p, --path P] [-v, --verbose] [--skipdirlist]
               [--debug]

optional arguments:
  -h, --help      show this help message and exit
  -d, --database  audit Oracle database
  -l, --linux     audit Linux system
  -w, --windows   audit Windows system
  -o, --output O  output filename (default results_{timestamp}.html)
  -p, --path P    base path to target directory (default .)
  -v, --verbose   run in verbose mode
  --skipdirlist   skip directory list checking (default false)
  --debug         run in debug mode (default false)
```

## License
This project is licensed under the terms of the MIT license.
