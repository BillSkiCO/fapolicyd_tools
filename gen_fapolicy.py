import re
from typing import TextIO, List
from pathlib import Path
import argparse

# Generate fapolicy rules from fapolicy deny_audit output
# /usr/bin/fapolicyd --permissive --deny-audit 2> fapolicy.output &
# This will run the fapolicyd daemon in the background, resume with 'fg'


# Remove rule=xxx pid=xxxxx from each fapolicyd generated rule in the deny list and change all perms to any
def line_formatter(deny_list: List[str]) -> List[str]:

    new_list = []

    # Replace inline
    for deny_policy in deny_list:

        deny_policy = re.sub(r'rule=\d* dec=deny_audit ', 'allow ', deny_policy)
        deny_policy = re.sub(r'pid=\d* ', '', deny_policy)
        deny_policy = re.sub(r'perm=\w*. ', 'perm=any ', deny_policy)

        new_list.append(deny_policy)

    # Remove list duplicates
    new_list = list(set(new_list))

    return new_list


def get_policy_lines(text_io: TextIO) -> List[str]:
    denied_list = []

    for line in text_io:
        if 'dec=deny_audit' in line:
            a = line.replace('\n', '')
            denied_list.append(a)

    return denied_list


def write_allow_file(allow_policy_list: List[str], location: str) -> None:

    print("Writing new allow policy file to : " + location)

    # Open new file for allow list and write all lines with newline at the end
    with open(location, "w") as out_file:
        for policy in allow_policy_list:
            out_file.write(policy + '\n')


# Set up command line argument parser
def arg_init() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        usage="%(prog)s --input <filepath> --output <filename>",
        description="Convert fapolicyd generated deny_audit file into fapolicyd allow rules"
    )
    p.add_argument("-i", "--input")
    p.add_argument("-o", "--output")

    return p


if __name__ == "__main__":

    # Init arg parser and pull in arguments that were passed into script
    parser = arg_init()
    args = parser.parse_args()

    # Try to open file locations from command line
    try:

        # If there are both input and output locations
        if args.input is not None and args.output is not None:
            output_full_path = str(Path(args.input_file).parent) + "/" + str(args.output_file)

            print("Opening fapolicyd deny_audit output file: " + str(args.input))
            with open(str(args.input), "r") as file:

                list_of_denied = get_policy_lines(file)
                allow_list = line_formatter(list_of_denied)
                write_allow_file(allow_list, output_full_path)
        else:
            error_str = "|| Input filepath (-i) = " + str(args.input) + " || " + "Output filename (-o) = " + str(args.output) + " ||"
            raise FileNotFoundError(error_str)

    except AttributeError as e:
        print("File Not Found - " + str(e))
