import argparse
import os
import shlex
import subprocess


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--template", default="template.yml")
    parser.add_argument("-o", "--output-file", default="packaged-template.yml")
    parser.add_argument("-s3", "--s3-repo")
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser.parse_args()  # $ Source


def main():
    args = get_args()

    cmd = f"sam validate --template {args.template} --lint"
    os.system(cmd)  # $ Alert

    cmd = f"sam package --output-template-file {args.output_file}"
    cmd = cmd + " --resolve-s3" if args.s3_repo is None else cmd + f" --s3-repo {args.s3_repo}"
    cmd = cmd + " --debug" if args.verbose else cmd
    os.system(cmd)  # $ Alert

    # Safe: no shell, each argument is passed as a separate argv entry.
    subprocess.run(["sam", "build", "--template", args.template], check=True)

    # Safe: constant command line.
    os.system("sam --version")


if __name__ == "__main__":
    main()
