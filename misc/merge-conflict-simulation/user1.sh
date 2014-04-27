#!/bin/bash

set -e

HERE="$( readlink -f "$( dirname "$BASH_SOURCE" )" )"
WORKDIR="$PWD"

PM="${WORKDIR}/venv/bin/password_manager"
export GNUPGHOME="${WORKDIR}/gnupghome-1"

git clone ./passwords ./passwords-1
cd ./passwords-1

echo "Secret2b" | ${PM} secret put PW2
echo "Secret3" | ${PM} secret put PW3

git add PW2 PW3
git commit -m 'Changes by user #1'

echo "----------------------------------------------------------------------"
echo "Done. Now \`cd ${WORKDIR}/passwords-1 && git push' to break things"
