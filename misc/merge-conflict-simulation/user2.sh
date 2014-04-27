#!/bin/bash

set -e

HERE="$( readlink -f "$( dirname "$BASH_SOURCE" )" )"
WORKDIR="$PWD"

PM="${WORKDIR}/venv/bin/password_manager"
export GNUPGHOME="${WORKDIR}/gnupghome-2"

git clone ./passwords ./passwords-2
cd ./passwords-2

echo "Secret4" | ${PM} secret put PW4
${PM} key regen

git add -A
git commit -m 'Changes by user #2'

echo "----------------------------------------------------------------------"
echo "Done. Now \`cd ${WORKDIR}/passwords-2 && git push' to break things"
