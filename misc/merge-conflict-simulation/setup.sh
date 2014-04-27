#!/bin/bash

set -e

HERE="$( readlink -f "$( dirname "$BASH_SOURCE" )" )"
REPOROOT="$( readlink -f "${HERE}/../../" )"

TEMPDIR="$( mktemp -d )"

cd "${TEMPDIR}"

cat <<EOF
----------------------------------------------------------------------

    STARTING SETUP IN 3 SECONDS

    Workdir: ${TEMPDIR}

----------------------------------------------------------------------
EOF

sleep 3

echo "----------------------------------------------------------------------"
echo "    Creating GPG homes"
echo "----------------------------------------------------------------------"

mkdir -p "${TEMPDIR}"/gnupghome-1 "${TEMPDIR}"/gnupghome-2
chmod 700 "${TEMPDIR}"/gnupghome-1 "${TEMPDIR}"/gnupghome-2


echo "----------------------------------------------------------------------"
echo "    Installing Password Manager"
echo "----------------------------------------------------------------------"

virtualenv "${TEMPDIR}/venv"
"${TEMPDIR}/venv/bin/pip" install -r "${REPOROOT}"/requirements.txt "${REPOROOT}"


echo "----------------------------------------------------------------------"
echo "    Import keys for the users"
echo "----------------------------------------------------------------------"

GNUPGHOME="${TEMPDIR}/gnupghome-1" gpg --import "${REPOROOT}/tests/keys/key1.sec"
GNUPGHOME="${TEMPDIR}/gnupghome-1" gpg --import "${REPOROOT}/tests/keys/key1.pub"
GNUPGHOME="${TEMPDIR}/gnupghome-1" gpg --import "${REPOROOT}/tests/keys/key2.pub"

GNUPGHOME="${TEMPDIR}/gnupghome-2" gpg --import "${REPOROOT}/tests/keys/key2.sec"
GNUPGHOME="${TEMPDIR}/gnupghome-2" gpg --import "${REPOROOT}/tests/keys/key1.pub"
GNUPGHOME="${TEMPDIR}/gnupghome-2" gpg --import "${REPOROOT}/tests/keys/key2.pub"


echo "----------------------------------------------------------------------"
echo "    Initialize the reposiory"
echo "----------------------------------------------------------------------"

mkdir -p "${TEMPDIR}/passwords"
cd "${TEMPDIR}/passwords"

export GNUPGHOME="${TEMPDIR}/gnupghome-1"
"${TEMPDIR}/venv/bin/password_manager" setup \
    "$( cat ${REPOROOT}/tests/keys/key1.fpr )" \
    "$( cat ${REPOROOT}/tests/keys/key2.fpr )"


echo "----------------------------------------------------------------------"
echo "    Create some secrets"
echo "----------------------------------------------------------------------"

export GNUPGHOME="${TEMPDIR}/gnupghome-1"
echo "Secret1" | "${TEMPDIR}/venv/bin/password_manager" secret put PW1
echo "Secret2" | "${TEMPDIR}/venv/bin/password_manager" secret put PW2


echo "----------------------------------------------------------------------"
echo "    Initialize git repo & commit"
echo "----------------------------------------------------------------------"

git init .
git add .keys
git commit -m "Import keys"
git add PW1 PW2
git commit -m "Added some passwords"


cat <<EOF
# User #1 should run this
cd "${TEMPDIR}"
export GNUPGHOME="${TEMPDIR}/gnupghome-1"
${HERE}/user1.sh

# User #2 should run this
cd "${TEMPDIR}"
export GNUPGHOME="${TEMPDIR}/gnupghome-1"
${HERE}/user2.sh
EOF
