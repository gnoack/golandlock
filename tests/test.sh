#!/bin/bash
# The go-landlock tests are currently just a shell script. Running
# Landlock from within a regular Go test is harder to manage, as tests
# can interfere with each other.

enter () {
    printf "  [Test] %60s" "$*"
}

success () {
    echo -e " \e[1;32m[pass]\e[0m"
}

fail () {
    echo -e " \e[1;31m[fail]\e[0m"
    echo
    echo "****************"
    echo $*
    echo "****************"
    echo
    echo "Direcory contents:"
    find .
    echo
    echo "Stdout:"
    cat stdout.txt
    echo
    echo "Stderr:"
    cat stderr.txt
    exit 1
}

shutdown() {
    rm -rf "${TMPDIR}"
}

expect_success() {
    if [ "$?" -ne 0 ]; then
        fail "Expected:" $*
    fi
    success
}

expect_failure() {
    if [ "$?" -eq 0 ]; then
        fail "Expected:" $*
    fi
    success
}

# Run
run() {
    "${CMD}" "-${LANDLOCK_VERSION}" -v -strict -ro /bin /usr $* >stdout.txt 2>stderr.txt
}

if [ ! -f "go.mod" ] || [ "$(head -n1 go.mod)" != "module github.com/landlock-lsm/go-landlock" ]; then
    echo "Need to run from go-landlock directory"
    exit 1
fi

CMD="$(pwd)/bin/landlock-restrict"
if [ ! -f "${CMD}" ]; then
    echo "Sandboxing command does not exist: ${CMD} Building."
    mkdir -p bin
    go build -o "$CMD" cmd/landlock-restrict/main.go
fi

ABICMD="$(pwd)/bin/landlock-abi-version"
if [ ! -f "${ABICMD}" ]; then
    echo "Sandboxing command does not exist: ${ABICMD} Building."
    mkdir -p bin
    go build -o "$ABICMD" cmd/landlock-abi-version/main.go
fi

SUPPORTED_LANDLOCK_VERSION=$("${ABICMD}")

TMPDIR=$(mktemp -t -d go-landlock-test.XXXXXX)
echo "Running in ${TMPDIR}"
cd "${TMPDIR}"
trap shutdown EXIT

# Set up an initial environment:
mkdir -p foo
echo lolcat > foo/lolcat.txt

for LANDLOCK_VERSION in $(seq 1 "${SUPPORTED_LANDLOCK_VERSION}"); do
    echo
    echo "LANDLOCK VERSION ${LANDLOCK_VERSION}"

    # Tests
    enter "No sandboxing, read works"
    /bin/cat foo/lolcat.txt > /dev/null
    expect_success "reading file should have worked"

    enter "No permissions, doing nothing succeeds"
    run -- /bin/true
    expect_success "doing nothing should succeed"

    enter "No permissions, read fails"
    run -- /bin/cat foo/lolcat.txt
    expect_failure "should have failed to read file"

    enter "Read permissions on dir (relative path), read works"
    run -ro "foo" -- /bin/cat foo/lolcat.txt
    expect_success "should have read the file"

    enter "Read permissions on dir (full path), read works"
    run -ro "${TMPDIR}/foo" -- /bin/cat foo/lolcat.txt
    expect_success "should have read the file"

    enter "Read permissions on file, read works"
    run -rofiles "foo/lolcat.txt" -- /bin/cat foo/lolcat.txt
    expect_success "should have read the file"

    enter "File-read permissions on dir, read works"
    run -rofiles "foo" -- /bin/cat foo/lolcat.txt
    expect_success "should have read the file"

    enter "Read-only permissions on dir, creating file fails"
    run -ro "foo" -- /bin/touch foo/fail
    expect_failure "should not be able to create file"

    enter "RW permissions on dir, creating file succeeds"
    run -rw "foo" -- /bin/touch foo/succeed
    expect_success "should be able to create file"

    enter "Read-only permissions on dir, removing file fails"
    run -ro "foo" -- /bin/rm foo/succeed
    expect_failure "should not be able to remove file"

    enter "RW permissions on dir, removing file succeeds"
    run -rw "foo" -- /bin/rm foo/succeed
    expect_success "should be able to remove file"

    enter "Read-only permissions on dir, mkfifo fails"
    run -ro "foo" -- /bin/mkfifo foo/fifo
    expect_failure "should not be able to create file"

    enter "RW permissions on dir, mkfifo succeeds"
    run -rw "foo" -- /bin/mkfifo foo/fifo
    expect_success "should be able to create file"
    rm foo/fifo

    enter "Linking files between directories with refer permission"
    mkdir bar
    run -rw +refer foo bar -- /bin/ln foo/lolcat.txt bar/lolcat.txt
    case "${LANDLOCK_VERSION}" in
        1) expect_failure "Landlock V1: SHOULD NOT be able to move a file between directories" ;;
        2) expect_success "Landlock V2: SHOULD be able to move a file between directories" ;;
    esac
    rm -f bar/lolcat.txt
    rmdir bar
done

echo
echo "PASS"
