# This script takes care of testing your crate

set -ex

main() {
    cargo build --target $TARGET
    cargo build --target $TARGET --release

    if [ ! -z $DISABLE_TESTS ]; then
        return
    fi

    cargo test --target $TARGET
    cargo test --target $TARGET --release

    # cross run --target $TARGET
    # cross run --target $TARGET --release
}

# we don't run the "test phase" when doing deploys
if [ -z $TRAVIS_TAG ]; then
    main
fi
