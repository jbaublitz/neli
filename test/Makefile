all: base ubuntu-musl-build rust-musl-ci-build

base:
	sudo docker pull ubuntu

ubuntu-musl-build:
	sudo docker build --no-cache -t ubuntu-musl ubuntu-musl

rust-musl-ci-build:
	sudo docker build --no-cache -t rust-musl-ci rust-musl-ci
