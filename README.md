# Sentinel-LX

A small Linux system activity collector written in C.

With cyber threats becoming increasingly serious, including in Japan, I wanted to build something useful with C and see what I could make.

I'm still learning C, so the code is far from perfect. There are probably plenty of things that could be written better, simpler, or just differently.

But it works, and I think it has become something useful.

## What it can do

Sentinel-LX can collect and record information about:

* Processes and parent processes
* Process execution context
* Network activity
* Related events and their context
* Local event records for later inspection

The goal is to make it easier to understand what happened on a Linux system after an event occurs.

## What it can't do

Sentinel-LX is not a complete security solution.

It does not automatically determine whether an event is malicious, prevent attacks, or replace proper security monitoring and incident response.

It is simply a small tool for collecting and keeping useful system activity data.

## Contributing

If you find a bug, have an idea, or want to contribute, please let me know.

Code, tests, documentation, and simple feedback are all welcome.

## Status

Early development.

Currently Linux only.

BSD support is planned for the future.


## Build

```sh
make
```

## Test

```sh
make test
```

## License

BSD 2-Clause License.
