[![badge](https://github.com/quay/claircore/workflows/CI/badge.svg)](https://github.com/ComplianceAsCode/cvetool)

# CVE Tool

A [Claircore](https://github.com/quay/claircore)-based CVE manager (see also [clair-action](https://github.com/quay/clair-action/)).

# Install
You can install cvetool from the copr repos below.

* [![rhel copr badge](https://copr.fedorainfracloud.org/coprs/packit/ComplianceAsCode-cvetool-main-rhel/package/cvetool/status_image/last_build.png)](https://copr.fedorainfracloud.org/coprs/packit/ComplianceAsCode-cvetool-main-rhel/) - RHEL
* [![fedora copr badge](https://copr.fedorainfracloud.org/coprs/packit/ComplianceAsCode-cvetool-main-fedora/package/cvetool/status_image/last_build.png)](https://copr.fedorainfracloud.org/coprs/packit/ComplianceAsCode-cvetool-main-fedora/) - Fedora

# Build

Install Go development tools and libraries (`golang`) and GNU `make`.
Run 
```
$ make build
```
to build the CLI tool.

# Run

## Update (or Initialize) the Database

In order to use the tool for CVE analysis and report generation first the CVE database must be initialized 
and filled with CVE records.

Run
```
$ ./cvetool update
```
to create or update the DB (SQLite).

The `--db-path` argument is the path to the database location. 

> [!NOTE]
> If the parameter is omitted the tool creates database for the user in `~/.local/share/cvetool/matcher.db`.

The initial update procedure could take up to 30 minutes. Further incremental updates will be significantly faster.

## Scan Local System

Run
```
$ ./cvetool scan --root-path=/
```
to scan the underlying system and generate vulnerabilities report.

The `--root-path` argument defines root directory of the target file system.

## Scan a Container Image

Run
```
$ ./cvetool scan --image-path=./rhel-10-ubi.tar
```
to scan a `podman/docker image save ...`-compatible `.tar` image and generate vulnerabilities report.

## Scan a Virtual Machine Image

The tool does not directly support indexing VM images. But it can work with a mounted file system, e.g. with `guestmount`.

Run
```
$ mkdir -p ./rhel10-vm
$ guestmount -a ~/.local/share/gnome-boxes/images/rhel10.0 -i --ro ./rhel10-vm
```
to mount the file system, and then
```
$ ./cvetool scan --root-path=./rhel10-vm --db-path=./matcher.db
```
to scan and generate vulnerabilities report.

# Report Formats

Default report format is `plain`, which represents basic information about found vulnerabilities in a human-readable form.
It could be changed with the `--format` argument. Possible options are 'clair', 'quay' and 'sarif'.

# Help

Run the tool with `--help` argument for detailed information about invocation options.
