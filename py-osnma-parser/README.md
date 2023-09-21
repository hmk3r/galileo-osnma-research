# py-osnma-parser

py-osnma-parser is a parser and verifier for Galileo OSNMA data

## ⚠️ NOTE ⚠️

As of 3 August 2023, OSNMA switched public key format, so this project will no longer work and needs patching.

I've provided previous GNSS samples that use the old keys for testing in [data](./data/)(they do not my location though)

## Capabilities

The parser reads the data from a CSV file, where each row is a Galileo I/NAV nominal page, provided in the format:

```csv
osnma,[PRN],[Word type],[HKROOT message],[MACK message],[navdata]
```

The verifier supports:

- DSM-KROOT verification
- TESLA Chain Key Verification
- MAC Look-up Table Verification
- MACSEQ Verification
- Tag Verification

This functionality allows for complete verification of navigational data.

Not implemented (due to lack of test data):

- DSM-PKR verification
- TESLA Chain state transitions
- Chain revocation
- Public key revocation

## Usage

Before running, install the dependencies using

```shell
> pip install -r requirements.txt
```

To run the program:

```shell
> python3 main.py [samples_file.csv] [osnma_public_keys_dir]
```

- `samples_file.csv` - path to the CSV file with samples; Default:  [./data/osnma-capture.csv](./data/osnma-capture.csv)
- `osnma_public_keys_dir` - path to the folder containing the public ECDSA OSNMA keys; Default:  [./osnma-keys/](./osnma-keys/)

An assortment of CSV sample files is provided in [./data](./data/) and example outputs of the program are provided in [./log](./log/)

An example invocation of the program would be

```shell
> python3 main.py data/osnma-galmon-hkroot-change.csv
```

As the output is long, it is recommended to pipe the output to a program like `less`

```shell
> python3 main.py data/osnma-galmon-hkroot-change.csv | less
```

or save it to a file

```shell
> python3 main.py data/osnma-galmon-hkroot-change.csv > log/example.log
```

## Obtaining CSV samples

Below you can find instructions on how to retrieve your own OSNMA CSV samples and run them through py-osnma-parser.

### Patched version of GNSS-SDR

[GNSS-SDR](https://github.com/gnss-sdr/gnss-sdr) can be patched to output the data in the CSV format required above.

To do so, simply apply the [patch](./tools/gnss-sdr-osnma-log.patch) ([./tools/gnss-sdr-osnma-log.patch](./tools/gnss-sdr-osnma-log.patch)) on a fresh copy of gnss-sdr

```shell
> git clone https://github.com/gnss-sdr/gnss-sdr.git
> cd gnss-sdr
> git apply /path/to/gnss-sdr-osnma-log.patch
```

and follow the build instructions in gnss-sdr's README.

The patched version will then output the osnma data to `C++`'s `std::cerr` in the CSV format specified before. To store it, redirect the standard error stream to a file:

```shell
> ./gnss-sdr --config_file=/path/to/my_receiver.conf 2>/tmp/osnma-data-gnss-sdr.csv
```

Then, run it through the parser:

```shell
> python3 main.py /tmp/osnma-data-gnss-sdr.csv
```

### Galmon data stream

OSNMA data can be retrieved from Galmon's navigational data stream. The tool `galmon_to_csv` (found in [./tools/galmon_to_csv.py](./tools/galmon_to_csv.py)) was developed for this purpose.

To get the data samples, you'll need a (stable) internet connection.

The tool outputs the data to the standard output, in the CSV format specified before. Therefore, samples are recorded in the following way:

```shell
> python3 tools/galmon_to_csv.py > data/osnma-data-galmon.csv
```

This can be then ran through py-osnma-parser like so:

```shell
> python3 main.py data/osnma-data-galmon.csv
```
