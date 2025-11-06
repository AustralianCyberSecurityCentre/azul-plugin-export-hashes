# Azul Plugin Export Hashes

Calculate export hashes for PE and ELF files. Also calculate import hashes for ELF files.

## Development Installation

To install azul-plugin-export-hashes for development run the command
(from the root directory of this project):

```bash
pip install -e .
```

## Usage

Usage on local files:

```
$ azul-plugin-export-hashes malware.file

```

Example PE output:

```
  output features:
           pe_export_hash: 766756d270d8eb254563c7aa22f7ef47
    pe_export_hash_sorted: 766756d270d8eb254563c7aa22f7ef47

Feature key:
  pe_export_hash:  MD5 hash of the export entries
  pe_export_hash_sorted:  MD5 hash of sorted export entries
```

Example ELF output:

```
  output features:
           elf_export_hash: 32cab333f0c2f9bde51c5b4debbf4a24
    elf_export_hash_sorted: a11fece009dbbadc99a8ee307e7d5cd6
           elf_import_hash: 2a517a5beb65ecd5e5d3d9a69a778860
    elf_import_hash_sorted: fd25e9d84134406460cc9822af2f961a

Feature key:
  elf_export_hash:  MD5 hash of the export entries
  elf_export_hash_sorted:  MD5 hash of sorted export entries
  elf_import_hash:  MD5 hash of the import entries
  elf_import_hash_sorted:  MD5 hash of sorted import entries
```

Some ELF/DLL files may not have exports, or the underlying parsing library (lief) does not see them. This yields successful completion with no features extracted.

Check `azul-plugin-export-hashes --help` for advanced usage.

## Python Package management

This python package is managed using a `setup.py` and `pyproject.toml` file.

Standardisation of installing and testing the python package is handled through tox.
Tox commands include:

```bash
# Run all standard tox actions
tox
# Run linting only
tox -e style
# Run tests only
tox -e test
```

## Dependency management

Dependencies are managed in the requirements.txt, requirements_test.txt and debian.txt file.

The requirements files are the python package dependencies for normal use and specific ones for tests
(e.g pytest, black, flake8 are test only dependencies).

The debian.txt file manages the debian dependencies that need to be installed on development systems and docker images.

Sometimes the debian.txt file is insufficient and in this case the Dockerfile may need to be modified directly to
install complex dependencies.
