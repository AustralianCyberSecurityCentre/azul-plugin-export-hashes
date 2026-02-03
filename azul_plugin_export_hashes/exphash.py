"""Module to calculate export hashes for DLL files and export and import hashes for ELF files."""

import logging
from hashlib import md5, sha256

import lief


def get_dll_exphash(dll: bytes) -> dict | None:
    """Calculate the export hash of a DLL file.

    :param dll: DLL file to calculate the export hash for
    :returns: dict containing md5 and sha256 hashes if successful, None otherwise
    """
    # use lief to sanity check exported functions
    lief_pe = lief.parse(dll)

    # did lief return an error of some type?
    if not lief_pe or isinstance(lief_pe, lief.lief_errors):
        return None

    logging.info(f"lief thinks there are {len(lief_pe.exported_functions)} exports")

    # we fail here if non-ascii export name, which may or may not be a PE thing
    # lief can mix str and bytes here, because it hates us
    lief_exports = [_bytesify(x.name.lower()) for x in lief_pe.exported_functions]
    logging.info(f"export name types: {[type(x) for x in lief_exports]}")

    # lief found no exports, don't calculate export hashes
    if len(lief_exports) == 0:
        return None

    export_str = b",".join(lief_exports)
    export_str_sorted = b",".join(sorted(lief_exports))
    logging.debug(f"LIEF found exports {export_str}")

    hashes = {
        "export_md5": md5(export_str).hexdigest(),  # noqa: S324
        "export_sha256": sha256(export_str).hexdigest(),
        "export_md5_sorted": md5(export_str_sorted).hexdigest(),  # noqa: S324
        "export_sha256_sorted": sha256(export_str_sorted).hexdigest(),
    }

    return hashes


def get_elf_hashes(elf: bytes) -> dict | None:
    """Calculate import and export hashes for ELF files.

    All files should have some imports, only .so files should have exports.
    We rely on LIEF to identify imports and exports correctly.
    :param elf: ELF file to calculate import and export hashes for
    :returns: dict containing md5 and sha256 hashes if successful, None otherwise
    """
    # other tools for querying elf info:
    # objdump -T
    # nm -g
    # readelf -s

    an_elf = lief.parse(elf)

    # did lief return an error of some type?
    if not an_elf or isinstance(an_elf, lief.lief_errors):
        return None

    if elf[16:18] == b"\x03\x00":
        # probably shared object
        so = True
        logging.debug("ELF is a shared object, processing exports")
    elif elf[16:18] == b"\x02\x00":
        # probably not shared object
        so = False
        logging.debug("ELF is not a shared object, ignoring exports")
    else:
        # not sure if shared object or not, assuming not
        so = False
        logging.debug("ELF is not a shared object, ignoring exports")

    exports = []
    imports = []

    for function in an_elf.exported_functions:
        # LIEF is apparently walking both .symtab and .dynsym, then doing some filtering?
        if function.name not in exports:
            exports.append(function.name)

    for function in an_elf.imported_functions:
        # not sure how best to handle mangled function names
        if function.name not in imports:
            imports.append(function.name)

    hashes = {}

    # calculate export hashes if exports found and ELF is shared object
    if len(exports) != 0 and so:
        # build strings for hashing
        export_str = ",".join(exports).encode()
        export_str_sorted = ",".join(sorted(exports)).encode()
        hashes.update(
            {
                "export_md5": md5(export_str).hexdigest(),  # noqa: S324
                "export_sha256": sha256(export_str).hexdigest(),
                "export_md5_sorted": md5(export_str_sorted).hexdigest(),  # noqa: S324
                "export_sha256_sorted": sha256(export_str_sorted).hexdigest(),
            }
        )
        logging.debug(f"LIEF found exports {export_str}")

    # calculate import hashes if imports found
    if len(imports) != 0:
        # build strings for hashing
        import_str = ",".join(imports).encode()
        import_str_sorted = ",".join(sorted(imports)).encode()
        hashes.update(
            {
                "import_md5": md5(import_str).hexdigest(),  # noqa: S324
                "import_sha256": sha256(import_str).hexdigest(),
                "import_md5_sorted": md5(import_str_sorted).hexdigest(),  # noqa: S324
                "import_sha256_sorted": sha256(import_str_sorted).hexdigest(),
            }
        )
        logging.debug(f"LIEF found imports {import_str}")

    return hashes


def _bytesify(some_export):
    """Function used to map mixed str and bytes list to all bytes."""
    if type(some_export) is str:
        return some_export.encode()
    else:
        return some_export
