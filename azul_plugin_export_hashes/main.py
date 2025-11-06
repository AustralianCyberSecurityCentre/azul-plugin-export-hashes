"""Calculate export hashes for PE and ELF files.  Also calculate import hashes for ELF files."""

from azul_runner import (
    BinaryPlugin,
    Feature,
    FeatureType,
    Job,
    add_settings,
    cmdline_run,
)

from azul_plugin_export_hashes.exphash import get_dll_exphash, get_elf_hashes


class AzulPluginExportHashes(BinaryPlugin):
    """Calculate export hashes for PE and ELF files.  Also calculate import hashes for ELF files."""

    VERSION = "2025.03.18"
    SETTINGS = add_settings(
        filter_max_content_size=(int, 10 * 1024 * 1024),  # File size to process
        # PE and ELF
        # DOS EXE needed for corkami test samples
        filter_data_types={
            "content": [
                # Windows exe (com and dos can be useful.)
                "executable/windows/",
                # Non windows exe
                "executable/dll32",
                "executable/pe32",
                # Linux elf
                "executable/linux/",
            ]
        },
    )
    FEATURES = [
        Feature("pe_export_hash", desc="MD5 hash of the export entries", type=FeatureType.String),
        Feature("pe_export_hash_sorted", desc="MD5 hash of sorted export entries", type=FeatureType.String),
        Feature("elf_export_hash", desc="MD5 hash of the export entries", type=FeatureType.String),
        Feature("elf_export_hash_sorted", desc="MD5 hash of sorted export entries", type=FeatureType.String),
        Feature("elf_import_hash", desc="MD5 hash of the import entries", type=FeatureType.String),
        Feature("elf_import_hash_sorted", desc="MD5 hash of sorted import entries", type=FeatureType.String),
    ]

    def execute(self, job: Job):
        """Run the plugin."""
        buf = job.get_data().read()

        # quick PE magic check
        if buf.startswith(b"MZ"):
            if hashes := get_dll_exphash(buf):
                # we calculated md5 and sha256, only store md5, since imphashes are md5
                self.add_feature_values("pe_export_hash", hashes.get("export_md5"))
                self.add_feature_values("pe_export_hash_sorted", hashes.get("export_md5_sorted"))

        # quick ELF magic check
        elif buf.startswith(b"\x7fELF"):
            # also do some sneaky imphashing in here...
            if hashes := get_elf_hashes(buf):
                # what have we got here?
                self.logger.debug(hashes.keys())

                # do we have export hashes?
                if "export_md5" in hashes and "export_md5_sorted" in hashes:
                    # we calculated md5 and sha256, only store md5, since imphashes are md5
                    self.add_feature_values("elf_export_hash", hashes.get("export_md5"))
                    self.add_feature_values("elf_export_hash_sorted", hashes.get("export_md5_sorted"))

                # also calculated imphashes for elf, so set it
                if "import_md5" in hashes and "import_md5_sorted" in hashes:
                    self.add_feature_values("elf_import_hash", hashes.get("import_md5"))
                    self.add_feature_values("elf_import_hash_sorted", hashes.get("import_md5_sorted"))


def main():
    """Plugin command-line entrypoint."""
    cmdline_run(plugin=AzulPluginExportHashes)


if __name__ == "__main__":
    main()
