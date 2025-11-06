"""Test cases for plugin output."""

from azul_runner import FV, Event, JobResult, State, test_template

from azul_plugin_export_hashes.main import AzulPluginExportHashes


class TestExecute(test_template.TestPlugin):
    """Test plugin execution."""

    PLUGIN_TO_TEST = AzulPluginExportHashes

    def test_invalid_sample(self):
        """Test on Godzilla webshell - 2c6c0edc953907d4f65049544433b4b48cb6fc23e29d3f327cd975fb05ca2b9b."""
        with self.assertRaises(AssertionError):
            data = self.load_test_file_bytes(
                "2c6c0edc953907d4f65049544433b4b48cb6fc23e29d3f327cd975fb05ca2b9b",
                "Malicious text file, webshell, Malware Family BLUEBEAM.JSP.",
            )
            self.do_execution(data_in=[("content", data)])

    def test_simple_dll(self):
        """Test on known STONEDOWN dll - a7d81c1f20df1b0e0dcfcf50c1c3dae8556ee8335e5f56d4e365367a41a03475.

        Only exports InitGadgets, so unsorted and sorted match.
        """
        data = self.load_test_file_bytes(
            "a7d81c1f20df1b0e0dcfcf50c1c3dae8556ee8335e5f56d4e365367a41a03475",
            "Malicious Windows 32DLL, malware family BEANSLICE.",
        )
        result = self.do_execution(data_in=[("content", data)])
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="a7d81c1f20df1b0e0dcfcf50c1c3dae8556ee8335e5f56d4e365367a41a03475",
                        features={
                            "pe_export_hash": [FV("766756d270d8eb254563c7aa22f7ef47")],
                            "pe_export_hash_sorted": [FV("766756d270d8eb254563c7aa22f7ef47")],
                        },
                    )
                ],
            ),
        )

    def test_fragtor_dll(self):
        """Test on fragtor DLL - 12bcb9015416e09c3a3ff3881a2b0a84ef6e5db5613629f9b80454f5fa0e7d24."""
        data = self.load_test_file_bytes(
            "12bcb9015416e09c3a3ff3881a2b0a84ef6e5db5613629f9b80454f5fa0e7d24",
            "Malicious Windows 32DLL, malware family fragtor.",
        )
        result = self.do_execution(data_in=[("content", data)])
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="12bcb9015416e09c3a3ff3881a2b0a84ef6e5db5613629f9b80454f5fa0e7d24",
                        features={
                            "pe_export_hash": [FV("e340d42e9eb6bec4726a07c292a16439")],
                            "pe_export_hash_sorted": [FV("641e0daa9d5d8996a036df8e1aae5412")],
                        },
                    )
                ],
            ),
        )

    def test_golang_dll(self):
        """Test on golang CobaltStrike dll - 8f31ac74fc288a7cb8211e49c2fce3dcc0e7a5ef38c64d881b87438ae1260fba."""
        data = self.load_test_file_bytes(
            "8f31ac74fc288a7cb8211e49c2fce3dcc0e7a5ef38c64d881b87438ae1260fba",
            "Malicious Windows 32DLL, cobaltStrike beacon, malware family BEACON.",
        )
        result = self.do_execution(data_in=[("content", data)])
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="8f31ac74fc288a7cb8211e49c2fce3dcc0e7a5ef38c64d881b87438ae1260fba",
                        features={
                            "pe_export_hash": [FV("9121bf2bf97401eac76aa078a83fb833")],
                            "pe_export_hash_sorted": [FV("e27c561dfb001262dce153d5fb44f1f4")],
                        },
                    )
                ],
            ),
        )

    def test_weird_dll(self):
        """Test dll with weird exports - f472b585de1699e2cb35bfdc9ba760e3d6c2669e807e1a515cb2d489706e59ad.

        Obtained from https://github.com/corkami/pocs/blob/master/PE/bin/dllweirdexp.dll
        """
        data = self.load_test_file_bytes(
            "f472b585de1699e2cb35bfdc9ba760e3d6c2669e807e1a515cb2d489706e59ad", "Malicious Windows 32DLL, spreader."
        )
        result = self.do_execution(data_in=[("content", data)])
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="f472b585de1699e2cb35bfdc9ba760e3d6c2669e807e1a515cb2d489706e59ad",
                        features={
                            "pe_export_hash": [FV("7e6f3c2e42b834e2d2f182193869ed13")],
                            "pe_export_hash_sorted": [FV("ca54aae91580add6cdf37169ffc6e3e5")],
                        },
                    )
                ],
            ),
        )

    def test_ord_dll(self):
        """Test dll with ordinal exports - b6a63852db7a65e87ef8079db0184af4defe8f0be233935a0a8b51d8df6b0e46.

        Obtained from https://github.com/corkami/pocs/blob/master/PE/bin/dllord.dll
        pefile is unable to find any exports, so no export hash can be calculated.
        """
        data = self.load_test_file_bytes(
            "b6a63852db7a65e87ef8079db0184af4defe8f0be233935a0a8b51d8df6b0e46", "Malicious WIndows 32DLL."
        )
        result = self.do_execution(data_in=[("content", data)])
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED_EMPTY),
            ),
        )

    def test_non_ascii_dll(self):
        r"""Test dll with manually hacked non-ascii export - 33cf70e2fcb4304a6786bd7d0de529a63c2c036675d729cb397bfc501bb9c59c.

        Derived from cobaltstrike secondstage with single export changed to RunDllEntr\xff
        """
        data = self.load_test_file_bytes(
            "33cf70e2fcb4304a6786bd7d0de529a63c2c036675d729cb397bfc501bb9c59c",
            "Derived from cobaltstrike secondstage with single export changed to RunDllEntr\\xff",
        )
        result = self.do_execution(data_in=[("content", data)])
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="33cf70e2fcb4304a6786bd7d0de529a63c2c036675d729cb397bfc501bb9c59c",
                        features={
                            "pe_export_hash": [FV("0286a1014a50dd9ae4d06ecc63073f5f")],
                            "pe_export_hash_sorted": [FV("0286a1014a50dd9ae4d06ecc63073f5f")],
                        },
                    )
                ],
            ),
        )

    def test_error_input(self):
        """Test sample with empty exports."""
        data = self.load_cart(
            "d5d9a31190002727fe01e55f2a73d02b129d7d5fc7923b266c062b1c3b427c62.cart",
            description="PE file created by Azul team with no exports.",
        )
        result = self.do_execution(data_in=[("content", data)])
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="d5d9a31190002727fe01e55f2a73d02b129d7d5fc7923b266c062b1c3b427c62",
                        features={
                            "pe_export_hash": [FV("e37f0136aa3ffaf149b351f6a4c948e9")],
                            "pe_export_hash_sorted": [FV("e37f0136aa3ffaf149b351f6a4c948e9")],
                        },
                    )
                ],
            ),
        )

    def test_non_ascii_2_dll(self):
        r"""Test DLL with single non-ascii export - 62fd6cfff6f4c7b5abc9b06cb017edaddfd8880b5c3a3daecf789334c6f76c2e.

        LIEF finds exports 'endwork,runing,servicemain,working\x90', last one can be problematic.
        """
        data = self.load_cart(
            "a8c7b93f4e9dd1811725509e5c532b8add0f35d0a86b9716cd76e46825f4511e.cart",
            description="DLL created by Azul team with single non-ascii export.",
        )
        result = self.do_execution(data_in=[("content", data)])
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="a8c7b93f4e9dd1811725509e5c532b8add0f35d0a86b9716cd76e46825f4511e",
                        features={
                            "pe_export_hash": [FV("42db59d568060a0c1cf8ed981877d746")],
                            "pe_export_hash_sorted": [FV("42db59d568060a0c1cf8ed981877d746")],
                        },
                    )
                ],
            ),
        )

    def test_unstripped_elf_so(self):
        """Test ELF .so that was not stripped."""
        data = self.load_cart(
            "8deb23390c1c3614ff5324d191ff630f1684e0175cd5c26c684cf52b085c6dee.cart",
            description="Plain ELF created by Azul test team",
        )
        result = self.do_execution(data_in=[("content", data)])
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="8deb23390c1c3614ff5324d191ff630f1684e0175cd5c26c684cf52b085c6dee",
                        features={
                            "elf_export_hash": [FV("546f26c737a0d3f5af4125b6a93d08da")],
                            "elf_export_hash_sorted": [FV("244aa2581f13fb7d54d095e387042eeb")],
                            "elf_import_hash": [FV("29680f1a087126f69efecc1c8009cdf7")],
                            "elf_import_hash_sorted": [FV("6a6044c27e9806e58b3435e98c852a31")],
                        },
                    )
                ],
            ),
        )

    def test_stripped_elf_so(self):
        """Test ELF .so that was stripped."""
        data = self.load_cart(
            "78221dfc5fe924031bc8878338ed33147fde69ccdbbe7cfe1bdb7669884c4749.cart",
            description="Plain ELF created by Azul team - stripped.",
        )
        result = self.do_execution(data_in=[("content", data)])
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="78221dfc5fe924031bc8878338ed33147fde69ccdbbe7cfe1bdb7669884c4749",
                        features={
                            "elf_import_hash": [FV("cba21fd5698e9ba62045cceff40ae818")],
                            "elf_import_hash_sorted": [FV("b08233dcb1cbf07c40b293a7c5f490fc")],
                        },
                    )
                ],
            ),
        )

    def test_pam_backdoor_elf_so(self):
        """Test backdoored pam_unix.so - 3ce8cc77f583df21526f579496545c26af08c9f586abc9327ce8e552ca382b00."""
        data = self.load_test_file_bytes(
            "3ce8cc77f583df21526f579496545c26af08c9f586abc9327ce8e552ca382b00",
            "Malicious ELF64, backdoored pam_unix.so, malware family slapstick.",
        )
        result = self.do_execution(data_in=[("content", data)])
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="3ce8cc77f583df21526f579496545c26af08c9f586abc9327ce8e552ca382b00",
                        features={
                            "elf_export_hash": [FV("ebbc83bc7ce135636cdb820232daf2e3")],
                            "elf_export_hash_sorted": [FV("f5fdbcdc7f39ffb8785ed5e86baff693")],
                            "elf_import_hash": [FV("e0c264e06c50c98eaa2705705a86ba46")],
                            "elf_import_hash_sorted": [FV("e164a074e13f1ae666a05a28be2c1ecb")],
                        },
                    )
                ],
            ),
        )

    def test_openssl_elf_so(self):
        """Test OpenSSL libssl.so 3.3.0 dev - a8902e095aad2a90fb05f49a55b34a06e211a1722132e2264f2368e93ef1372e."""
        data = self.load_test_file_bytes(
            "a8902e095aad2a90fb05f49a55b34a06e211a1722132e2264f2368e93ef1372e", "OpenSSL libssl.so 3.3.0 dev."
        )
        result = self.do_execution(data_in=[("content", data)])
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="a8902e095aad2a90fb05f49a55b34a06e211a1722132e2264f2368e93ef1372e",
                        features={
                            "elf_export_hash": [FV("32cab333f0c2f9bde51c5b4debbf4a24")],
                            "elf_export_hash_sorted": [FV("a11fece009dbbadc99a8ee307e7d5cd6")],
                            "elf_import_hash": [FV("2a517a5beb65ecd5e5d3d9a69a778860")],
                            "elf_import_hash_sorted": [FV("fd25e9d84134406460cc9822af2f961a")],
                        },
                    )
                ],
            ),
        )

    def test_arm_elf_so(self):
        """Test 32 bit ARM ELF so - 9f5f000d41641ff940146b18c20ad157ee26ad856a05c5aaa4254cdec8db65da."""
        data = self.load_test_file_bytes(
            "9f5f000d41641ff940146b18c20ad157ee26ad856a05c5aaa4254cdec8db65da", "Malicious ARM ELF32, dropper."
        )
        result = self.do_execution(data_in=[("content", data)])
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="9f5f000d41641ff940146b18c20ad157ee26ad856a05c5aaa4254cdec8db65da",
                        features={
                            "elf_export_hash": [FV("2b0f268cfd3e0a15824342a0d985e6aa")],
                            "elf_export_hash_sorted": [FV("bfcf197d0d4ea387f9ea41b68cac792e")],
                            "elf_import_hash": [FV("a8f965495c218c57b406b151840d1cbd")],
                            "elf_import_hash_sorted": [FV("a14fc7036d641ee3bf47e5d27b39915f")],
                        },
                    )
                ],
            ),
        )
