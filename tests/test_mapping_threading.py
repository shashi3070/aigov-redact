from __future__ import annotations

import threading

from aigov_redact.mapping.vault import MappingVault


class TestMappingVaultThreadSafety:
    def test_concurrent_registration_is_safe(self):
        vault = MappingVault()
        errors: list[Exception] = []

        def worker(slug: str):
            try:
                for i in range(200):
                    vault.register("EMAIL", f"user{i}@{slug}.com")
            except Exception as e:  # pragma: no cover
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(f"w{n}",)) for n in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        # 8 workers x 200 unique values each = 1600 unique entities
        assert len(vault) == 1600

    def test_concurrent_same_value_is_deterministic(self):
        vault = MappingVault()
        tokens: list[str] = []
        lock = threading.Lock()
        barrier = threading.Barrier(8)

        def worker():
            barrier.wait()
            t = vault.register("EMAIL", "same@example.com")
            with lock:
                tokens.append(t)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All 8 threads get the exact same token for the same value
        assert len(set(tokens)) == 1

    def test_concurrent_mixed_read_write(self):
        vault = MappingVault()
        stop = threading.Event()
        errors: list[Exception] = []

        def writer():
            try:
                while not stop.is_set():
                    vault.register("SSN", "123-45-6789")
            except Exception as e:  # pragma: no cover
                errors.append(e)

        def reader():
            try:
                while not stop.is_set():
                    vault.resolve("<SSN_something>")
                    vault.export_mapping()
            except Exception as e:  # pragma: no cover
                errors.append(e)

        w = threading.Thread(target=writer)
        r = threading.Thread(target=reader)
        w.start()
        r.start()
        import time

        time.sleep(0.05)
        stop.set()
        w.join()
        r.join()
        assert not errors
