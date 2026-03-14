import importlib.util
import shutil
import sys
import tempfile
from pathlib import Path
import unittest


class StorageApiCallLoggerLoaderTests(unittest.TestCase):
    def _load_runtime_module(self, service_dir: str):
        source_path = Path(__file__).resolve().parents[2] / "services" / service_dir / "app.py"
        temp_root = tempfile.TemporaryDirectory()
        runtime_task_dir = Path(temp_root.name) / "var" / "task"
        runtime_task_dir.mkdir(parents=True, exist_ok=True)
        runtime_app_path = runtime_task_dir / "app.py"
        shutil.copy2(source_path, runtime_app_path)

        module_name = f"{service_dir.replace('-', '_')}_runtime_import_test"
        module_spec = importlib.util.spec_from_file_location(module_name, runtime_app_path)
        if module_spec is None or module_spec.loader is None:
            temp_root.cleanup()
            raise RuntimeError(f"Unable to load runtime test module for {service_dir}")

        module = importlib.util.module_from_spec(module_spec)
        sys.modules[module_name] = module
        try:
            module_spec.loader.exec_module(module)
        except Exception:
            sys.modules.pop(module_name, None)
            temp_root.cleanup()
            raise
        return module, runtime_app_path, temp_root

    def test_storage_handlers_import_without_common_module_in_code_uri(self):
        service_dirs = (
            "storage-upload",
            "storage-delete",
            "storage-download",
            "storage-ls",
            "price-storage",
        )
        for service_dir in service_dirs:
            with self.subTest(service_dir=service_dir):
                module, runtime_app_path, temp_root = self._load_runtime_module(service_dir)
                try:
                    broken_path = runtime_app_path.resolve().parents[1] / "common" / "api_call_logger.py"
                    self.assertFalse(broken_path.exists())
                    self.assertTrue(callable(module.log_api_call))
                    module.log_api_call(
                        event={},
                        context=None,
                        route="/test",
                        status_code=200,
                        result="success",
                    )
                finally:
                    sys.modules.pop(module.__name__, None)
                    temp_root.cleanup()

