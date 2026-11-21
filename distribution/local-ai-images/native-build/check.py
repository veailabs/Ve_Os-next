import ast
import unittest

from native_inputs import ROOT, input_manifest, verify_context


for path in ROOT.glob("*.py"):
    ast.parse(path.read_text(), filename=str(path))
result = unittest.TextTestRunner(verbosity=1).run(unittest.defaultTestLoader.discover(str(ROOT), pattern="test_*.py"))
if not result.wasSuccessful():
    raise SystemExit(1)
proof = verify_context(ROOT / "llamacpp-context", input_manifest())
print("Exact llama.cpp inputs verified: " + str(proof["files"]) + " files, " + str(proof["bytes"]) + " bytes")
