"""Evidence hashes must survive the repository's text-normalization policy."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[2]
BUNDLE = REPO / 'examples/demo_bundle'
GIT = shutil.which('git')


class EvidencePortabilityTests(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads((BUNDLE / 'config/provenance.json').read_text(encoding='utf-8'))

    def test_demo_evidence_uses_canonical_lf_and_matches_manifest(self):
        for source in self.manifest['sources']:
            with self.subTest(source=source['id']):
                data = (BUNDLE / source['path']).read_bytes()
                self.assertNotIn(b'\r', data, 'Evidence must use LF bytes before its digest is calculated')
                self.assertEqual(hashlib.sha256(data).hexdigest(), source['sha256'])
        attributes = (REPO / '.gitattributes').read_text(encoding='utf-8').splitlines()
        self.assertIn('* text eol=lf', attributes)

    def test_runtime_identity_references_the_same_synthetic_evidence(self):
        source = next(item for item in self.manifest['sources'] if item['id'] == 'src:active_st')
        expected = hashlib.sha256((BUNDLE / source['path']).read_bytes()).hexdigest()
        bindings = json.loads((BUNDLE / 'config/bindings.json').read_text(encoding='utf-8'))
        request = json.loads((REPO / 'examples/request.json').read_text(encoding='utf-8'))
        fixture = json.loads((Path(__file__).parent / 'fixtures/qualification_request.json').read_text(encoding='utf-8'))
        self.assertEqual(bindings['runtime_sha256'], expected)
        self.assertEqual(request['snapshot']['runtime_sha256'], expected)
        self.assertEqual(fixture['inputs']['snapshot']['runtime_sha256'], expected)

    @unittest.skipUnless(GIT, 'Git is optional; raw LF and evidence-digest checks still run')
    def test_git_index_normalization_preserves_evidence_manifest(self):
        # A separate repository reproduces Windows autocrlf behavior without
        # touching the main checkout, its index, or any deployment evidence.
        with tempfile.TemporaryDirectory(prefix='ics_risk_evidence_git_') as directory:
            root = Path(directory)
            shutil.copy2(REPO / '.gitattributes', root / '.gitattributes')
            shutil.copytree(BUNDLE, root / 'examples/demo_bundle')

            def git(*args):
                return subprocess.run([GIT, *args], cwd=root, check=True,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout

            git('init', '--quiet')
            git('config', '--local', 'core.autocrlf', 'true')
            git('add', '--', '.gitattributes', 'examples/demo_bundle')
            staged = json.loads(git('show', ':examples/demo_bundle/config/provenance.json'))
            for source in staged['sources']:
                with self.subTest(source=source['id']):
                    stored = git('show', ':examples/demo_bundle/' + source['path'])
                    self.assertNotIn(b'\r', stored)
                    self.assertEqual(hashlib.sha256(stored).hexdigest(), source['sha256'],
                                     'Git-normalized evidence must match the committed manifest')


if __name__ == '__main__':
    unittest.main()
