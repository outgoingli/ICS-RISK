"""CLI checks use independent expected results; never contact a control network."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from ics_risk import cli

ROOT = Path(__file__).resolve().parents[1]


class CliTests(unittest.TestCase):
    def test_demo_validation_and_record(self):
        with tempfile.TemporaryDirectory() as records:
            run = subprocess.run([sys.executable, '-m', 'ics_risk', '--bundle',
                str(ROOT / 'examples/demo_bundle'), '--backend', 'json', '--records', records,
                'evaluate', '--input', str(ROOT / 'examples/request.json')],
                cwd=ROOT, capture_output=True, text=True, check=True)
            result = json.loads(run.stdout)
            self.assertEqual('INDETERMINATE', result['decision'])
            saved = json.loads(Path(result['record_path']).read_text(encoding='utf-8'))
            self.assertEqual('synthetic_demo', saved['bundle_profile'])
            self.assertEqual(5, len(saved['result']['constraints']))

    def test_backend_outage_nonzero_exit(self):
        with patch.object(sys, 'argv', ['ics-risk', 'validate']), patch.object(cli, 'run',
                return_value={'http_status': 503, 'decision': 'INDETERMINATE'}), \
                patch('builtins.print'), self.assertRaises(SystemExit) as context:
            cli.main()
        self.assertEqual(2, context.exception.code)
