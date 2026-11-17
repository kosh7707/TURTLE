"""선택적 보고서의 집계만 검사한다. 프레임워크의 원자료 분석은 사용하지 않는다."""
import json
from pathlib import Path
import random
import shutil
import tempfile
import unittest
from report import quantile, bootstrap_difference, regenerate


class Report(unittest.TestCase):
    def test_statistics(self):
        self.assertEqual(quantile([1, 2, 3, 4], .25), 1.75)
        self.assertIsNone(quantile([], .5))
        self.assertEqual(bootstrap_difference([7] * 30, [2] * 30, random.Random(0), 100), [5, 5])

    def test_analysis_only_input_and_reproducibility(self):
        # An actual native test supplies this optional integration fixture.
        import os
        if 'TURTLE_REPORT_TEST_RUN' not in os.environ:
            self.skipTest('set TURTLE_REPORT_TEST_RUN to a native run')
        source = Path(os.environ['TURTLE_REPORT_TEST_RUN'])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data = root / 'input'
            data.mkdir()
            shutil.copy2(source / 'manifest.json', data / 'manifest.json')
            manifest = json.loads((data / 'manifest.json').read_text())
            for attempt in manifest['attempts']:
                target = data / attempt['directory']
                target.mkdir(parents=True)
                shutil.copy2(source / attempt['directory'] / 'analysis.json', target / 'analysis.json')
            first = regenerate(data, root / 'first')
            second = regenerate(data, root / 'second')
            self.assertEqual(first, second)
            for path in (root / 'first').iterdir():
                self.assertEqual(path.read_bytes(), (root / 'second' / path.name).read_bytes())
            self.assertEqual(len(first['attempts']), len(manifest['attempts']))
            self.assertTrue(all(row['valid_samples'] <= row['attempts'] for row in first['metrics']))
            self.assertFalse(any(data.rglob('*.pcap')))
            self.assertFalse(any(data.rglob('events.jsonl')))


if __name__ == '__main__':
    unittest.main()
