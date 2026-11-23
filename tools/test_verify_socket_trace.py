"""Independent proof rejects missing bytes, wrong offsets and orphan socket I/O."""
import tempfile
import unittest
from pathlib import Path

from verify_socket_trace import direction_proof, trace_io


class TraceProof(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        stream = bytes.fromhex('17030300026162170303000163')
        for layer in ('tls', 'wire'):
            (self.root / f'{layer}_send.bin').write_bytes(stream)
        self.calls = []
        self.events = []
        for i, (a, b) in enumerate(((0, 2), (2, 8), (8, len(stream)))):
            self.calls.append((b - a, stream[a:b]))
            fields = dict(id=2*i+1, call_id=44, success=True, requested=b-a, transferred=b-a,
                          direction='send', begin={'wall_ns': a}, end={'wall_ns': b},
                          wire_begin=a, tls_begin=a, wire_end=b, tls_end=b)
            self.events.extend([dict(fields, kind='transport', source='adapter_io'),
                                dict(fields, kind='socket', id=2*i+2, parent=2*i+1)])

    def proof(self):
        return direction_proof(self.root, 'send', self.events, self.calls)

    def test_real_header_splits_and_record_intersections(self):
        proof = self.proof()
        self.assertTrue(proof['split_header'] and proof['split_record'] and proof['coalesced_records'])
        self.assertEqual([r['socket_ids'] for r in proof['records']], [[2, 4], [4, 6]])

    def test_same_total_wrong_interval(self):
        self.events[1]['wire_begin'] += 1
        with self.assertRaisesRegex(ValueError, 'diverges'):
            self.proof()

    def test_unpaired_hook(self):
        self.events[3]['parent'] = 1
        with self.assertRaises(ValueError):
            self.proof()

    def test_truncated_tracer_rejected(self):
        log = self.root / 'trace'
        log.write_text('sendto(4<TCP:[123]>, "\\x17"..., 5, 0, NULL, 0) = 5\n')
        with self.assertRaisesRegex(ValueError, 'truncated'):
            trace_io(log)


if __name__ == '__main__':
    unittest.main()
