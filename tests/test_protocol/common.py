
from tls13.utils import Uint


class TypeTestMixin:

    def test_size(self):
        self.assertTrue(hasattr(self.target, '_size'))

    def test_values(self):
        UintN = Uint.get_type(size=self.target._size)
        self.assertTrue(all(type(v) == UintN for v in self.target.values))

    def test_labels(self):
        self.assertTrue(all(self.target.labels[v] for v in self.target.values))
