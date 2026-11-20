import itertools
import random
import unittest
from difflib import SequenceMatcher

from ptinjector._sequence_matcher import ExactSequenceMatcher


class ExactSequenceMatcherTest(unittest.TestCase):
    def assert_same_opcodes(self, first, second):
        expected = SequenceMatcher(None, first, second, autojunk=False)
        actual = ExactSequenceMatcher(None, first, second, autojunk=False)
        self.assertEqual(actual.get_opcodes(), expected.get_opcodes(), (first, second))

    def test_all_short_binary_sequences(self):
        sequences = [
            ''.join(parts)
            for length in range(7)
            for parts in itertools.product('ab', repeat=length)
        ]
        for first in sequences:
            for second in sequences:
                self.assert_same_opcodes(first, second)

    def test_random_sequences_and_subranges(self):
        rng = random.Random(2026)
        for _ in range(1000):
            first = [rng.choice('aabbbc<> /') for _ in range(rng.randrange(100))]
            second = [rng.choice('aabbbc<> /') for _ in range(rng.randrange(100))]
            self.assert_same_opcodes(first, second)
            alo = rng.randrange(len(first) + 1)
            ahi = rng.randrange(alo, len(first) + 1)
            blo = rng.randrange(len(second) + 1)
            bhi = rng.randrange(blo, len(second) + 1)
            expected = SequenceMatcher(None, first, second, autojunk=False)
            actual = ExactSequenceMatcher(None, first, second, autojunk=False)
            self.assertEqual(
                actual.find_longest_match(alo, ahi, blo, bhi),
                expected.find_longest_match(alo, ahi, blo, bhi),
                (first, second, alo, ahi, blo, bhi),
            )

    def test_repeated_html_with_insertions_and_deletions(self):
        from ptinjector.modules.BOOLEAN import split_content
        row = '<div class="row">Product</div>\n'
        first = row * 40 + '<nonce>100</nonce>'
        for second in (
            row * 40 + '<nonce>200</nonce>',
            row * 20 + '<p>Found</p>' + row * 20,
            row * 39,
        ):
            self.assert_same_opcodes(split_content(first), split_content(second))

    def test_junk_options_preserve_standard_behavior(self):
        first, second = ' abcd' * 50, 'abcd abcd' * 50
        for isjunk, autojunk in ((None, True), (lambda token: token == ' ', False)):
            expected = SequenceMatcher(isjunk, first, second, autojunk=autojunk)
            actual = ExactSequenceMatcher(isjunk, first, second, autojunk=autojunk)
            self.assertEqual(actual.get_opcodes(), expected.get_opcodes())
