from difflib import Match, SequenceMatcher


class ExactSequenceMatcher(SequenceMatcher):
    """Keep difflib's block selection, accelerating its longest-match search."""

    def find_longest_match(self, alo=0, ahi=None, blo=0, bhi=None):
        if self.isjunk is not None or self.autojunk:
            return super().find_longest_match(alo, ahi, blo, bhi)

        a, b = self.a, self.b
        ahi = len(a) if ahi is None else ahi
        bhi = len(b) if bhi is None else bhi

        # Each state represents substrings with the same occurrence positions.
        transitions = [{}]
        links = [-1]
        lengths = [0]
        first_ends = [-1]
        last = 0

        for index in range(blo, bhi):
            token = b[index]
            current = len(transitions)
            transitions.append({})
            lengths.append(lengths[last] + 1)
            links.append(0)
            first_ends.append(index)
            previous = last

            while previous != -1 and token not in transitions[previous]:
                transitions[previous][token] = current
                previous = links[previous]

            if previous != -1:
                target = transitions[previous][token]
                if lengths[previous] + 1 == lengths[target]:
                    links[current] = target
                else:
                    clone = len(transitions)
                    transitions.append(transitions[target].copy())
                    lengths.append(lengths[previous] + 1)
                    links.append(links[target])
                    first_ends.append(first_ends[target])
                    while previous != -1 and transitions[previous].get(token) == target:
                        transitions[previous][token] = clone
                        previous = links[previous]
                    links[target] = links[current] = clone

            last = current

        state = size = 0
        best = Match(alo, blo, 0)
        for index in range(alo, ahi):
            token = a[index]
            while state and token not in transitions[state]:
                state = links[state]
                size = lengths[state]
            if token in transitions[state]:
                state = transitions[state][token]
                size += 1
            else:
                size = 0
            if size > best.size:
                best = Match(index - size + 1, first_ends[state] - size + 1, size)

        return best
