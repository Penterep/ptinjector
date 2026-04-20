import hashlib
import random
import string
from random import choice
from random import randint
from typing import List
from enum import Enum
import json
from urllib import parse



def sh_obfuscate_spaces(payload_str: str):
    """
    Replaces spaces with random value which shell accepts instead of space.
    """
    space_replacement = choice(("${IFS}", "\r","\n", "\v" "\t", "$'\x20'", "$'\x09'", "$'\\x20'", "$'\\x09'"))
    return payload_str.replace(" ", space_replacement)



def encode_hex(payload_str: str):
    tmplist = []
    for c in payload_str:
        tmplist.append(f"\\x{hex(ord(c))[2:]}")
    return "".join(tmplist)


def double_encode(payload_str: str):
    def subencode(ch: chr):
        if ch in string.punctuation:
            return f"%25{hex(ord(ch))[2:]}"
        return ch

    return "".join(map(subencode, payload_str))

encoders = {"quote_plus": parse.quote_plus, "quote": parse.quote, "none": lambda x: x,
                        "double_encode": double_encode, "sh_obfuscate_spaces": sh_obfuscate_spaces
}

def encode_payload(payload_str: str, encoding: str = "none"):
    global encoders
    encoder = encoders.get(encoding, parse.quote_plus)
    return encoder(payload_str)


def random_word(length=15, alphabet=string.ascii_letters):
    return "".join([random.choice(alphabet) for _ in range(length)])


default_variables = dict()

class TokenType(Enum):
    NONE = 0
    LIT = 1
    VAR = 2
    SET = 3
    WS = 4
    SEP = 5



class Token():
    def __init__(self, value=None, token_type=TokenType.NONE):
        self.value = value
        if value is None or value == "":
            self.token_type = TokenType.NONE
        else:
            self.token_type = token_type

    def __repr__(self):
        return f"T: value={self.value}, type={self.token_type}"

    def __str__(self):
        return self.__repr__()



def skipchars(template_string: str, chars):
    i = 0
    while i < len(template_string) and template_string[i] in chars:
        i += 1
    return Token(template_string[:i], TokenType.SEP), template_string[i:]


def skipseparators(template_string):
    return skipchars(template_string, string.whitespace + ",")


def parse_literal(template_string):
    i = 1
    while i < len(template_string) and template_string[0] == "'" :
        if template_string[i] == "'":
            i += 1
            break
        i += 1
    return Token(template_string[0:i][1:-1], TokenType.LIT), template_string[i:]


def parse_variable(template_string):
    if not template_string or template_string[0] == "'" or template_string[0] == "{":
        return Token(), template_string

    i = 0
    while i < len(template_string) and template_string[i] not in string.whitespace + "{},":
        i += 1
    return Token(template_string[:i], TokenType.VAR), template_string[i:]


def parse_set(template_string):
    if not template_string or template_string[0] != "{":
        return Token(), template_string

    parse_list = []
    while template_string and template_string[0] != "}":
        fragment, rest = parse_template_part(template_string[1:])
        if fragment:
            parse_list.append(fragment)
        template_string = rest

    return Token(parse_list, TokenType.SET), template_string[1:]


def parse_template_part(template_string):
    parse_list = []
    _, template_string = skipseparators(template_string)
    if template_string == "":
        return parse_literal("''")
    if template_string[0] == "'":
        return parse_literal(template_string)
    if template_string[0] == "{":
        return parse_set(template_string)
    else:
        return parse_variable(template_string)


def parse_template(template_string):
    parse_list = []


    rest = template_string
    while rest:
        fragment, rest = parse_template_part(rest)
        parse_list.append(fragment)

    return parse_list


def get_var_values(variable, variables):
    global default_variables
    return variables.get(variable, default_variables.get(variable, [""]))


def fillin_variables(parse_list, variables):
    filled = []
    for token in parse_list:
        if token.token_type == TokenType.LIT:
            filled.append(token)
        elif token.token_type == TokenType.VAR:
            newset = Token()
            newset.token_type = TokenType.SET
            newset.value = [Token(val, TokenType.LIT) for val in get_var_values(token.value, variables)]

            filled.append(newset)
        elif token.token_type == TokenType.SET:
            newset = Token(value=[], token_type=TokenType.SET)
            for t in token.value:
                if t.token_type != TokenType.VAR:
                    newset.value.append(t)
                    continue
                newset.value.extend(Token(x, TokenType.LIT) for x in get_var_values(t.value, variables))
            filled.append(newset)

    assert all(type(x) == Token for x in filled)
    return filled


def init_payload_generator(parse_list, variables):

    parse_list = fillin_variables(parse_list, variables)


    def calculate_number_variants(parse_list):
        """Calculates how many payload template_strings are generated from given parse_list (and so correspond to 1 template template_string + provided variables)"""
        n = 1
        for token in parse_list:
            if token.token_type == TokenType.LIT:
                continue
            elif token.token_type == TokenType.SET:
                n *= len(token.value)
            else:
                raise Exception(f"Calculating number of varians for {parse_list}")
        return n

    def create_variant(parse_list, i: int):
        result = []
        for e in parse_list:
            if e.token_type == TokenType.LIT:
                result.append(e.value)
            elif e.token_type == TokenType.SET:
                result.append(e.value[i % len(e.value)].value)
                i //= len(e.value)
            else:
                raise Exception(f"Unexpeted TokenType == {e.token_type}")

        return "".join(result)

    n = calculate_number_variants(parse_list)

    for i in range(n):
        encodings = get_var_values("encoding", variables)
        generated_payload = create_variant(parse_list, i)
        if not encodings:

            yield generated_payload
        else:
            for encoding in encodings:
                encoded_payload_str = encode_payload(generated_payload, encoding)
                yield encoded_payload_str


    return


def make_payload_generator(template_string: str, variables: dict):
    parse_list = parse_template(template_string)
    return init_payload_generator(parse_list, variables)



def expand_template_object(p):
    if not set(p.get('tags', [])).intersection({'payload_template'}):
        yield p
        return

    result = dict()
    result["verify"] = p["verify"]
    result["tags"] = p.get("tags", set())
    result["type"] = p.get("type", "REGEX")
    template_string_generators = [make_payload_generator(t, p.get('vars', dict())) for t in p["payload"]]
    generated_payloads = list()
    while (generated_payloads := list(map(next, template_string_generators))) != []:
        result['payload'] = generated_payloads
        yield result
    return


def prepare_templates(payloads: List[dict]):
    for p in payloads:
        for po in expand_template_object(p):
            yield po
