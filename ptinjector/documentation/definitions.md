
# Definitions

Definitions are files which define payloads and methods of checking whether the target
is vulnerable.

The only supported definition format is .json, which MUST contain:
'description', 'payloads' top level keys and optionally also 'vulnerability' top level key,
where 'payloads' must contain a payload object itself containing: 'payload', 'type', 'verify' and optionally 'tags' and 'vars' keys.

## definition.json file format
- description: self-explanatory, description of the tested vulnerability
- vulnerability: its name or some other identifier (for example PTV-WEB-SANIT-SQLINJ)
- payloads: list of payload objects

- payload (object): MUST contain the keys 'payload', 'type', 'verify' and optionally also 'tags', 'vars'
- payload: nonempty list of strings to send to target, these strings can always contain '[RANDOM_N]' with some positive N which is replaced with random N digit number each run.
- verify: nonempty list of strings to pass to verification module
- type: a string determining the type of verificator module to perform the checking, for module documentation see modules.md, supported types are those for which there is TYPE.py in the _modules_ directory
- tags: this is optional field used to give the tool extra information about the particular payload object. This is used for performing only subsets of tests (lets say we know the target runs PostgreSQL, then we can test only payloads specific to it instead of all of those defined.) and also for defining payload object as templated - that is one whose payloads are not directly sent to target but rather used to generate multiple payloads.
- vars: also optional field used for defining variables for templated payload objects, described below in the templates section

### definition.json  minimal example

```json
{
    "description": "vulnerability",
    "vulnerability": "ID",
    "payloads": [payload1, payload2, ... payloadN]
}

```

where each paylod is
```json
{
    "payload":[
        "string1",
        "string2",
        ...
        "stringM"
    ],
    "type": "REGEX",
    "verify": ["some IOC string"],
    "tags": ["somesoftware"]
}
```

### Templates
It is likely that at least some of the payloads which are to be tested share a common portion requiring us to write multiple mutations of the same
payload. Templates can define such mutations in single payload object. 

### Template syntax and usage
To create a template the tag: "payload_template" is added to the "tags" key and some syntax is used in the payload strings (so all this is inline, in what reffered to above as string1, string2...)

- unquoted spaces are ignored
- literals: are substrings between single quotes, multiple literals separated by spaces get concatenated to one string
    - so ["string"] is the same as template payload: [" 'string' "] which is the same as payload: ["'str' 'ing'"].
- curly braces '{' and '}' are used to mark literal string sets which are used for generating mutliple payload strings, for example we can write template for this payload object:
- the only metacharacters are '{', '}', and ''', ','. single quote - for inserting literals, comma for separating values in sets.
```json
"payload":[
    "' OR 1=1",
    "' OR 1=1--",
    "' OR 1=1--+",
    "' OR 1=1/*",
    "\" OR 1=1",
    "\" OR 1=1--",
    "\" OR 1=1--+",
    "\" OR 1=1/*",
]
```
Like this, using variables defined in templates/default.json:
```json
"payload": [
    "{SQUOTE, DQUOTE} 'OR 1=1' {'', '--', '--+', '/*'}"
],
"tags": ["payload_template"]
```

Or defining our own variables:

```json
"payload:"[
    "MYQUOTE 'OR 1=1' MYTERMINATOR"
],
"tags": ["payload_template"],
"vars":{
    "MYQUOTE":["'", "\""],
    "MYTERMINATOR": ['', '--', '--+', '/*']
}
```

- variables: any unqoted string will be treated as a variable, first taken from `vars` if not found from defauls and it it is not there replaced with empty string, default variables are in the `default` file in templates/ directory.
- control variables: are not put into the payload template string only to the `vars` dictionary. Currently there is only `encoding` control variable whose value should be list of "quote_plus", "quote", "none", "double_encode", "sh_obfuscate_spaces". If undefined encoding is used a default encoding is used. Defining it causes all generated payloads to be encoded for given payload object.
