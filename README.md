[![penterepTools](https://www.penterep.com/external/penterepToolsLogo.png)](https://www.penterep.com/)


## PTINJECTOR - Injection Vulnerability Testing Tool

## Installation

```
pip install ptinjector
```

## Adding to PATH
If you're unable to invoke the script from your terminal, it's likely because it's not included in your PATH. You can resolve this issue by executing the following commands, depending on the shell you're using:

For ZSH Users
```bash
echo "export PATH=\"`python3 -m site --user-base`/bin:\$PATH\"" >> ~/.zshrc
source ~/.zshrc
```

For Bash Users
```bash
echo "export PATH=\"`python3 -m site --user-base`/bin:\$PATH\"" >> ~/.bashrc
source ~/.bashrc
```


## Usage examples
```
ptinjector -u https://www.example.com/?parameter1=abc&parameter2=def --parameter search -t XSS, SQLI
ptinjector -u https://www.example.com/?parameter1=abc&parameter2=def* -t XSS, SQLI
ptinjector -u http://192.168.0.3/admin/ping.php -d 'host=127.0.0.1*' -c 'PHPSESSID=cf0a2784f5b34228a016ec5' -H 'X-Forwarded-For:127.0.0.1' -p http://127.0.0.1:8080
```

## Options
```
   -u   --url                 <url>                Test URL
   -t   --test                <test>               Specify one or more tests to perform:
                               403_bypass            Test for 403 Bypass
                               crlf                  Test for HTTP Response Splitting (CRLF Injection)
                               fpd                   Test for Full Path Disclosure
                               function_injection    Test for Function Injection
                               hhi                   Test for Host Header Injection
                               lfi                   Test for Local File Inclusion
                               rce                   Test for Remote Code Execution
                               rfi                   Test for Remote File Inclusion
                               sqli_boolean          Test for Blind SQL Injection
                               sqli_error            Test for Error-based SQL Injection
                               sqli_time             Test for Time-based SQL Injection
                               sqli_union            Test for Union-based SQL Injection
                               ssi                   Test for Server Side Includes (shtml)
                               ssrf                  Test for Server Side Request Forgery
                               ssti                  Test for Template Injection
                               xss                   Test for Cross Site Scripting

   -rf  --request_file        <request-file>       Set request-file.txt
   -d   --data                <data>               Set request-data
   -P   --parameter           <parameter>          Set parameter to test (e.g. GET, POST parameters)
   -H   --headers             <headers>            Set Header(s)
   -c   --cookie              <cookie>             Set Cookie(s)
   -a   --agent               <agent>              Set User-Agent
   -p   --proxy               <proxy>              Set Proxy
   -vu  --verify-url          <verify-url>         Set Verification URL (used with e.g. SSRF)
   -g   --technology          <technology>         Set Technology
   -k   --keep-testing                             Keep sending payloads, even if vulnerability is already detected
   -l   --start-local-server  <port>               Start local server on <port> (default 5000)
   -v   --version                                  Show script version and exit
   -h   --help                                     Show this help message and exit
   -j   --json                                     Output in JSON format
```

## Dependencies
```
ptlibs
bs4
html5lib
flask
apscheduler
```

## License

Copyright (c) 2024 Penterep Security s.r.o.

ptinjector is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

ptinjector is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with ptinjector. If not, see https://www.gnu.org/licenses/.

## Warning

You are only allowed to run the tool against the websites which
you have been given permission to pentest. We do not accept any
responsibility for any damage/harm that this application causes to your
computer, or your network. Penterep is not responsible for any illegal
or malicious use of this code. Be Ethical!