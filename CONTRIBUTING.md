# Contributing

Please keep changes focused and add or update a regression test when changing
status handling, option parsing, or output format.

Before opening a pull request, run:

```bash
bash -n checkCRT.sh
shellcheck -s bash checkCRT.sh
./tests/test_cli.sh
```

Do not commit private certificates, private keys, or credentials. Test
certificates must be generated at test time.
