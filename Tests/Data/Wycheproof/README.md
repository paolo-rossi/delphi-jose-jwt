# Project Wycheproof JOSE test vectors

The four `json_web_*_test.json` files are copied unchanged from
[C2SP/wycheproof](https://github.com/C2SP/wycheproof), folder `testvectors_v1`,
commit `d5f724a21e449bbf8f142e032a6bf86884f2851c` (2026-11-09).

They are distributed under the Apache License 2.0, the license of the
Wycheproof project.

`Tests/Source/JOSE.Tests.Wycheproof.pas` runs them. The vectors this library
answers differently from Wycheproof are listed in its `KNOWN_DEVIATIONS`
constant, each with the reason. Every key in these files is a published test
key, never a real secret.

To update, download the files again from a newer commit, update the commit
above, and rerun the fixture: its failure message lists every vector that
changed outcome.
