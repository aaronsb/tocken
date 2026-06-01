# EFF Large Wordlist

`eff_large_wordlist.txt` is the [EFF Large Wordlist for Passphrases](https://www.eff.org/dice), published by the Electronic Frontier Foundation in 2016.

> Source: https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt

## License

The EFF wordlist is published under the [Creative Commons Attribution 3.0 United States License](https://creativecommons.org/licenses/by/3.0/us/). This means it can be redistributed, including in commercial software, with attribution.

The file is bundled here unmodified (7,776 lines, format: `<5-digit dice roll>\t<word>`).

`SPDX-License-Identifier: CC-BY-3.0-US`

## Why bundled

`tocken` generates Diceware-style recovery passphrases (6 words, ~77 bits of entropy) at first-run. Bundling the wordlist makes the passphrase generation reproducible offline and avoids a runtime network dependency on the EFF site.
