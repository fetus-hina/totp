totp
====

PHP implementation of RFC6238 (TOTP: Time-Based One-Time Password Algorithm).

[![License](https://poser.pugx.org/jp3cki/totp/license.svg)](https://packagist.org/packages/jp3cki/totp)
[![Latest Stable Version](https://poser.pugx.org/jp3cki/totp/v/stable.svg)](https://packagist.org/packages/jp3cki/totp)
[![CI](https://github.com/fetus-hina/totp/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/fetus-hina/totp/actions/workflows/ci.yml)

Requirements
------------

* PHP (64-bits): PHP 8.2 or later
* PHP Extensions: hash

Install
-------

1. Set up [Composer](https://getcomposer.org/), the de facto standard package manager.
2. `php composer.phar require jp3cki/totp`

Usage
-----
```php
<?php

declare(strict_types=1);

use jp3cki\totp\Totp;

require_once('vendor/autoload.php');

// Generate new shared-secret key (for each user)
$secret = Totp::generateKey();
echo "secret: {$secret}\n";
echo "\n";

// Make URI for importing from QRCode.
$uri = Totp::createKeyUriForGoogleAuthenticator($secret, 'theuser@example.com', 'Issuer Name');
echo "uri: {$uri}\n";
echo "\n";

// Verify user input
$userInput = '123456'; // $_POST['totp']
$isValid = Totp::verify($userInput, $secret, time());
var_dump($isValid);
```

Security Notes
--------------

* **Replay protection is the caller's responsibility.** `Totp::verify()` does not remember which one-time codes have already been used. Per RFC 6238 §5.2, a server MUST reject any TOTP value that was previously accepted within the validity window. Store the most recently accepted time-step (or the accepted code itself) per user, and reject any submission that is equal to or older than it.
* **Rate-limit verification attempts.** A 6-digit code with the default ±1-step window leaves roughly 3 codes valid at any moment, i.e. a 3-in-1,000,000 chance per guess. Without throttling, an attacker can brute force a valid code in minutes. Apply per-account lockout or exponential back-off in the calling application.
* **Restrict the hash algorithm to RFC 6238 values.** The library only accepts `sha1`, `sha256`, and `sha512`. Do not forward an untrusted `hash` parameter into `calc()` / `verify()` from user input.

License
-------

[The MIT License](https://github.com/fetus-hina/totp/blob/master/LICENSE).

`Copyright (c) 2015-2025 AIZAWA Hina <hina@fetus.jp>`

Contributing
------------

Patches and/or report issues are welcome.

* Please create new branch for each issue or feature. (should not work in master branch)
* Please write and run test. `$ make test`
* Please run check-style for static code analysis and coding rule checking. `$ make check-style`
* Please clean up commits.
* Please create new pull-request for each issue or feature.
* Please use Japanese or *very simple* English to create new pull-request or issue.

Breaking Changes
----------------

- v4.0.0
  - Minimum environment is now PHP 8.2
  - `Totp::calc()` and `Totp::verify()` no longer accept arbitrary hash algorithms from `hash_algos()`. Only `sha1`, `sha256`, and `sha512` (the algorithms defined by RFC 6238) are allowed; any other value now throws `InvalidArgumentException`. Callers that previously passed values such as `md5` or `crc32` must switch to one of the supported algorithms.
  - The default verification window of `Totp::verify()` is narrowed. `$acceptStepPast` now defaults to `1` (was `2`), matching the maximum drift recommended by RFC 6238 §5.2. To restore the previous behaviour, pass `$acceptStepPast: 2` explicitly.
  - `Totp::generateKey()` now defaults to a 160-bit shared secret (was 80 bits), matching the HMAC-SHA1 output length recommended by RFC 4226 §4 R6. Existing keys keep working; only newly generated keys are longer. Pass `Totp::generateKey(80)` to restore the previous size.

- v3.0.0
  - Minimum environment is now PHP 8.1

- v2.0.0
  - Minimum environment is now PHP 7.2
  - Argument types are now strictly enforced
  - Removed `Random::generate*()`. Always use `random_bytes()` now.
