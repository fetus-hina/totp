totp
====

PHP implementation of RFC6238 (TOTP: Time-Based One-Time Password Algorithm).

[![License](https://poser.pugx.org/jp3cki/totp/license.svg)](https://packagist.org/packages/jp3cki/totp)
[![Latest Stable Version](https://poser.pugx.org/jp3cki/totp/v/stable.svg)](https://packagist.org/packages/jp3cki/totp)
[![CI](https://github.com/fetus-hina/totp/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/fetus-hina/totp/actions/workflows/ci.yml)

Requirements
------------

* PHP (64-bits): PHP 7.2 or later
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

License
-------

[The MIT License](https://github.com/fetus-hina/totp/blob/master/LICENSE).

`Copyright (c) 2015-2021 AIZAWA Hina <hina@fetus.jp>`

Contributing
------------

Patches and/or report issues are welcome.

* Please create new branch for each issue or feature. (should not work in master branch)
* Please write and run test. `$ make test`
* Please run check-style for static code analysis and coding rule checking. `$ make check-style`
* Please clean up commits.
* Please create new pull-request for each issue or feature.
* Please gazing the results of Travis-CI and other hooks.
* Please use Japanese or *very simple* English to create new pull-request or issue.

Breaking Changes
----------------

- v2.0.0
  - Minimum environment is now PHP 7.2
  - Argument types are now strictly enforced
  - Removed `Random::generate*()`. Always use `random_bytes()` now.
