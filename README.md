totp
====

PHP implementation of RFC6238 (TOTP: Time-Based One-Time Password Algorithm).

[![License](https://poser.pugx.org/jp3cki/totp/license.svg)](https://packagist.org/packages/jp3cki/totp)
[![Build Status](https://travis-ci.org/fetus-hina/totp.svg)](https://travis-ci.org/fetus-hina/totp)
[![Latest Stable Version](https://poser.pugx.org/jp3cki/totp/v/stable.svg)](https://packagist.org/packages/jp3cki/totp)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/fetus-hina/totp/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/fetus-hina/totp/?branch=master)
[![Code Climate](https://codeclimate.com/github/fetus-hina/totp/badges/gpa.svg)](https://codeclimate.com/github/fetus-hina/totp)
[![Test Coverage](https://codeclimate.com/github/fetus-hina/totp/badges/coverage.svg)](https://codeclimate.com/github/fetus-hina/totp)

Requirements
------------

* PHP (64-bits): PHP 5.4.0 or later
* PHP Extensions: hash, openssl

Install
-------

1. Set up [Composer](https://getcomposer.org/), the de facto standard package manager.
2. `php composer.phar require jp3cki/totp:~1.0`

Usage
-----
```php
<?php
require_once('vendor/autoload.php');
use jp3cki\totp\Totp;

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

`Copyright (c) 2015 AIZAWA Hina <hina@bouhime.com>`

Contributing
------------

Patches and/or report issues are welcome.

* Please create new branch for each issue or feature. (should not work in master branch)
* Please write and run test. `$ make test`
* Please run phpmd for static code analysis. `$ make phpmd`
* Please clean up commits.
* Please create new pull-request for each issue or feature.
* Please gazing the results of Travis-CI and other hooks.
* Please use Japanese or *very simple* English to create new pull-request or issue.
