.PHONY: all
all: vendor

vendor: composer.lock composer.phar
	php composer.phar install --prefer-dist
	touch -r $< $@

composer.lock: composer.json composer.phar
	php composer.phar update

composer.phar:
	curl -fsS https://getcomposer.org/installer | php
	touch -t 201601010000 $@

.PHONY: test
test: vendor
	vendor/bin/phpunit

.PHONY: check-style
check-style: vendor
	vendor/bin/phpcs src test
	vendor/bin/phpstan analyze

.PHONY: fix-style
fix-style: vendor
	vendor/bin/phpcs src test

.PHONY: clean
clean:
	rm -rf vendor composer.phar clover.xml
