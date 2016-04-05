COMPOSER_VERSION=1.0.0-beta2

all: vendor doc

vendor: composer.lock composer.phar
	php composer.phar install --prefer-dist
	touch -r $< $@

composer.lock: composer.json
	php composer.phar update -vvv

composer.phar:
	curl -sS https://getcomposer.org/installer | php -- --version=$(COMPOSER_VERSION)
	touch -t 201601010000 $@

doc: vendor
	rm -rf doc/api
	vendor/bin/apigen generate --source="src" --destination="doc/api"

test: vendor
	vendor/bin/phpunit

check-style: vendor
	vendor/bin/phpmd src text cleancode,codesize,design,naming,unusedcode
	vendor/bin/phpcs --standard=PSR2 src test

fix-style: vendor
	vendor/bin/phpcs --standard=PSR2 src test

clean:
	rm -rf doc vendor composer.phar clover.xml

.PHONY: all doc check-style fix-style clean test
