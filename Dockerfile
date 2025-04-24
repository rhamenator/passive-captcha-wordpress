FROM php:8.4-cli-alpine AS base
RUN apk update && apk upgrade --no-cache && apk add --no-cache bash

FROM base

# Install dependencies
RUN apt-get update && apt-get install -y \
    default-mysql-client \
    unzip \
    git \
    && docker-php-ext-install mysqli

# Install PHPUnit
RUN curl -OL https://phar.phpunit.de/phpunit-9.phar \
    && chmod +x phpunit-9.phar \
    && mv phpunit-9.phar /usr/local/bin/phpunit

# Install WP-CLI
RUN curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar \
    && chmod +x wp-cli.phar \
    && mv wp-cli.phar /usr/local/bin/wp

# Working directory
WORKDIR /var/www/html

# Entrypoint to run the tests
ENTRYPOINT ["phpunit"]
