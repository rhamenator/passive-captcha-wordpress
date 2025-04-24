# Makefile for Passive CAPTCHA Hardened Plugin Docker Testing Environment

PLUGIN_DIR=passive-captcha-hardened
CONTAINER_PHPUNIT=phpunit
CONTAINER_WORDPRESS=wordpress
CONTAINER_DB=db

build:
	docker-compose build

up:
	docker-compose up -d

down:
	docker-compose down

logs:
	docker-compose logs -f

db-reset:
	docker-compose run --rm $(CONTAINER_PHPUNIT) bash -c "\
		wp db reset --yes && \
		wp core install --url='http://localhost:8080' --title='Passive CAPTCHA Test' --admin_user='admin' --admin_password='password' --admin_email='admin@example.com'"

activate-plugin:
	docker-compose run --rm $(CONTAINER_PHPUNIT) bash -c "\
		wp plugin activate $(PLUGIN_DIR)"

install-tests:
	docker-compose run --rm $(CONTAINER_PHPUNIT) bash -c "\
		if [ ! -d /tmp/wordpress ]; then \
			git clone https://github.com/WordPress/wordpress-develop.git /tmp/wordpress; \
			cd /tmp/wordpress; \
			npm install; \
			npm run build; \
			cp wp-tests-config-sample.php wp-tests-config.php; \
			sed -i \"s/youremptytestdbnamehere/wordpress_test/\" wp-tests-config.php; \
			sed -i \"s/yourusernamehere/wp_test/\" wp-tests-config.php; \
			sed -i \"s/yourpasswordhere/password/\" wp-tests-config.php; \
			sed -i \"s/localhost/db/\" wp-tests-config.php; \
		fi"

test:
	docker-compose run --rm $(CONTAINER_PHPUNIT) phpunit

test-reset: down up install-tests db-reset activate-plugin test
