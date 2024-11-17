# Dockerfile
FROM quay.io/keycloak/keycloak:26.0.5

# Workdir to Keycloak home
WORKDIR /opt/keycloak

# Add default configuration for admin user
ENV KC_BOOTSTRAP_ADMIN_USERNAME=admin
ENV KC_BOOTSTRAP_ADMIN_PASSWORD=admin
ENV KC_DB=postgres
ENV KC_DB_URL_DATABASE=keycloak
ENV KC_DB_URL_HOST=keycloak-db
ENV KC_DB_USERNAME=keycloak
ENV KC_DB_PASSWORD=keycloakpassword
ENV KC_LOG_LEVEL=debug
# currently dpop is still preview feature
ENV KC_FEATURES=dpop

# Expose Keycloak on port 8080
EXPOSE 8080

# Run Keycloak in development mode
ENTRYPOINT ["./bin/kc.sh", "start-dev"]