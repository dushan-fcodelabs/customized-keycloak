
FROM quay.io/keycloak/keycloak:26.4 as builder

ADD --chown=keycloak:keycloak ./mfa-authenticator/target/keycloak-mfa-authenticator.jar /opt/keycloak/providers/mfa-authenticator.jar


RUN /opt/keycloak/bin/kc.sh build
