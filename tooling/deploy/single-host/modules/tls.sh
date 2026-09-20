#!/usr/bin/env bash
# tls.sh -- obtain/install the server certificate per ACCESS_MODE x TLS_MODE (§8.2).
# Requires _common.sh. Exports SSL_CERT_REMOTE / SSL_KEY_REMOTE for nginx.sh.
#
# Reads (exported by deploy.sh): ACCESS_MODE, TLS_MODE, DOMAIN, HOST_IP,
#   LETSENCRYPT_EMAIL, LETSENCRYPT_STAGING, SSL_KEY_PASSWORD.
# Provided-cert files (if any) are SCP'd by deploy.sh to /tmp/whitehat-deploy/cert/.
#
# certbot's --nginx installer needs a working http-01 server block on port 80. deploy.sh
# renders + installs the nginx config (with the ACME location) BEFORE calling this for
# letsencrypt, so certbot can complete the challenge and wire the cert in.

CERT_DIR=/etc/ssl/whitehat
SSL_CERT_REMOTE=""
SSL_KEY_REMOTE=""

_install_provided_cert() {
  # md5-idempotent install of an operator-provided cert/key.
  local src_cert=/tmp/whitehat-deploy/cert/fullchain.pem
  local src_key=/tmp/whitehat-deploy/cert/privkey.pem
  [[ -f "${src_cert}" ]] || { err "provided cert not found at ${src_cert}"; return 1; }
  [[ -f "${src_key}"  ]] || { err "provided key not found at ${src_key}"; return 1; }

  run_sudo mkdir -p "${CERT_DIR}"
  SSL_CERT_REMOTE="${CERT_DIR}/fullchain.pem"
  SSL_KEY_REMOTE="${CERT_DIR}/privkey.pem"

  # Decrypt the key if a passphrase was supplied
  local key_to_install="${src_key}"
  if [[ -n "${SSL_KEY_PASSWORD:-}" ]]; then
    if openssl pkey -in "${src_key}" -out /tmp/whitehat-deploy/cert/privkey.dec.pem -passin pass:"${SSL_KEY_PASSWORD}" 2>/dev/null; then
      key_to_install=/tmp/whitehat-deploy/cert/privkey.dec.pem
    else
      err "Could not decrypt provided key with SSL_KEY_PASSWORD -- nginx cannot load an encrypted key non-interactively"
      return 1
    fi
  fi

  local lc rc lk rk
  lc=$(md5sum "${src_cert}" | awk '{print $1}')
  rc=$(run_sudo md5sum "${SSL_CERT_REMOTE}" 2>/dev/null | awk '{print $1}' || echo "")
  if [[ "${lc}" != "${rc}" ]]; then
    run_sudo cp "${src_cert}" "${SSL_CERT_REMOTE}"; run_sudo chmod 644 "${SSL_CERT_REMOTE}"; run_sudo chown root:root "${SSL_CERT_REMOTE}"
    info "certificate installed"
  else info "certificate already up-to-date"; fi

  lk=$(md5sum "${key_to_install}" | awk '{print $1}')
  rk=$(run_sudo md5sum "${SSL_KEY_REMOTE}" 2>/dev/null | awk '{print $1}' || echo "")
  if [[ "${lk}" != "${rk}" ]]; then
    run_sudo cp "${key_to_install}" "${SSL_KEY_REMOTE}"; run_sudo chmod 600 "${SSL_KEY_REMOTE}"; run_sudo chown root:root "${SSL_KEY_REMOTE}"
    info "private key installed"
  else info "private key already up-to-date"; fi

  rm -f /tmp/whitehat-deploy/cert/privkey.dec.pem 2>/dev/null || true
}

_make_self_signed() {
  run_sudo mkdir -p "${CERT_DIR}"
  SSL_CERT_REMOTE="${CERT_DIR}/fullchain.pem"
  SSL_KEY_REMOTE="${CERT_DIR}/privkey.pem"
  if run_sudo test -f "${SSL_CERT_REMOTE}" && run_sudo test -f "${SSL_KEY_REMOTE}"; then
    info "self-signed cert already present -- reusing"
    return 0
  fi
  local cn="${HOST_IP:-localhost}"
  info "Generating self-signed cert for ${cn} (browser warning expected)"
  run_sudo openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "${SSL_KEY_REMOTE}" -out "${SSL_CERT_REMOTE}" -days 825 \
    -subj "/CN=${cn}" -addext "subjectAltName=IP:${cn}" 2>/dev/null \
    || run_sudo openssl req -x509 -newkey rsa:2048 -nodes \
         -keyout "${SSL_KEY_REMOTE}" -out "${SSL_CERT_REMOTE}" -days 825 -subj "/CN=${cn}"
  run_sudo chmod 600 "${SSL_KEY_REMOTE}"; run_sudo chmod 644 "${SSL_CERT_REMOTE}"
}

# Non-letsencrypt path: install/generate the cert and export the paths. Called by
# deploy.sh BEFORE nginx.sh renders the config.
setup_tls_cert() {
  case "${TLS_MODE:-letsencrypt}" in
    provided)    step "TLS: provided certificate"; _install_provided_cert ;;
    self-signed) step "TLS: self-signed certificate"; _make_self_signed ;;
    letsencrypt) : ;;  # handled by run_certbot AFTER nginx is up
    *) err "Unknown TLS_MODE: ${TLS_MODE}"; return 1 ;;
  esac
  export SSL_CERT_REMOTE SSL_KEY_REMOTE
}

# Let's Encrypt path: run AFTER nginx.sh has installed the port-80 ACME bootstrap
# (nginx_install_acme_bootstrap). Uses `certbot certonly --webroot` to ONLY obtain the
# cert (we keep full control of the vhost, which nginx_render_and_install writes next),
# then sets + exports SSL_CERT_REMOTE/SSL_KEY_REMOTE so the render fills ssl_certificate.
run_certbot() {
  [[ "${TLS_MODE:-}" == "letsencrypt" ]] || return 0
  step "TLS: Let's Encrypt (certbot certonly --webroot)"
  install_if_missing certbot python3-certbot-nginx
  run_sudo mkdir -p /var/www/certbot
  local staging=""
  is_true "${LETSENCRYPT_STAGING:-false}" && { staging="--staging"; warn "using LE STAGING cert (not browser-trusted)"; }
  run_sudo certbot certonly --webroot -w /var/www/certbot -d "${DOMAIN}" \
    -m "${LETSENCRYPT_EMAIL}" --agree-tos -n --keep-until-expiring ${staging}
  SSL_CERT_REMOTE="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
  SSL_KEY_REMOTE="/etc/letsencrypt/live/${DOMAIN}/privkey.pem"
  export SSL_CERT_REMOTE SSL_KEY_REMOTE
  # Auto-renew with an nginx reload hook (certbot's systemd timer runs renew)
  run_sudo mkdir -p /etc/letsencrypt/renewal-hooks/deploy
  echo '#!/bin/sh
systemctl reload nginx' | run_sudo_tee /etc/letsencrypt/renewal-hooks/deploy/whitehat-reload.sh
  run_sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/whitehat-reload.sh
  success "Let's Encrypt certificate issued for ${DOMAIN}"
}

# ssl-renew verb
renew_tls() {
  case "${TLS_MODE:-letsencrypt}" in
    letsencrypt) run_sudo certbot renew --deploy-hook 'systemctl reload nginx'; success "certbot renew done" ;;
    provided)    setup_tls_cert; run_sudo systemctl reload nginx; success "provided cert re-installed + nginx reloaded" ;;
    self-signed) warn "self-signed certs are static -- nothing to renew (regenerate via 'init' if expired)" ;;
  esac
}
