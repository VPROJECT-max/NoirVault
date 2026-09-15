#ifndef NOIRVAULT_CORE_H
#define NOIRVAULT_CORE_H

#include <stddef.h>
#include <stdint.h>

typedef struct NvBuffer {
    uint8_t *data;
    size_t len;
} NvBuffer;

NvBuffer nv_encrypt_json(const char *password, const uint8_t *json, size_t json_len);
NvBuffer nv_decrypt_json(const char *password, const uint8_t *envelope, size_t envelope_len);
NvBuffer nv_derive_vault_key(const char *password, const uint8_t *envelope, size_t envelope_len);
NvBuffer nv_decrypt_json_with_key(const uint8_t *key, size_t key_len, const uint8_t *envelope, size_t envelope_len);
NvBuffer nv_reencrypt_json_with_key(const uint8_t *key, size_t key_len, const uint8_t *existing_envelope, size_t existing_envelope_len, const uint8_t *json, size_t json_len);
void nv_free_buffer(NvBuffer buffer);
const char *nv_last_error(void);

#endif
