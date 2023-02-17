# AES-Crypt
**Encrypting/decrypting AES files.**

```python
a = AesCrypt('.', ['aes'], 'enter_the_key')

a.encrypt_file('file_location/file_name')
```
```python
a.decrypt_file('file_location/file_name.aes')
```

You can use the `encrypt_file()` and `decrypt_file()` functions to encrypt and decrypt AES-files. You also have the option to use your own key.
