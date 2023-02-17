import hashlib
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto import Random


class AesCrypt:
    _key = ''
    _files_dir = ''
    _target_ext = ''
    _file_encryption_blocks = 10000
    _crypt_ext = 'aes'

    def __init__(self, directory, ext, key):
        self._files_dir = directory
        self._target_ext = ext
        self._key = key.strip()

    def encrypt(self):
        index = self.index(self._target_ext)

        for item in index:
            if self.encrypt_file(item):
                os.remove(item)

    def decrypt(self):
        index = self.index(self._crypt_ext)

        for item in index:
            if self.decrypt_file(item):
                os.remove(item)

    def index(self, index_ext):
        index = self.scandir(self._files_dir)
        return index

    def scandir(self, path, index=None):
        if not index:
            index = []

        with os.scandir(path) as it:
            for entry in it:
                if entry.name.startswith('.'):
                    continue
                if entry.is_file():
                    name, ext = os.path.splitext(entry.path)
                    if ext[1:] in self._target_ext:
                        index.append(entry.path)
                else:
                    self.scandir(entry.path, index)
        return index

    # encrypt
    def encrypt_file(self, source, dest=''):
        error = False
        if not dest:
            dest = f'{source}.{self._crypt_ext}'

        block_size = 16
        chunk_size = block_size * self._file_encryption_blocks

        m = hashlib.sha1()
        m.update(self._key.encode('utf-8'))
        key = m.digest()[0:16]
        iv = Random.new().read(block_size)

        try:
            with open(dest, 'wb') as dest_file:
                dest_file.write(iv)
                with open(source, 'rb') as source_file:
                    while True:
                        plain = source_file.read(chunk_size)
                        if not plain:
                            break
                        cipher = AES.new(key, AES.MODE_CBC, iv)
                        cipher_text = cipher.encrypt(pad(plain, block_size))
                        iv = cipher_text[0:block_size]
                        dest_file.write(cipher_text)
        except Exception as e:
            error = True

        return False if error else dest

    # decrypt
    def decrypt_file(self, source, dest=''):
        error = False
        if not dest:
            dest = f'{source[:-len(self._crypt_ext) - 1]}'

        block_size = 16
        chunk_size = block_size * (self._file_encryption_blocks + 1)

        m = hashlib.sha1()
        m.update(self._key.encode('utf-8'))
        key = m.digest()[0:16]

        try:
            with open(dest, 'wb') as dest_file:
                with open(source, 'rb') as source_file:
                    iv = source_file.read(block_size)
                    while True:
                        cipher_text = source_file.read(chunk_size)
                        if not cipher_text:
                            break
                        cipher = AES.new(key, AES.MODE_CBC, iv)
                        plain = cipher.decrypt(cipher_text)[0:chunk_size - block_size]
                        iv = cipher_text[0:block_size]
                        dest_file.write(plain)
        except Exception as e:
            print(e)
            error = True

        return False if error else dest


a = AesCrypt('.', ['aes'], 'enter the key')
