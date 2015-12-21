from distutils.core import setup, Extension

argon2_hash_module = Extension('argon2_hash',
                               sources = ['argon2module.c',
                                          'argon2m.c',
  "scrypt.c",
  "sha3/sj/scrypt-jane.c",
  "sha3/ar2/src/cores.c", 
  "sha3/ar2/src/blake2/blake2b.c",
  "sha3/ar2/src/thread.c",
  "sha3/ar2/src/ref.c",
  "sha3/ar2/src/argon2.c",

										  ],
                               include_dirs=['.', './sha3'], extra_compile_args=['-O3', '-msse3','-DSCRYPT_SALSA64', '-DSCRYPT_SKEIN512'])

setup (name = 'argon2_hashs',
       version = '1.0',
       description = 'Bindings for scrypt proof of work used by Argon2coin',
       ext_modules = [argon2_hash_module])
