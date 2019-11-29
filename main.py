#!

import rsa
import argparse
import asn1tools
import base64
import pathlib
import sys
import hashlib


class ArgumentParser(object):

    def __init__(self):
        parser = argparse.ArgumentParser(
            description='RSA Implementation in Python',
            usage='''python3 main.py <command> [<args>]

The most commonly used commands are:
   generate     Generates a keypair
   encrypt      Encrypts a string using an imported key
   decrypt      Decrypts a string using an imported key
   sign         Signs a file using an imported private key
   verify       Verifies a signature using an imported public key
''')

        parser.add_argument('command', help='Subcommand to run')
        # parse_args defaults to [1:] for args, but you need to
        # exclude the rest of the args too, or validation will fail
        args = parser.parse_args(sys.argv[1:2])
        if not hasattr(self, args.command):
            print('Unrecognized command')
            parser.print_help()
            exit(1)
        # use dispatch pattern to invoke method with same name
        getattr(self, args.command)()

    def generate(self):
        parser = argparse.ArgumentParser(
            description='Generates a keypair')
        # prefixing the argument with -- means it's optional
        parser.add_argument('generate', help='Generate')
        parser.add_argument(
            'keysize',
            type=int,
            help="Size of the key in bits, allowed values: 512, 1024, 2048, 4096")
        parser.add_argument(
            'outdir',
            type=str,
            help="Where to store the generated keys")

        args = parser.parse_args(sys.argv[1:])

        public_key, private_key = rsa.generate_key_pair(args.keysize)
        path = pathlib.Path(args.outdir)
        public_key.export(path.joinpath('key.pub'))
        private_key.export(path.joinpath('key'))

    def encrypt(self):
        parser = argparse.ArgumentParser(
            description='Encrypts a string using a key')
        # prefixing the argument with -- means it's optional

        parser.add_argument('encrypt', help='Encrypt')

        parser.add_argument(
            'public_key_file_path',
            type=str,
            help="Path of where the key is located")

        parser.add_argument(
            'message',
            type=str,
            help="Message to be encrypted")

        args = parser.parse_args(sys.argv[1:])

        public_key = rsa.PublicKey.importFile(args.public_key_file_path)
        print(rsa.encrypt(public_key, args.message))

    def decrypt(self):
        parser = argparse.ArgumentParser(
            description='Decrypts a string using a key')
        # prefixing the argument with -- means it's optional

        parser.add_argument('decrypt', help='Decrypt')

        parser.add_argument(
            'private_key_file_path',
            type=str,
            help="Path of where the key is located")

        parser.add_argument(
            'message',
            type=str,
            help="Message to be decrypted")

        args = parser.parse_args(sys.argv[1:])

        private_key = rsa.PrivateKey.importFile(args.private_key_file_path)
        print(rsa.decrypt(private_key, args.message))

    def sign(self):
        parser = argparse.ArgumentParser(
            description='Signs a file using a private key')
        # prefixing the argument with -- means it's optional

        parser.add_argument('sign', help='Sign')

        parser.add_argument(
            'input_file_path',
            type=str,
            help="Path of where the input file is located")

        parser.add_argument(
            'private_key_file_path',
            type=str,
            help="Path of the private key")

        parser.add_argument(
            'output_file_path',
            type=str,
            help="Path to store signature")

        args = parser.parse_args(sys.argv[1:])
        private_key = rsa.PrivateKey.importFile(args.private_key_file_path)

        BLOCKSIZE = 65536
        hasher = hashlib.sha1()
        with open(args.output_file_path, 'w+') as ofile:
            with open(args.input_file_path, 'rb') as afile:
                buf = afile.read(BLOCKSIZE)
                while len(buf) > 0:
                    hasher.update(buf)
                    buf = afile.read(BLOCKSIZE)
            hash = hasher.hexdigest()

            signature = rsa.encrypt(private_key, hash)
            ofile.write(signature)

    def verify(self):
        parser = argparse.ArgumentParser(
            description='Verify a signature')
        # prefixing the argument with -- means it's optional

        parser.add_argument('sign', help='Sign')

        parser.add_argument(
            'input_file_path',
            type=str,
            help="Path of where the input file is located")

        parser.add_argument(
            'public_key_file_path',
            type=str,
            help="Path of the public key")

        parser.add_argument(
            'signature_file_path',
            type=str,
            help="Path to store signature")

        args = parser.parse_args(sys.argv[1:])
        public_key = rsa.PublicKey.importFile(args.public_key_file_path)

        BLOCKSIZE = 65536
        hasher = hashlib.sha1()
        with open(args.signature_file_path, 'r') as ofile:
            signature = ofile.read()

            try:
                hash = rsa.decrypt(public_key, signature)

                with open(args.input_file_path, 'rb') as afile:
                    buf = afile.read(BLOCKSIZE)
                    while len(buf) > 0:
                        hasher.update(buf)
                        buf = afile.read(BLOCKSIZE)
                file_hash = hasher.hexdigest()

                if file_hash == hash:
                    print('Verified')
                else:
                    print('Not verified')
            except:
                print('Not verified')


if __name__ == '__main__':
    ArgumentParser()
