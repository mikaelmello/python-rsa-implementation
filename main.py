#!

import rsa
import argparse
import asn1tools
import base64
import pathlib
import sys


class ArgumentParser(object):

    def __init__(self):
        parser = argparse.ArgumentParser(
            description='RSA Implementation in Python',
            usage='''python3 main.py <command> [<args>]

The most commonly used commands are:
   generate     Generates a keypair
   encrypt      Encrypts a file using an imported public key
   decrypt      Decrypts a file using an imported private key
   signs        Signs a file using an imported private key
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

    def fetch(self):
        parser = argparse.ArgumentParser(
            description='Download objects and refs from another repository')
        # NOT prefixing the argument with -- means it's not optional
        parser.add_argument('repository')
        args = parser.parse_args(sys.argv[2:])
        print('Running git fetch, repository=%s' % args.repository)


if __name__ == '__main__':
    ArgumentParser()
