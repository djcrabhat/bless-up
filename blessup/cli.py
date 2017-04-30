#!/usr/bin/env python

from blessup.client import BlessClient
import stat
import sys
import os

import argparse
import logging
import boto3
from botocore.exceptions import (ClientError,
                                 ParamValidationError,
                                 ConnectionError,
                                 EndpointConnectionError)


def parse_args():
    parser = argparse.ArgumentParser(description='Get your pub key signed by BLESS')
    parser.add_argument('region', help='AWS region where your lambda is deployed')
    parser.add_argument('--bastion_user', help='User requesting the signing, for logging')
    parser.add_argument('bastion_ip', help='IP of user requesting the signing, for logging')
    parser.add_argument('remote_users', help='Comma-separated list of username(s) or authorized principals on the '
                                             'remote server that will be used in the SSH request.  This is enforced in '
                                             'the issued certificate.')
    parser.add_argument('ssh_source_ip',
                        help='The source IP(s) where the SSH connection will be initiated from. Addresses should be '
                             'comma-separated and can be individual IPs or CIDR format (nn.nn.nn.nn/nn or '
                             'hhhh::hhhh/nn).  This is enforced in the issued certificate.')

    parser.add_argument('--function_name', help="Name of the BLESS lambda function", default='bless')
    parser.add_argument('--key_to_sign', help="The .pub key to sign, defaults to ~/.ssh/id_rsa.pub",
                        default=os.path.expanduser('~/.ssh/id_rsa.pub'))
    parser.add_argument('--cert_output', help="The output of the signed request.  defaults to ~/.ssh/id_rsa-cert.pub",
                        default=os.path.expanduser('~/.ssh/id_rsa-cert.pub'))
    parser.add_argument('--kmsauth', help='KMS auth token, if kmsauth is setup.  see: github.com/lyft/python-kmsauth')
    parser.add_argument('--kmsauth_autogen_key', help='If you want to try an automatically generate a user token, the '
                                                      'key to usthis key')
    parser.add_argument('--kmsauth_autogen_service', help='If you want to try an automatically generate a user token, '
                                                          'the service name being used by BLESS')
    parser.add_argument('--mfa_serial', help='If you require MFA for getting the kmsauth, the arn/serial of that device')

    parser.add_argument('-v', '--verbose', action='count', default=0, help="enable verbose logging, multiple \"v\"s "
                                                                           "for deeper logging levels")

    args =  parser.parse_args()
    if not args.bastion_user:
        try:
            iam_client = boto3.client('iam', region_name=args.region)
            user = iam_client.get_user()['User']
            args.user_arn = user['Arn']
            username = user['UserName']
            args.bastion_user = username
        except ClientError as ex:
            raise ValueError("Could not fetch bastion username from AWS credentials: %s"%ex)

    return args



def main(args=None):
    if not args:
        args = parse_args()

    levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    level = levels[min(len(levels) - 1, args.verbose)]  # capped to number of levels
    logging.basicConfig(level=level)

    region, lambda_function_name, bastion_user, bastion_user_ip, remote_usernames, bastion_ips, \
    bastion_command, public_key_filename, certificate_filename = args.region, args.function_name, args.bastion_user, \
                                                                 args.bastion_ip, args.remote_users, \
                                                                 args.ssh_source_ip, '*', args.key_to_sign, \
                                                                 args.cert_output

    with open(public_key_filename, 'r') as f:
        public_key = f.read().strip()

    client = BlessClient(region, lambda_function_name, args=args)

    cert = client.sign_key(bastion_user, bastion_user_ip, remote_usernames, bastion_ips, public_key)

    if cert == -1:
        raise ValueError("did not receive cert from BLESS, please check for errors")

    with os.fdopen(os.open(certificate_filename, os.O_WRONLY | os.O_CREAT, 0o600),
                   'w') as cert_file:
        cert_file.write(cert)

    # If cert_file already existed with the incorrect permissions, fix them.
    file_status = os.stat(certificate_filename)
    if 0o600 != (file_status.st_mode & 0o777):
        os.chmod(certificate_filename, stat.S_IRUSR | stat.S_IWUSR)

    print('Wrote Certificate to: ' + certificate_filename)


if __name__ == '__main__':
    main()
