blessup
=====

A nice client for [netflix/bless](https://github.com/Netflix/bless)

Usage
-----
```
usage: cli.py [-h] [--function_name FUNCTION_NAME] [--key_to_sign KEY_TO_SIGN]
              [--cert_output CERT_OUTPUT] [--kmsauth KMSAUTH]
              [--kmsauth_autogen_key KMSAUTH_AUTOGEN_KEY]
              [--kmsauth_autogen_service KMSAUTH_AUTOGEN_SERVICE]
              region bastion_user bastion_ip remote_users ssh_source_ip

Sign a cert for a pub key with bless

positional arguments:
  region                AWS region where your lambda is deployed
  bastion_user          user requesting the signing, for logging
  bastion_ip            ip of user requesting the signing, for logging
  remote_users          Comma-separated list of username(s) or authorized
                        principals on the remote server that will be used in
                        the SSH request. This is enforced in the issued
                        certificate.
  ssh_source_ip         The source IP(s) where the SSH connection will be
                        initiated from. Addresses should be comma-separated
                        and can be individual IPs or CIDR format
                        (nn.nn.nn.nn/nn or hhhh::hhhh/nn). This is enforced in
                        the issued certificate.

optional arguments:
  -h, --help            show this help message and exit
  --function_name FUNCTION_NAME
  --key_to_sign KEY_TO_SIGN
  --cert_output CERT_OUTPUT
  --kmsauth KMSAUTH     KMS auth token, if kmsauth is setup. see:
                        github.com/lyft/python-kmsauth
  --kmsauth_autogen_key KMSAUTH_AUTOGEN_KEY
                        if you want to try an automatically generate a user
                        token, then use this key
  --kmsauth_autogen_service KMSAUTH_AUTOGEN_SERVICE
                        if you want to try an automatically generate a user
                        token, the service name being used by BLESS
```

