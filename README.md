blessup
=====

A nice client for [netflix/bless](https://github.com/Netflix/bless)

Usage
-----
```
usage: cli.py [-h] [--function_name FUNCTION_NAME] [--key_to_sign KEY_TO_SIGN]
              [--cert_output CERT_OUTPUT] [--kmsauth KMSAUTH]
              [--kmsauth_autogen_key KMSAUTH_AUTOGEN_KEY]
              [--kmsauth_autogen_service KMSAUTH_AUTOGEN_SERVICE] [-v]
              region bastion_user bastion_ip remote_users ssh_source_ip

Get your pub key signed by BLESS

positional arguments:
  region                AWS region where your lambda is deployed
  bastion_user          User requesting the signing, for logging
  bastion_ip            IP of user requesting the signing, for logging
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
                        Name of the BLESS lambda function
  --key_to_sign KEY_TO_SIGN
                        The .pub key to sign, defaults to ~/.ssh/id_rsa.pub
  --cert_output CERT_OUTPUT
                        The output of the signed request. defaults to ~/.ssh
                        /id_rsa-cert.pub
  --kmsauth KMSAUTH     KMS auth token, if kmsauth is setup. see:
                        github.com/lyft/python-kmsauth
  --kmsauth_autogen_key KMSAUTH_AUTOGEN_KEY
                        If you want to try an automatically generate a user
                        token, the key to usthis key
  --kmsauth_autogen_service KMSAUTH_AUTOGEN_SERVICE
                        If you want to try an automatically generate a user
                        token, the service name being used by BLESS
  -v, --verbose         enable verbose logging, multiple "v"s for deeper
                        logging levels
```

