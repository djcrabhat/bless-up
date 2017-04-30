import json
import boto3
from logging import getLogger

try:
    import kmsauth

    KMS_AUTH = True
except ImportError:
    KMS_AUTH = False

log = getLogger(__name__)




class BlessClient:
    def __init__(self, region, function_name='bless', args=None):
        self.region = region
        self.function_name = function_name


        self.kmsauth_autogen = False
        if args:
            if args.kmsauth_autogen_key and args.kmsauth_autogen_service:
                self.kmsauth_autogen_key = args.kmsauth_autogen_key
                self.kmsauth_autogen_service = args.kmsauth_autogen_service
                self.kmsauth_autogen = True
        pass

    def sign_key(self, bastion_user, bastion_user_ip, remote_usernames, bastion_ips, public_key, bastion_command='*',
                 kmsauth=None):
        payload = {'bastion_user': bastion_user, 'bastion_user_ip': bastion_user_ip,
                   'remote_usernames': remote_usernames, 'bastion_ips': bastion_ips,
                   'command': bastion_command, 'public_key_to_sign': public_key}

        if kmsauth:
            payload['kmsauth_token'] = kmsauth
        elif self.kmsauth_autogen:
            auth_username, payload['kmsauth_token'] = self.generate_user_token(bastion_user)

        payload_json = json.dumps(payload)

        log.info('Executing:')
        log.info('payload_json is: \'{}\''.format(payload_json))
        lambda_client = boto3.client('lambda', region_name=self.region)
        response = lambda_client.invoke(FunctionName=self.function_name,
                                        InvocationType='RequestResponse',
                                        LogType='None',
                                        Payload=payload_json)
        log.info('Response: {}\n'.format(response['ResponseMetadata']))

        if response['StatusCode'] != 200:
            log.error('Error creating cert.')
            return -1

        payload = json.loads(response['Payload'].read())

        if 'certificate' not in payload:
            log.error('certificate not found: %s' % payload)
            return -1

        cert = payload['certificate']
        return cert

    def generate_user_token(self, user):
        '''
        Question: what kinda access control is it if I have direct access to the authorization key, generate it myself?
                  You'd probably get something handed to you by https://lyft.github.io/confidant/
        
        :param user: 
        :return:
        
        '''
        if not KMS_AUTH:
            raise ValueError("kmsauth is not installed")

        # user to service authentication
        generator = kmsauth.KMSTokenGenerator(
            # KMS key to use for authentication
            self.kmsauth_autogen_key,

            # Encryption context to use
            {
                # We're authenticating to this service
                'to': self.kmsauth_autogen_service,
                # It's from this user
                'from': user,
                # This token is for a user
                'user_type': 'user'
            },
            # Find the KMS key in this region
            self.region
        )
        username = generator.get_username()
        token = generator.get_token()

        return username, token
