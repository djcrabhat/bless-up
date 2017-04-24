from setuptools import setup

setup(
      name='blessup',
      version='0.0.1',
      description='BLESS client',
      entry_points={
          'console_scripts': ['blessup=blessup.cli:main'],
      },
      url='http://github.com/djcrabhat/blessup',
      author='DJCrabhat',
      author_email='djcrabhat@sosimplerecords.com',
      license='MIT',
      packages=['blessup'],
      install_requires=[
          'boto3',
          'kmsauth'
      ],
      zip_safe=False
      )