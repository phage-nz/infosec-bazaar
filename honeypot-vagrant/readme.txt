Vagrant Install Notes
"""""""""""""""""""""

Install Vagrant and required libraries:
apt-get install vagrant zlib1g-dev

Fetch and apply the Vagrant plugin patch if you haven't already:
wget https://raw.githubusercontent.com/t0x0-nz/malware-hunting/master/honeypots/vagrant-plugin.patch
sudo patch --directory /usr/lib/ruby/vendor_ruby/vagrant < vagrant-plugin.patch

Install the Vagrant AWS plugin:
vagrant plugin install vagrant-aws

cd into the directory with the Vagrantfile.

Configure the dummy box:
vagrant box add dummy https://github.com/mitchellh/vagrant-aws/raw/master/dummy.box

Fetch the autoinstall script into the 'scripts' directory:
wget https://raw.githubusercontent.com/t0x0-nz/malware-hunting/master/honeypots/autoinstall.sh -O scripts/bootstrap.sh

Edit bootstrap.sh and complete the server and domain naming variable definition.

Edit aws.credentials and enter:
- Your AWS access key.
- Your AWS secret key.
- The name of your EC2 SSH keypair.
- The local path of the EC2 SSH private key.

Pull the AWS credentials into environment variables:
source aws.credentials

Create your Vagrant machine:
vagrant up --provider=aws