# Step 1: Import the Elastic PGP Key
# This key verifies that the packages we download are authentic.
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg

# Step 2: Add the Official Elastic APT Repository
# This tells your system where to find the software. First, ensure the transport tool is installed.
sudo apt-get install apt-transport-https
# Then, add the repository. The '[signed-by=...]' part ties it to the key we just imported.
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list

# Step 3: Install Elasticsearch and Kibana
# Update the package list to include the new repo, then install both.
sudo apt-get update
# Watch the terminal output carefully during this step!
sudo apt-get install elasticsearch kibana
#IMPORTANT: During the Elasticsearch installation, pay close attention to the terminal output. It will display the auto-generated password for the elastic superuser.

# Step 4: Start Elasticsearch and Configure It to Start on Boot
sudo systemctl daemon-reload
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch

# (Wait about a minute for Elasticsearch to fully initialize)

# Step 5: Configure Kibana to Connect Securely
# Generate an enrollment token. This token is valid for 30 minutes.
sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana

# Step 6: Start Kibana and Configure It to Start on Boot
sudo systemctl enable kibana
sudo systemctl start kibana

# To complete the setup via Kibana's web interface:

# Open your browser and go to http://<your_ubuntu_server_ip>:5601.

# You will see a setup page. Paste the enrollment token you generated in Step 5 into the box and click "Configure Elastic".

# Kibana will then ask for a verification code. You can get this code by running the following command on your server:

sudo /usr/share/kibana/bin/kibana-verification-code