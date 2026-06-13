#!/bin/bash
echo "ShadowMap AI Setup"
read -p "Enter your Google API Key: " api_key
echo "GOOGLE_API_KEY=$api_key" > backend/.env
echo "Setup complete! Run ./start.sh to launch ShadowMap AI"
