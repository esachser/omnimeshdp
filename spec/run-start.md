# Starting OmnimeshDP

## Introduction

This document describes how to start OmnimeshDP.
It must follow some steps and fail if any step fails.

## Steps

1. Read configuration from file or env.
1. Connect to the Spire Agent to get a mTLS configuration.
1. Open the internal and external ports to listen for incoming connections.
   - The next step must only run after this one succeeds.
1. Connect to the Control Plane using the mTLS configuration from step 2.
1. Receive the inicial ScopeSnapshot and prepare routing config.
1. Read namespace subnets from the configuration file.
1. Use packet processsor to configure packet filtering.
1. Read from config and files what services to deploy.
1. Send and receive updates to/from Control Plane and update routing config and packet filtering.
   - This should run until the application is stopped.
1. Clean up and exit.