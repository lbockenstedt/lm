# CPPM Module Guide

The CPPM module provides integration with Aruba ClearPass Policy Manager for network access control and device visibility.

## 1. Capabilities
- **Access Tracker**: Monitoring of authentication attempts and results.
- **Device Inventory**: Listing of endpoints and their posture.
- **Role Management**: Visibility into assigned user and device roles.
- **Policy Mapping**: Identifying which security policies are applying to specific endpoints.

## 2. Configuration
Configuration is managed via **Setup $\rightarrow$ CPPM Configuration**.

### Required Fields
- **Host**: The IP address of the ClearPass Publisher.
- **User**: API username.
- **Password**: API password.

## 3. Technical Implementation
The CPPM spoke interacts with the ClearPass REST API. It supports "API Probing" via the Hub's Diagnostics tool, allowing admins to test raw API paths against the CPPM server.
