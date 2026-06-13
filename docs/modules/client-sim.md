# Client Simulator Module Guide

The Client Simulator (CS) module is used to generate synthetic traffic and simulate end-user behavior for testing network policies and firewall rules.

## 1. Capabilities
- **Traffic Generation**: Simulating various protocols and traffic patterns.
- **DNS Configuration**: Setting custom DNS profiles for simulated clients.
- **Schedules**: Automating when simulation laods are triggered.

## 2. Configuration
Configuration is managed via **Setup $\rightarrow$ Global Config $\rightarrow$ CS**. It uses a JSON-based profile system allowing multiple simulation profiles to be defined.

## 3. Technical Implementation
The Client Sim spoke runs a series of traffic generators. It is primarily used as a validation tool to ensure that the rules configured in OPNsense or CPPM are actually working as intended by observing the resulting traffic patterns.
