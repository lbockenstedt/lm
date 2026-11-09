# Lab Manager: Module Class Architecture

To ensure a "single pane of glass" experience and allow for interchangeable infrastructure, Lab Manager uses a **Module Class** system. Instead of product-specific navigation, the UI is organized by functional categories.

## Module Class Mappings

| Category (Class) | Supported Products (Examples) |
| :--- | :--- |
| **Virtual Machines** | Proxmox, KVM, VMware, UTM |
| **Firewall** | OPNsense, pfSense, Juniper, Fortigate |
| **IPAM** | NetBox, phpIPAM |
| **Security/NAC** | ClearPass (CPPM), Cisco ISE |

## UI Implementation Logic

### 1. Side Navigation
The left-hand navigation menu displays the **Category Name** (e.g., "Firewall") rather than the specific product name. A category appears in the menu if at least one approved spoke belonging to that class is reporting in.

### 2. Product Selection (The "Swappable" View)
When a user selects a category:
- **Single Product**: If only one product of that class is connected and approved (e.g., only OPNsense), the UI directly renders that product's management sub-menus.
- **Multiple Products**: If multiple products of the same class are active (e.g., OPNsense and pfSense), a set of **Product Tabs** appears at the top of the viewport.
    - The user selects the desired product from the tabs.
    - The sub-menus and content then update to reflect the selected product's capabilities.

### 3. Dynamic Visibility
- Product tabs and category menus are only visible if the corresponding spoke is **Approved** and **Reporting** (Connected).
- If a spoke is un-approved, its associated product is removed from the category views and the category itself is hidden if no other products of that class remain.

## Module Developer Requirements
Any new module must be assigned to one of the predefined classes. The module must implement a standard set of command interfaces for its class to ensure the "Stitched View" and category-based navigation work seamlessly.

### Credentials must live in the Credential Vault
Any new module that holds a connection secret (API key, token, password) MUST store it in the Credential Vault whenever the vault is enabled. Never persist the secret inline in `global_config`.
- Add the product's secret fields to `SECRET_FIELDS` in `core/src/instance_vault.py`; add its storage key to `VAULT_REQUIRED` if it cannot work without the secret.
- The stored record keeps only a non-secret `vault_credential: {bucket, name}` reference.
- On create/update routes call `instance_vault.validate_ref` then `strip_inline_secrets`.
- At push time (spoke connect and fleet push) call `overlay` / `overlay_many` on a copy so the secret reaches the spoke without being stored.
- List routes must never return the secret; expose a boolean such as `api_key_set`.
- In the WebUI device type set `vaultPicker: true`, `vaultRequired: true` and `vaultSecret: true` on the secret field (see `DEVICE_TYPES.firewall`/`truenas` in `module-management.js`).
- Add a test in `core/tests/test_instance_vault.py` covering the missing-reference rejection and the overlay.
