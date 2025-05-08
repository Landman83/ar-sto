# OpenZeppelin Transparent Proxy Deployment Guide

This guide explains how to deploy the STO protocol using the OpenZeppelin Transparent Proxy pattern, which follows best practices for upgradeable contracts.

## Overview

The OpenZeppelin Transparent Proxy pattern provides several advantages:

1. **Upgradeable Contracts**: Allows you to replace the implementation contract while preserving state
2. **Clean Separation of Concerns**: Clear separation between admin operations and contract usage
3. **Standardized Pattern**: Well-established pattern used by most major DeFi protocols
4. **Security**: Well-audited by the community with known patterns for safe usage

## Components

The deployment consists of these key components:

1. **CappedSTOUpgradeable**: The implementation contract with proper initialization functions
2. **ProxyAdmin**: The contract that controls the proxy and manages upgrades
3. **TransparentUpgradeableProxy**: The proxy contract that delegates calls to the implementation
4. **Auxiliary Contracts**: All the supporting contracts needed by the STO system

## Deployment Process

The `OZProxyDeploy.s.sol` script implements a full deployment following these steps:

1. Deploy the implementation contract (`CappedSTOUpgradeable`)
2. Deploy the proxy admin (`ProxyAdmin`)
3. Deploy the proxy (`TransparentUpgradeableProxy`) pointing to the implementation
4. Initialize the proxy with the correct parameters
5. Deploy all auxiliary contracts (pricing, escrow, etc.)
6. Configure the STO with all the auxiliary contracts

## How to Deploy

Run the deployment script with Foundry:

```bash
forge script script/OZProxyDeploy.s.sol:OZProxyDeployScript --broadcast --verify -vvvv
```

Make sure to set the required environment variables:

```bash
export PRIVATE_KEY=...
export RPC_URL=...
export CHAIN_ID=...
export SECURITY_TOKEN_ADDRESS=...
export INVESTMENT_TOKEN=...
export HARD_CAP=...
export SOFT_CAP=...
export MIN_INVESTMENT=...
export RATE=...
export DEPLOYER_ADDRESS=...
```

## Upgrading the Implementation

To upgrade to a new implementation in the future:

1. Deploy the new implementation contract
2. Call `ProxyAdmin.upgrade(proxy, newImplementation)` from the admin address

Example using Foundry:

```solidity
// In a new script
ProxyAdmin admin = ProxyAdmin(ADMIN_ADDRESS);
CappedSTOUpgradeable newImplementation = new CappedSTOUpgradeable(...);
admin.upgrade(PROXY_ADDRESS, address(newImplementation));
```

## Differences from Previous Deployment Approach

The key differences from the previous deployment approach are:

1. **Proper Initialization**: Uses an `initialize` function instead of relying on constructors
2. **Standard Upgradability**: Uses OpenZeppelin's well-tested proxy contracts
3. **Admin Separation**: Uses a separate admin contract to prevent admin/user confusion
4. **Initialization Guards**: Prevents re-initialization of the contract
5. **Storage Gaps**: Includes storage gaps for safe future upgrades

## Contract Architecture

```
TransparentUpgradeableProxy
├─ delegates to ─> CappedSTOUpgradeable
│                  ├─ InvestmentManager
│                  ├─ FinalizationManager
│                  ├─ VerificationManager
│                  ├─ Compliance
│                  ├─ Escrow
│                  ├─ Refund
│                  ├─ Minting
│                  ├─ Fees
│                  └─ FixedPrice
└─ managed by ─> ProxyAdmin
```

## Best Practices

When working with this architecture:

1. **Never initialize the implementation**: Only initialize via the proxy
2. **Keep constructors empty or basic**: Implementation constructors should do minimal work
3. **Use storage gaps**: Always include a storage gap in upgradeable contracts
4. **Check initialization**: Always check for and prevent re-initialization
5. **Be careful with contract references**: Make sure all contracts refer to the proxy, not the implementation
6. **Use the ProxyAdmin for upgrades**: Don't call upgrade methods directly on the proxy

## Access Control Solutions

The deployment script handles access control requirements by using helper functions in the CappedSTOUpgradeable contract:

1. **VerificationManager**: Setting the attribute registry requires STO authorization
   - Solution: The `setAttributeRegistryOnVerificationManager(address, address)` helper method allows the STO proxy to call the VerificationManager with correct permissions

2. **InvestmentManager**: Setting the STOConfig requires STO authorization
   - Solution: The `setSTOConfigOnInvestmentManager(address, address)` helper method routes calls through the STO proxy

3. **FinalizationManager**: Setting the STOConfig requires STO authorization
   - Solution: The `setSTOConfigOnFinalizationManager(address, address)` helper method routes calls through the STO proxy

These helper methods work because:
- They accept explicit addresses instead of using immutable fields (which are problematic in proxy patterns)
- They enforce proper access control in the STO contract
- They allow the deployer to set up the proper relationships between components

## Troubleshooting

If you encounter issues:

1. **Initialization failures**: Check that the initialize function signature matches what the proxy is calling
2. **Missing functions**: Ensure the implementation has all required functions
3. **Access control issues**: Verify the caller has the appropriate roles
   - "Only STO contract can call": Use the appropriate helper methods in CappedSTOUpgradeable
   - "Unauthorized": Ensure the caller has OPERATOR_ROLE or FACTORY_ROLE
4. **Contract size limits**: Keep implementations under the contract size limit (24KB)
5. **Storage layout conflicts**: Be careful not to change storage layout in upgrades