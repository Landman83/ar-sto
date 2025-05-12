# Fix for STO Agent Registration Issue

## Problem Identified

When deploying the STO using the OZProxyDeploy.s.sol script, the following error occurs:

```
[21531] TransparentUpgradeableProxy::fallback()
  ├─ [16665] CappedSTOUpgradeable::registerAsAgent() [delegatecall]
  │   ├─ [7425] 0x7c8c75bBD60123cC5a743dF08F5d33D142bB5f8E::registerSTO(TransparentUpgradeableProxy: [0xf5b5201aF149dbE4dd16D8628ddEc97dBA58E073])
  │   │   ├─ [2617] 0xB137Aa3C17203F5956204Af11290d8CF907EC7Aa::registerSTO(TransparentUpgradeableProxy: [0xf5b5201aF149dbE4dd16D8628ddEc97dBA58E073]) [delegatecall]
  │   │   │   └─ ← [Revert] OwnableUnauthorizedAccount(0xf5b5201aF149dbE4dd16D8628ddEc97dBA58E073)
  │   │   └─ ← [Revert] OwnableUnauthorizedAccount(0xf5b5201aF149dbE4dd16D8628ddEc97dBA58E073)
  │   └─ ← [Revert] Failed to register STO with security token
  └─ ← [Revert] Failed to register STO with security token
```

This error indicates that the STO proxy (address 0xf5b5201aF149dbE4dd16D8628ddEc97dBA58E073) is trying to call `registerSTO` on the security token, but this method can only be called by the token owner.

## Root Cause

After analyzing the code:

1. In the CappedSTO contract, there's a `registerAsAgent()` function (line 322-345) that tries to register the STO with the security token by calling `IToken(securityToken).registerSTO(address(this))`.

2. According to the IToken interface, the `registerSTO` method can only be called by the token owner:
   ```solidity
   /**
    * @dev Register a Security Token Offering (STO) contract that should be allowed to mint tokens
    * @param _stoContract The address of the STO contract to register
    * This function can only be called by the owner of the token
    * The STO contract will automatically be added as an agent and will be able to mint tokens
    * emits a `STORegistered` event
    */
   function registerSTO(address _stoContract) external;
   ```

3. In the OZProxyDeploy.s.sol script, at line 625-630, the script attempts to call `registerAsAgent()` on the STO proxy:
   ```solidity
   try sto.registerAsAgent() {
       console.log("STO registered as agent on the security token");
   } catch {
       console.log("Failed to register STO as agent - manual registration may be needed");
   }
   ```

4. The error occurs because the STO proxy itself is trying to register itself with the security token, but only the token owner has permission to do this.

## Solution

You need to modify the approach to register the STO as an agent. Here are two options:

### Option 1: Manual Registration (Recommended)

After deploying the STO, the security token owner should manually call the `registerSTO` function on the security token:

```solidity
// As the token owner, call:
IToken(securityTokenAddress).registerSTO(stoProxyAddress);
```

This can be done using a separate script or through a wallet interface like Remix.

### Option 2: Modify the Deployment Script

If you want to automate this in the deployment script, you need to ensure the script is executed by the token owner:

1. Ensure the private key used in the deployment script belongs to the token owner
2. Add a direct call to the token's registerSTO method:

```solidity
// In OZProxyDeploy.s.sol, replace or supplement the registerAsAgent call with:
try IToken(securityToken).registerSTO(stoAddress) {
    console.log("STO registered with the security token successfully");
} catch Error(string memory reason) {
    console.log("Failed to register STO with security token. Reason:", reason);
} catch {
    console.log("Failed to register STO with security token (unknown error)");
}
```

## Important Note

When registering the STO with the security token, the security token automatically adds the STO as an agent. This is a crucial step because the agent role is required for the STO to:

- Mint tokens for investors
- Perform other privileged operations on the token

Without being registered as an agent, the STO will not be able to mint tokens, which is essential for the token sale functionality.