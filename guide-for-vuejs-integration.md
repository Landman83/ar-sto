# Guide for Integrating STO Investment & Withdrawal Functions in Vue.js

This guide explains how to implement security token offering (STO) investment and withdrawal functionality in a Vue.js application using browser wallets like MetaMask. The implementation focuses on secure transaction signing without exposing private keys.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Setup and Installation](#setup-and-installation)
3. [Connecting to User's Wallet](#connecting-to-users-wallet)
4. [Investing in the STO](#investing-in-the-sto)
   - [Direct Investment](#direct-investment)
   - [Signed Order Investment](#signed-order-investment)
5. [Withdrawing Funds](#withdrawing-funds)
6. [Handling Transaction Status](#handling-transaction-status)
7. [Security Considerations](#security-considerations)
8. [Complete Implementation Example](#complete-implementation-example)

## Prerequisites

- Vue.js application
- ethers.js or web3.js library
- MetaMask or compatible browser wallet
- STO contract address
- ABI definitions for the STO contract

## Setup and Installation

### 1. Install Required Packages

```bash
npm install ethers@5.7.2  # or web3.js
```

### 2. Create a Service for Blockchain Interactions

Create a file named `stoService.js` to handle blockchain interactions:

```javascript
import { ethers } from 'ethers';
import STO_ABI from './abi/sto-abi.json';

export default class STOService {
  constructor(stoAddress) {
    this.stoAddress = stoAddress;
    this.provider = null;
    this.signer = null;
    this.stoContract = null;
  }

  // Initialize connection to wallet and contract
  async connect() {
    // Check if MetaMask is installed
    if (!window.ethereum) {
      throw new Error('MetaMask is not installed. Please install MetaMask to continue.');
    }

    // Request account access
    await window.ethereum.request({ method: 'eth_requestAccounts' });
    
    // Create web3 provider and signer
    this.provider = new ethers.providers.Web3Provider(window.ethereum);
    this.signer = this.provider.getSigner();
    
    // Initialize the STO contract
    this.stoContract = new ethers.Contract(this.stoAddress, STO_ABI, this.signer);
    
    // Return the connected address
    return await this.signer.getAddress();
  }

  // Get STO details
  async getSTODetails() {
    const details = await this.stoContract.getSTODetails();
    return {
      startTime: details[0].toNumber(),
      endTime: details[1].toNumber(),
      hardCap: ethers.utils.formatEther(details[2]),
      softCap: ethers.utils.formatEther(details[3]),
      currentRate: ethers.utils.formatEther(details[4]),
      fundsRaised: ethers.utils.formatEther(details[5]),
      investorCount: details[6].toNumber(),
      tokensSold: ethers.utils.formatEther(details[7]),
      investmentToken: details[8],
      softCapReached: details[9],
      stoClosed: details[10]
    };
  }

  // Get user's current nonce (for signed orders)
  async getNonce(address) {
    return await this.stoContract.getNonce(address);
  }

  // More methods will be added later...
}
```

### 3. Import in Your Vue Component

```javascript
import STOService from '@/services/stoService';

export default {
  data() {
    return {
      stoService: new STOService('YOUR_STO_CONTRACT_ADDRESS'),
      userAddress: null,
      stoDetails: null,
      investmentAmount: '',
      // more state variables...
    }
  },
  // methods will be added later...
}
```

## Connecting to User's Wallet

Create a component or method to connect to the user's wallet:

```javascript
// Inside Vue component methods
methods: {
  async connectWallet() {
    try {
      this.userAddress = await this.stoService.connect();
      this.stoDetails = await this.stoService.getSTODetails();
      
      // Also set up event listeners for account changes
      window.ethereum.on('accountsChanged', this.handleAccountsChanged);
      window.ethereum.on('chainChanged', () => window.location.reload());
      
      return this.userAddress;
    } catch (error) {
      console.error('Error connecting wallet:', error);
      this.$notify({
        type: 'error',
        title: 'Connection Failed',
        text: error.message
      });
    }
  },
  
  handleAccountsChanged(accounts) {
    if (accounts.length === 0) {
      // User disconnected their wallet
      this.userAddress = null;
    } else if (accounts[0] !== this.userAddress) {
      // User switched accounts
      this.userAddress = accounts[0];
      // Refresh relevant data
      this.refreshUserData();
    }
  },
  
  async refreshUserData() {
    // Refresh user-specific data when account changes
    if (this.userAddress) {
      this.stoDetails = await this.stoService.getSTODetails();
      // Load any user-specific data
    }
  }
}
```

## Investing in the STO

There are two ways to invest in the STO:

1. Direct investment via `buyTokens` function
2. Signed order investment via `executeSignedOrder` function

Let's implement both:

### Direct Investment

First, add methods to the `stoService.js` file:

```javascript
// Add to STOService class
async approveTokenSpending(tokenAddress, amount) {
  // Get the ERC20 token contract
  const tokenContract = new ethers.Contract(
    tokenAddress,
    ['function approve(address spender, uint256 amount) public returns (bool)'],
    this.signer
  );
  
  // Approve the STO contract to spend tokens
  const tx = await tokenContract.approve(this.stoAddress, amount);
  return await tx.wait();
}

async buyTokens(beneficiary, amount) {
  // If beneficiary is not specified, use the connected wallet address
  if (!beneficiary) {
    beneficiary = await this.signer.getAddress();
  }
  
  const tx = await this.stoContract.buyTokens(beneficiary, amount);
  return await tx.wait();
}
```

Then implement the Vue component method:

```javascript
// Inside Vue component methods
async investDirectly() {
  try {
    if (!this.investmentAmount || this.investmentAmount <= 0) {
      throw new Error('Please enter a valid investment amount');
    }
    
    const amount = ethers.utils.parseUnits(this.investmentAmount, 18); // Adjust decimals based on your token
    
    // First approve token spending
    this.$toast.info('Please approve token spending in your wallet...');
    await this.stoService.approveTokenSpending(this.stoDetails.investmentToken, amount);
    
    // Then execute the buyTokens transaction
    this.$toast.info('Please confirm the investment transaction in your wallet...');
    const receipt = await this.stoService.buyTokens(this.userAddress, amount);
    
    this.$toast.success('Investment successful!');
    this.investmentAmount = '';
    
    // Refresh STO details
    this.stoDetails = await this.stoService.getSTODetails();
    
    return receipt;
  } catch (error) {
    console.error('Investment failed:', error);
    this.$toast.error(`Investment failed: ${error.message}`);
  }
}
```

### Signed Order Investment

This method allows users to sign an order that can be submitted by an operator later, enabling gas-less transactions for users.

First, add methods to the `stoService.js` file:

```javascript
// Add to STOService class
async createOrderSignature(orderInfo) {
  // Get domain data for EIP-712 signature
  const chainId = (await this.provider.getNetwork()).chainId;
  
  const domain = {
    name: 'Security Token Offering',
    version: '1',
    chainId: chainId,
    verifyingContract: this.stoAddress
  };
  
  // EIP-712 type definition for OrderInfo
  const types = {
    OrderInfo: [
      { name: 'investor', type: 'address' },
      { name: 'investmentToken', type: 'address' },
      { name: 'investmentTokenAmount', type: 'uint256' },
      { name: 'securityTokenAmount', type: 'uint256' },
      { name: 'nonce', type: 'uint256' }
    ]
  };
  
  // Sign the order using EIP-712
  const signature = await this.signer._signTypedData(domain, types, orderInfo);
  
  return {
    order: orderInfo,
    signature
  };
}

async approveTokenForSignedOrder(tokenAddress, amount) {
  // This is still needed as the operator will need allowance to transfer tokens later
  const tokenContract = new ethers.Contract(
    tokenAddress,
    ['function approve(address spender, uint256 amount) public returns (bool)'],
    this.signer
  );
  
  const tx = await tokenContract.approve(this.stoAddress, amount);
  return await tx.wait();
}

// This would typically be called by an operator, not the investor directly
async executeSignedOrder(orderInfo, signature) {
  const tx = await this.stoContract.executeSignedOrder(orderInfo, signature);
  return await tx.wait();
}
```

Then implement the Vue component method:

```javascript
// Inside Vue component methods
async createSignedInvestment() {
  try {
    if (!this.investmentAmount || this.investmentAmount <= 0) {
      throw new Error('Please enter a valid investment amount');
    }
    
    const amount = ethers.utils.parseUnits(this.investmentAmount, 18);
    const address = await this.stoService.signer.getAddress();
    
    // Get current nonce for the user
    const nonce = await this.stoService.getNonce(address);
    
    // Create order info object
    const orderInfo = {
      investor: address,
      investmentToken: this.stoDetails.investmentToken,
      investmentTokenAmount: amount,
      securityTokenAmount: ethers.utils.parseUnits('0', 18), // Often 0 for dynamic pricing
      nonce: nonce
    };
    
    // First approve token spending
    this.$toast.info('Please approve token spending in your wallet...');
    await this.stoService.approveTokenForSignedOrder(this.stoDetails.investmentToken, amount);
    
    // Sign the order
    this.$toast.info('Please sign the order in your wallet...');
    const { order, signature } = await this.stoService.createOrderSignature(orderInfo);
    
    // At this point, you would typically send the order and signature to your backend
    // which would submit it to the blockchain at an appropriate time
    
    this.$toast.success('Order signed successfully! Waiting for operator execution.');
    this.investmentAmount = '';
    
    // Return the signed order for further processing (e.g. sending to backend)
    return { order, signature };
  } catch (error) {
    console.error('Signed order creation failed:', error);
    this.$toast.error(`Signed order failed: ${error.message}`);
  }
}
```

## Withdrawing Funds

First, add methods to the `stoService.js` file:

```javascript
// Add to STOService class
async withdrawInvestment(amount) {
  const amountBN = ethers.utils.parseUnits(amount, 18);
  const tx = await this.stoContract.withdrawInvestment(amountBN);
  return await tx.wait();
}

async getUserInvestment() {
  // This is a custom function you would need to implement based on contract events
  // or other methods to get a user's current investment amount
  const userAddress = await this.signer.getAddress();
  
  // Example: Fetching from events (implementation depends on contract structure)
  const filter = this.stoContract.filters.TokenPurchase(userAddress);
  const events = await this.stoContract.queryFilter(filter);
  
  let totalInvestment = ethers.BigNumber.from(0);
  events.forEach(event => {
    totalInvestment = totalInvestment.add(event.args.investedAmount);
  });
  
  return ethers.utils.formatEther(totalInvestment);
}
```

Then implement the Vue component method:

```javascript
// Inside Vue component methods
async withdrawFunds() {
  try {
    if (!this.withdrawalAmount || this.withdrawalAmount <= 0) {
      throw new Error('Please enter a valid withdrawal amount');
    }
    
    // Confirm the withdrawal
    if (!confirm(`Are you sure you want to withdraw ${this.withdrawalAmount} tokens?`)) {
      return;
    }
    
    this.$toast.info('Please confirm the withdrawal in your wallet...');
    const receipt = await this.stoService.withdrawInvestment(this.withdrawalAmount);
    
    this.$toast.success('Withdrawal successful!');
    this.withdrawalAmount = '';
    
    // Refresh STO details
    this.stoDetails = await this.stoService.getSTODetails();
    
    return receipt;
  } catch (error) {
    console.error('Withdrawal failed:', error);
    this.$toast.error(`Withdrawal failed: ${error.message}`);
  }
}
```

## Handling Transaction Status

Create methods to track transaction status:

```javascript
// Add to the Vue component methods
async trackTransaction(txHash) {
  const provider = this.stoService.provider;
  
  try {
    this.transactionStatus = 'pending';
    
    // Wait for transaction confirmation
    const receipt = await provider.waitForTransaction(txHash);
    
    if (receipt.status === 1) {
      this.transactionStatus = 'success';
      this.$toast.success('Transaction successful!');
    } else {
      this.transactionStatus = 'failed';
      this.$toast.error('Transaction failed!');
    }
    
    return receipt;
  } catch (error) {
    this.transactionStatus = 'failed';
    console.error('Error tracking transaction:', error);
    this.$toast.error(`Transaction error: ${error.message}`);
  }
}
```

## Security Considerations

Add to the guide as a section:

```markdown
## Security Considerations

1. **Never request private keys** - Only use the wallet's signing mechanism (MetaMask, etc.)
2. **Use EIP-712 for structured signing** - Makes it clear what the user is signing
3. **Include nonces in all signatures** - Prevents replay attacks
4. **Verify contract addresses** - Always double-check contract addresses
5. **Handle error messages carefully** - Don't expose sensitive information in error messages
6. **Implement transaction timeouts** - Don't let users wait indefinitely for transactions
7. **Validate input amounts** - Ensure amounts are valid before submitting transactions
8. **Use HTTPS** - Secure your application to prevent man-in-the-middle attacks
9. **Include clear transaction details** - Show users exactly what they're signing
10. **Test thoroughly** - Test all edge cases and error scenarios
```

## Complete Implementation Example

Here's a more complete Vue component example:

```vue
<template>
  <div class="sto-interface">
    <div v-if="!userAddress" class="connect-wallet">
      <h2>Connect your wallet to invest</h2>
      <button @click="connectWallet" class="btn btn-primary">Connect Wallet</button>
    </div>
    
    <div v-else class="sto-dashboard">
      <div class="sto-details">
        <h2>STO Details</h2>
        <div v-if="stoDetails" class="details-grid">
          <div class="detail-item">
            <div class="label">Start Time</div>
            <div class="value">{{ formatDate(stoDetails.startTime) }}</div>
          </div>
          <div class="detail-item">
            <div class="label">End Time</div>
            <div class="value">{{ formatDate(stoDetails.endTime) }}</div>
          </div>
          <div class="detail-item">
            <div class="label">Hard Cap</div>
            <div class="value">{{ stoDetails.hardCap }} tokens</div>
          </div>
          <div class="detail-item">
            <div class="label">Soft Cap</div>
            <div class="value">{{ stoDetails.softCap }} tokens</div>
          </div>
          <div class="detail-item">
            <div class="label">Current Rate</div>
            <div class="value">{{ stoDetails.currentRate }}</div>
          </div>
          <div class="detail-item">
            <div class="label">Funds Raised</div>
            <div class="value">{{ stoDetails.fundsRaised }}</div>
          </div>
          <div class="detail-item">
            <div class="label">Investors</div>
            <div class="value">{{ stoDetails.investorCount }}</div>
          </div>
          <div class="detail-item">
            <div class="label">Tokens Sold</div>
            <div class="value">{{ stoDetails.tokensSold }}</div>
          </div>
          <div class="detail-item">
            <div class="label">Status</div>
            <div class="value">{{ stoDetails.stoClosed ? 'Closed' : 'Open' }}</div>
          </div>
        </div>
        <div v-else class="loading">Loading STO details...</div>
      </div>
      
      <div class="invest-section">
        <h2>Invest in STO</h2>
        <div class="form-group">
          <label for="investment-amount">Investment Amount</label>
          <input 
            id="investment-amount" 
            v-model="investmentAmount" 
            type="number" 
            class="form-control" 
            placeholder="Enter amount" 
            :disabled="stoDetails?.stoClosed"
          />
        </div>
        <div class="actions">
          <button 
            @click="investDirectly" 
            class="btn btn-success" 
            :disabled="!investmentAmount || stoDetails?.stoClosed">
            Invest Directly
          </button>
          <button 
            @click="createSignedInvestment" 
            class="btn btn-primary" 
            :disabled="!investmentAmount || stoDetails?.stoClosed">
            Sign Investment Order
          </button>
        </div>
      </div>
      
      <div class="withdraw-section">
        <h2>Withdraw Funds</h2>
        <div class="form-group">
          <label for="withdrawal-amount">Withdrawal Amount</label>
          <input 
            id="withdrawal-amount" 
            v-model="withdrawalAmount" 
            type="number" 
            class="form-control" 
            placeholder="Enter amount" 
            :disabled="stoDetails?.stoClosed"
          />
        </div>
        <div class="actions">
          <button 
            @click="withdrawFunds" 
            class="btn btn-warning" 
            :disabled="!withdrawalAmount || stoDetails?.stoClosed">
            Withdraw Funds
          </button>
        </div>
      </div>
      
      <div v-if="transactionStatus" class="transaction-status">
        <div class="status">
          <span>Transaction Status: </span>
          <span :class="statusClass">{{ transactionStatus }}</span>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import STOService from '@/services/stoService';

export default {
  name: 'STOInterface',
  data() {
    return {
      stoService: new STOService(process.env.VUE_APP_STO_ADDRESS),
      userAddress: null,
      stoDetails: null,
      investmentAmount: '',
      withdrawalAmount: '',
      transactionStatus: null
    };
  },
  computed: {
    statusClass() {
      return {
        'text-warning': this.transactionStatus === 'pending',
        'text-success': this.transactionStatus === 'success',
        'text-danger': this.transactionStatus === 'failed'
      };
    }
  },
  methods: {
    async connectWallet() {
      // Implementation from earlier sections
    },
    
    handleAccountsChanged(accounts) {
      // Implementation from earlier sections
    },
    
    async refreshUserData() {
      // Implementation from earlier sections
    },
    
    async investDirectly() {
      // Implementation from earlier sections
    },
    
    async createSignedInvestment() {
      // Implementation from earlier sections
    },
    
    async withdrawFunds() {
      // Implementation from earlier sections
    },
    
    async trackTransaction(txHash) {
      // Implementation from earlier sections
    },
    
    formatDate(timestamp) {
      return new Date(timestamp * 1000).toLocaleString();
    }
  },
  async mounted() {
    // Check if user has a connected wallet on page load
    if (window.ethereum && window.ethereum.selectedAddress) {
      await this.connectWallet();
    }
  },
  beforeUnmount() {
    // Remove event listeners
    if (window.ethereum) {
      window.ethereum.removeListener('accountsChanged', this.handleAccountsChanged);
    }
  }
};
</script>

<style scoped>
.sto-interface {
  max-width: 800px;
  margin: 0 auto;
  padding: 20px;
}

.connect-wallet {
  text-align: center;
  margin: 50px 0;
}

.sto-dashboard {
  display: grid;
  gap: 30px;
}

.details-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
  gap: 15px;
  margin-top: 15px;
}

.detail-item {
  border: 1px solid #ddd;
  border-radius: 5px;
  padding: 10px;
  background-color: #f9f9f9;
}

.label {
  font-weight: bold;
  color: #555;
  margin-bottom: 5px;
}

.form-group {
  margin-bottom: 15px;
}

.actions {
  display: flex;
  gap: 10px;
}

.transaction-status {
  padding: 15px;
  border: 1px solid #ddd;
  border-radius: 5px;
  margin-top: 20px;
}

.text-warning {
  color: orange;
}

.text-success {
  color: green;
}

.text-danger {
  color: red;
}
</style>
```

## Working with EIP-712 Signatures

To help you better understand the EIP-712 signature process, here's a detailed explanation of how the signing works:

```javascript
// Detailed explanation of the EIP-712 signing process

/*
EIP-712 allows users to sign structured data instead of just arbitrary message strings.
This makes it much clearer to the user what they're signing and provides better security.

The signature process consists of:

1. Define the domain separator (uniquely identifies the dapp and contract)
2. Define the type structure (specifies what fields are being signed)
3. Provide the actual data to be signed
4. Sign the structured data using the wallet
*/

// For our order signing:
async createOrderSignature(order) {
  // 1. Domain separator defines the context of the signature
  const domain = {
    name: 'Security Token Offering',    // Name of the dapp/protocol
    version: '1',                       // Version of the contract
    chainId: await this.getChainId(),   // Current blockchain chainId
    verifyingContract: this.stoAddress  // Contract address verifying the signature
  };
  
  // 2. Types define the structure of what's being signed
  const types = {
    // This must match the struct defined in your smart contract
    OrderInfo: [
      { name: 'investor', type: 'address' },
      { name: 'investmentToken', type: 'address' },
      { name: 'investmentTokenAmount', type: 'uint256' },
      { name: 'securityTokenAmount', type: 'uint256' },
      { name: 'nonce', type: 'uint256' }
    ]
  };
  
  // 3. The actual data to sign
  const value = {
    investor: order.investor,
    investmentToken: order.investmentToken,
    investmentTokenAmount: order.investmentTokenAmount,
    securityTokenAmount: order.securityTokenAmount,
    nonce: order.nonce
  };
  
  // 4. Sign the data - this will show the user exactly what they're signing
  // in metamask, with each field clearly labeled
  const signature = await this.signer._signTypedData(domain, types, value);
  
  return signature;
}
```

## Conclusion

This guide covered the key aspects of integrating STO investment and withdrawal functionality into a Vue.js application using browser wallets. The implementation enables secure transactions without exposing private keys by leveraging the wallet's native signing capabilities.

The key security features implemented are:
1. Wallet-based signing for authentication and transactions
2. EIP-712 structured data signing for clear user consent
3. Nonce-based replay protection
4. Transaction status tracking and error handling

By following this guide, you can create a secure and user-friendly interface for STO investment and withdrawal operations that works with any EVM-compatible wallet.