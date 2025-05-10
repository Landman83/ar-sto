#!/usr/bin/env node

const { ethers } = require('ethers');
const readline = require('readline');
const dotenv = require('dotenv');
const fs = require('fs');

// Load environment variables
dotenv.config();

// Configuration - using existing .env variables
const STO_CONTRACT_ADDRESS = process.env.STO_ADDRESS;
const INVESTMENT_TOKEN_ADDRESS = process.env.INVESTMENT_TOKEN;
const INVESTOR_PRIVATE_KEY = process.env.PRIVATE_KEY;
const RPC_URL = process.env.RPC_URL || 'http://localhost:8545';
const CHAIN_ID = parseInt(process.env.CHAIN_ID || '137'); // Default to Polygon Mainnet

// Debug mode
const DEBUG = process.env.DEBUG === 'true' || false;

// Load ABIs
const stoAbi = JSON.parse(fs.readFileSync('./out/CappedSTO.sol/CappedSTO.json')).abi;
const erc20Abi = JSON.parse(fs.readFileSync('./out/TestERC20.sol/TestERC20.json')).abi;

// Initialize provider and signer
const provider = new ethers.providers.JsonRpcProvider(RPC_URL);
const wallet = new ethers.Wallet(INVESTOR_PRIVATE_KEY, provider);

// Initialize contracts
const stoContract = new ethers.Contract(STO_CONTRACT_ADDRESS, stoAbi, wallet);
const investmentToken = new ethers.Contract(INVESTMENT_TOKEN_ADDRESS, erc20Abi, wallet);

// Create readline interface for CLI interaction
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

// EIP-712 domain and types
const domain = {
  name: 'Security Token Offering', // Changed to match the contract exactly (with spaces)
  version: '1',
  chainId: CHAIN_ID,
  verifyingContract: STO_CONTRACT_ADDRESS
};

const types = {
  OrderInfo: [
    { name: 'investor', type: 'address' },
    { name: 'investmentToken', type: 'address' },
    { name: 'investmentTokenAmount', type: 'uint256' },
    { name: 'securityTokenAmount', type: 'uint256' },
    { name: 'nonce', type: 'uint256' }
  ]
};

async function getSTODetails() {
  try {
    const details = await stoContract.getSTODetails();

    // Parse the details array based on the contract's return format
    const [
      startTime,
      endTime,
      hardCap,
      softCap,
      currentRate,
      fundsRaised,
      investorCount,
      tokensSold,
      investmentTokenAddress,
      softCapReached,
      stoClosed
    ] = details;

    console.log('\n*** STO DETAILS ***');
    console.log(`Hard Cap: ${ethers.utils.formatEther(hardCap)} tokens`);
    console.log(`Soft Cap: ${ethers.utils.formatEther(softCap)} tokens`);
    console.log(`Current Rate: ${ethers.utils.formatEther(currentRate)} tokens per investment token`);
    console.log(`Funds Raised: ${ethers.utils.formatEther(fundsRaised)} investment tokens`);
    console.log(`Investors: ${investorCount.toString()}`);
    console.log(`Tokens Sold: ${ethers.utils.formatEther(tokensSold)} tokens`);
    console.log(`STO Status: ${stoClosed ? 'Closed' : 'Open'}`);
    console.log('********************\n');

    return details;
  } catch (error) {
    console.error('Error fetching STO details:', error);
    throw error;
  }
}

async function checkOperatorRole() {
  try {
    console.log('Checking if current address has OPERATOR_ROLE...');

    // Define OPERATOR_ROLE bytes32 value
    const OPERATOR_ROLE = ethers.utils.keccak256(ethers.utils.toUtf8Bytes('OPERATOR_ROLE'));

    // Check if the wallet address has the OPERATOR_ROLE
    const hasRole = await stoContract.hasRole(OPERATOR_ROLE, wallet.address);
    console.log(`Address ${wallet.address} ${hasRole ? 'HAS' : 'DOES NOT HAVE'} OPERATOR_ROLE`);

    // This is a good indication if the old version of the contract is deployed
    // If hasRole returns true and our wallet has OPERATOR_ROLE, the transaction should work
    // If it returns false and we still get "Invalid operation", it suggests the contract
    // still has the restriction but our account doesn't have the role

    return hasRole;
  } catch (error) {
    console.error('Error checking operator role:', error);
    console.log('This may indicate that the contract does not implement the AccessControl interface as expected');
    return false;
  }
}

async function checkAllowance() {
  try {
    const allowance = await investmentToken.allowance(wallet.address, STO_CONTRACT_ADDRESS);
    return allowance;
  } catch (error) {
    console.error('Error checking allowance:', error);
    throw error;
  }
}

async function approveInvestmentToken(amount) {
  try {
    console.log(`Approving ${ethers.utils.formatEther(amount)} investment tokens to be spent by the STO contract...`);
    const tx = await investmentToken.approve(STO_CONTRACT_ADDRESS, amount);
    console.log(`Approval transaction hash: ${tx.hash}`);
    await tx.wait();
    console.log('Approval confirmed!');
  } catch (error) {
    console.error('Error approving tokens:', error);
    throw error;
  }
}

async function getNonce() {
  try {
    const nonce = await stoContract.getNonce(wallet.address);
    return nonce;
  } catch (error) {
    console.error('Error getting nonce:', error);
    throw error;
  }
}

async function signOrder(investmentTokenAmount) {
  try {
    const nonce = await getNonce();
    console.log(`Current nonce for ${wallet.address}: ${nonce.toString()}`);
    
    // Calculate expected security tokens at current rate
    const details = await stoContract.getSTODetails();
    const currentRate = details[4]; // Assuming the 5th element is the current rate
    
    // Calculate security token amount based on rate
    // rate is in tokens per investment token with 18 decimals
    const securityTokenAmount = investmentTokenAmount.mul(currentRate).div(ethers.utils.parseEther('1'));
    
    // Create the order - using BigNumber for amounts exactly as expected by the contract
    const order = {
      investor: wallet.address,
      investmentToken: INVESTMENT_TOKEN_ADDRESS,
      investmentTokenAmount: investmentTokenAmount, // Keep as BigNumber
      securityTokenAmount: securityTokenAmount, // Keep as BigNumber
      nonce: nonce // Keep as BigNumber
    };
    
    console.log('Signing order:');
    console.log(JSON.stringify(order, null, 2));
    
    // Sign the order with EIP-712
    const signature = await wallet._signTypedData(domain, types, order);
    
    return { order, signature };
  } catch (error) {
    console.error('Error signing order:', error);
    throw error;
  }
}

async function submitOrder(order, signature) {
  try {
    console.log('Submitting signed order to the STO contract...');

    // Convert the order to the format expected by the contract
    // The contract expects an OrderInfo struct as a tuple
    const orderForContract = [
      order.investor,
      order.investmentToken,
      order.investmentTokenAmount,  // Already BigNumber
      order.securityTokenAmount,    // Already BigNumber
      order.nonce                   // Already BigNumber
    ];

    if (DEBUG) {
      console.log('Order details:');
      console.log(JSON.stringify(order, null, 2));
      console.log(`Signature: ${signature}`);
      console.log('Contract address:', STO_CONTRACT_ADDRESS);

      // Explicitly check the function exists
      const function_signature = "0x62325c2f"; // Function signature for executeSignedOrder
      console.log('Function availability check:',
                  stoContract.interface.fragments.some(f =>
                    f.type === 'function' &&
                    f.name === 'executeSignedOrder'));

      // Try to manually verify the order and signature - similar to what the contract does
      try {
        // This is how ethers.js handles EIP-712 signing
        const orderHash = ethers.utils._TypedDataEncoder.hash(domain, types, order);
        console.log('Order hash (from ethers):', orderHash);
        
        // Log the order components for debugging
        console.log('Order components:');
        console.log('- Investor:', order.investor);
        console.log('- Investment Token:', order.investmentToken);
        console.log('- Investment Amount:', order.investmentTokenAmount.toString());
        console.log('- Security Token Amount:', order.securityTokenAmount.toString());
        console.log('- Nonce:', order.nonce.toString());
        
        // For verifying the signature
        const recoveredAddress = ethers.utils.recoverAddress(orderHash, signature);
        console.log('Recovered signer:', recoveredAddress);
        console.log('Expected signer:', order.investor);
        console.log('Signature valid:', recoveredAddress.toLowerCase() === order.investor.toLowerCase());
        
        // Log the signature components in a format that mimics the test
        const sig = ethers.utils.splitSignature(signature);
        console.log('Signature components:');
        console.log('- v:', sig.v);
        console.log('- r:', sig.r);
        console.log('- s:', sig.s);
      } catch (e) {
        console.error('Error verifying signature:', e);
      }
    }

    // Use manual gas estimation and override
    const gasEstimate = 500000; // Set a reasonable gas limit manually

    if (DEBUG) {
      console.log('Calling stoContract.executeSignedOrder with:');
      console.log('- Contract address:', STO_CONTRACT_ADDRESS);
      console.log('- Order tuple:', orderForContract.map(val => 
        typeof val === 'object' && val.toString ? val.toString() : val));
      console.log('- Signature:', signature);
      console.log('- Gas limit:', gasEstimate);
    }
    
    // Submit the order with manual gas limit to the STO contract (not InvestmentManager)
    const tx = await stoContract.executeSignedOrder(
      orderForContract,
      signature,
      { gasLimit: gasEstimate }
    );
    console.log(`Transaction hash: ${tx.hash}`);

    // Wait for confirmation
    console.log('Waiting for transaction confirmation...');
    const receipt = await tx.wait();
    console.log(`Transaction confirmed in block ${receipt.blockNumber}`);

    return receipt;
  } catch (error) {
    console.error('Error submitting order:', error);

    // Extract more specific error message if available
    if (error.error && error.error.message) {
      console.error('Contract error message:', error.error.message);
    } else if (error.data) {
      // Try to decode the error data
      try {
        const errorData = error.data;
        console.error('Contract error data:', errorData);
      } catch (e) {
        console.error('Could not decode error data');
      }
    }

    throw error;
  }
}

async function main() {
  try {
    console.log(`Connected to the blockchain as ${wallet.address}`);
    console.log('Fetching initial STO details...');

    const details = await getSTODetails();

    // Check if the STO is active
    const [startTime, endTime, hardCap, softCap, currentRate, fundsRaised, investorCount, tokensSold, investmentTokenAddress, softCapReached, stoClosed] = details;

    if (stoClosed) {
      console.error("The STO is closed. Cannot submit orders.");
      process.exit(1);
    }

    // Check if we have the OPERATOR_ROLE
    const hasOperatorRole = await checkOperatorRole();

    // If we don't have OPERATOR_ROLE, warn the user that the transaction might fail
    if (!hasOperatorRole) {
      console.warn("\nWARNING: Your address does not have the OPERATOR_ROLE.");
      console.warn("If the contract hasn't been updated to remove the role restriction,");
      console.warn("the transaction will fail with 'Invalid operation'.");
      console.warn("Proceeding anyway...\n");
    }

    const now = Math.floor(Date.now() / 1000);
    if (now < startTime.toNumber()) {
      console.error("The STO has not started yet.");
      process.exit(1);
    }

    if (now > endTime.toNumber()) {
      console.error("The STO has ended.");
      process.exit(1);
    }

    console.log("STO is active and accepting investments.");
    
    rl.question('Enter the amount of investment tokens to contribute: ', async (amountStr) => {
      try {
        // Convert the input amount to wei
        const investmentAmount = ethers.utils.parseEther(amountStr);
        console.log(`You're contributing ${amountStr} investment tokens.`);
        
        // Check and set allowance if needed
        const allowance = await checkAllowance();
        if (allowance.lt(investmentAmount)) {
          console.log(`Current allowance (${ethers.utils.formatEther(allowance)}) is less than the investment amount.`);
          await approveInvestmentToken(investmentAmount);
        } else {
          console.log(`Current allowance is sufficient: ${ethers.utils.formatEther(allowance)} tokens.`);
        }
        
        // Sign the order
        const { order, signature } = await signOrder(investmentAmount);
        
        // Submit the signed order
        await submitOrder(order, signature);
        
        // Check the updated STO details
        console.log('\nFetching updated STO details after your investment:');
        await getSTODetails();
        
        console.log('Investment completed successfully!');
        rl.close();
      } catch (error) {
        console.error('Error in investment process:', error);
        rl.close();
      }
    });
  } catch (error) {
    console.error('Error in main process:', error);
    rl.close();
  }
}

// Execute the main function
main().catch(console.error);