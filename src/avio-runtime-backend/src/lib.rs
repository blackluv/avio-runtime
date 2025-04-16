use ic_cdk::export::candid::{CandidType, Deserialize};
use ic_cdk_macros::*;
use std::collections::HashMap;
use evm::backend::{MemoryBackend, ApplyBackend, Apply};
use evm::executor::{StackExecutor, StackSubstateMetadata};
use evm::{Config, Context, ExitReason, ExitSucceed, U256};
use ic_cdk::api::management_canister::ecdsa::{sign_with_ecdsa, EcdsaKeyId, SignWithEcdsaArgument};
use sha2::{Digest, Sha256};
use hex;
use tiny_keccak::{Hasher, Keccak};
use ethabi::{Function, Param, ParamType, Token};
use secp256k1::{ecdsa::RecoverableSignature, Message, Secp256k1};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use ripemd160::{Ripemd160, Digest as Ripemd160Digest};
use base58::ToBase58;
use mongodb::{Client as MongoClient, options::ClientOptions, bson::doc};
use moka::sync::Cache;
use log::{info, error};
use revm::{EVM, TransactTo, Env, Return, AccountInfo, Bytecode};
use tokio::task;

#[derive(CandidType, Deserialize, Default)]
struct EvmState {
    contracts: HashMap<String, String>, // Contract address -> Bytecode
    balances: HashMap<String, U256>,    // EVM address -> DOGE balance
    gas_prices: HashMap<String, U256>,  // EVM address -> Gas price per unit
    tx_status: HashMap<String, String>, // Transaction ID -> Status
    storage: HashMap<String, HashMap<U256, U256>>, // Contract address -> Storage (Key, Value)
    doge_wallet_address: String, // Runtime's DOGE wallet address
    doge_node_url: String,       // URL of the DOGE node
    treasury_address: String,    // Treasury address for gas fees
    doge_to_evm: HashMap<String, String>, // DOGE address -> EVM address
    contract_cache: Cache<String, Vec<u8>>, // Cache for contract bytecode
    balance_cache: Cache<String, U256>,    // Cache for balances
}

thread_local! {
    static EVM_STATE: std::cell::RefCell<EvmState> = std::cell::RefCell::new(EvmState::default());
}

#[update]
async fn deploy_smart_contract(address: String, bytecode: String) -> Result<String, String> {
    EVM_STATE.with(|state| {
        state.borrow_mut().contracts.insert(address.clone(), bytecode);
    });
    Ok(format!("Contract deployed at: {}", address))
}

#[update]
async fn execute_smart_contract(
    caller_doge_address: String,
    contract_address: String,
    input_data: String,
    gas_price: U256,
    signature: Vec<u8>,
) -> Result<String, String> {
    // Verify the signature
    let message = format!("{}{}{}", caller_doge_address, contract_address, input_data);
    let message_hash = Sha256::digest(message.as_bytes());
    if !verify_signature(&caller_doge_address, &message_hash, &signature) {
        return Err("Invalid signature".to_string());
    }

    // Map DOGE address to EVM address
    let caller_evm_address = EVM_STATE.with(|state| {
        state.borrow().doge_to_evm.get(&caller_doge_address).cloned()
    });

    let caller_evm_address = match caller_evm_address {
        Some(addr) => addr,
        None => return Err("DOGE address not found in mapping".to_string()),
    };

    // Deduct gas fee from the caller's balance
    EVM_STATE.with(|state| {
        let mut state_mut = state.borrow_mut();
        if let Some(balance) = state_mut.balances.get_mut(&caller_evm_address) {
            if *balance < gas_price {
                return Err("Insufficient DOGE balance for gas".to_string());
            }
            *balance -= gas_price;
        } else {
            return Err("Caller balance not found".to_string());
        }
    });

    // Execute the contract using revm
    let mut evm = EVM::new();
    let contract_bytecode = EVM_STATE.with(|state| {
        state.borrow().contracts.get(&contract_address).cloned()
    });

    let contract_bytecode = match contract_bytecode {
        Some(code) => Bytecode::new_raw(hex::decode(code).unwrap()),
        None => return Err("Contract not found".to_string()),
    };

    let caller = hex::decode(caller_evm_address).unwrap();
    let contract = hex::decode(contract_address).unwrap();
    let input = hex::decode(input_data).unwrap();

    let env = Env {
        caller: caller.into(),
        transact_to: TransactTo::Call(contract.into()),
        data: input.into(),
        value: U256::zero(),
        gas_limit: 1_000_000,
        gas_price,
        ..Default::default()
    };

    evm.env = env;
    evm.database(AccountInfo {
        balance: U256::zero(),
        code: Some(contract_bytecode),
        ..Default::default()
    });

    let result = evm.transact().unwrap();

    match result.exit_reason {
        Return::Return => {
            // Apply storage changes
            EVM_STATE.with(|state| {
                let mut state_mut = state.borrow_mut();
                let contract_storage = state_mut.storage.entry(contract_address.clone()).or_insert(HashMap::new());
                for (key, value) in result.state.iter() {
                    contract_storage.insert(*key, *value);
                }
            });

            Ok(format!("Executed contract at {} with result: {:?}", contract_address, result.output))
        }
        _ => Err("Contract execution failed".to_string()),
    }
}

#[update]
async fn deposit_doge(
    caller_doge_address: String,
    amount: U256,
    public_key: Vec<u8>,
    signature: Vec<u8>,
) -> Result<String, String> {
    // Verify the signature
    let message = format!("{}{}{}", caller_doge_address, amount, hex::encode(&public_key));
    let message_hash = Sha256::digest(message.as_bytes());
    if !verify_signature(&caller_doge_address, &message_hash, &signature) {
        return Err("Invalid signature".to_string());
    }

    // Verify the public key corresponds to the DOGE address
    if !verify_doge_address(&caller_doge_address, &public_key)? {
        return Err("Invalid public key for DOGE address".to_string());
    }

    // Derive EVM address from the public key
    let evm_address = derive_evm_address(&public_key)?;

    // Update the caller's balance
    EVM_STATE.with(|state| {
        let mut state_mut = state.borrow_mut();
        let balance = state_mut.balances.entry(evm_address.clone()).or_insert(U256::zero());
        *balance += amount;

        // Store the DOGE-to-EVM mapping
        state_mut.doge_to_evm.insert(caller_doge_address, evm_address);
    });

    Ok(format!("Deposited {} DOGE to {}", amount, evm_address))
}

#[update]
async fn withdraw_doge(
    caller_doge_address: String,
    recipient_doge_address: String,
    amount: U256,
    signature: Vec<u8>,
) -> Result<String, String> {
    info!("Withdrawal request from {}: {} DOGE to {}", caller_doge_address, amount, recipient_doge_address);

    // Verify the signature
    let message = format!("{}{}{}", caller_doge_address, recipient_doge_address, amount);
    let message_hash = Sha256::digest(message.as_bytes());
    if !verify_signature(&caller_doge_address, &message_hash, &signature) {
        error!("Invalid signature for {}", caller_doge_address);
        return Err("Invalid signature".to_string());
    }

    // Map DOGE address to EVM address
    let caller_evm_address = EVM_STATE.with(|state| {
        state.borrow().doge_to_evm.get(&caller_doge_address).cloned()
    });

    let caller_evm_address = match caller_evm_address {
        Some(addr) => addr,
        None => return Err("DOGE address not found in mapping".to_string()),
    };

    // Verify the caller's balance
    EVM_STATE.with(|state| {
        let mut state_mut = state.borrow_mut();
        if let Some(balance) = state_mut.balances.get_mut(&caller_evm_address) {
            if *balance < amount {
                return Err("Insufficient DOGE balance".to_string());
            }
            *balance -= amount; // Deduct the withdrawal amount
        } else {
            return Err("Caller balance not found".to_string());
        }
    });

    // Send DOGE to the recipient's wallet
    let node_url = EVM_STATE.with(|state| state.borrow().doge_node_url.clone());
    let tx_hex = create_doge_transaction(&recipient_doge_address, amount, &node_url).await?;
    let tx_id = broadcast_doge_transaction(&tx_hex, &node_url).await?;

    // Store the transaction in MongoDB
    store_transaction(&tx_id, &caller_doge_address, &recipient_doge_address, amount).await?;

    Ok(format!("Withdrawn {} DOGE to {}", amount, recipient_doge_address))
}

#[update]
async fn batch_withdraw_doge(transactions: Vec<(String, String, U256, Vec<u8>)>) -> Result<Vec<String>, String> {
    let mut handles = vec![];

    for (caller_doge_address, recipient_doge_address, amount, signature) in transactions {
        let handle = task::spawn(async move {
            withdraw_doge(caller_doge_address, recipient_doge_address, amount, signature).await
        });
        handles.push(handle);
    }

    let mut results = vec![];
    for handle in handles {
        results.push(handle.await.unwrap()?);
    }

    Ok(results)
}

#[query]
async fn get_transaction_history(sender: String) -> Result<Vec<(String, String, U256)>, String> {
    get_transaction_history(&sender).await
}

#[update]
async fn prune_old_transactions() -> Result<String, String> {
    let client = connect_to_mongodb().await?;
    let db = client.database("runtime");
    let collection = db.collection("transactions");

    let filter = doc! { "timestamp": { "$lt": chrono::Utc::now() - chrono::Duration::days(30) } };
    collection
        .delete_many(filter, None)
        .await
        .map_err(|e| e.to_string())?;

    Ok("Old transactions pruned".to_string())
}

async fn connect_to_mongodb() -> Result<MongoClient, String> {
    let client_options = ClientOptions::parse("mongodb://localhost:27017")
        .await
        .map_err(|e| e.to_string())?;

    let client = MongoClient::with_options(client_options).map_err(|e| e.to_string())?;

    // Verify the connection
    client
        .database("admin")
        .run_command(doc! { "ping": 1 }, None)
        .await
        .map_err(|e| e.to_string())?;

    Ok(client)
}

async fn store_transaction(tx_id: &str, sender: &str, recipient: &str, amount: U256) -> Result<(), String> {
    let client = connect_to_mongodb().await?;
    let db = client.database("runtime");
    let collection = db.collection("transactions");

    let doc = doc! {
        "tx_id": tx_id,
        "sender": sender,
        "recipient": recipient,
        "amount": amount.to_string(),
        "timestamp": chrono::Utc::now(),
    };

    collection
        .insert_one(doc, None)
        .await
        .map_err(|e| e.to_string())?;

    Ok(())
}

async fn get_transaction_history(sender: &str) -> Result<Vec<(String, String, U256)>, String> {
    let client = connect_to_mongodb().await?;
    let db = client.database("runtime");
    let collection = db.collection("transactions");

    let filter = doc! { "sender": sender };
    let cursor = collection
        .find(filter, None)
        .await
        .map_err(|e| e.to_string())?;

    let mut transactions = vec![];
    for result in cursor {
        let doc = result.map_err(|e| e.to_string())?;
        let tx_id = doc.get_str("tx_id").map_err(|e| e.to_string())?.to_string();
        let recipient = doc.get_str("recipient").map_err(|e| e.to_string())?.to_string();
        let amount = U256::from_dec_str(doc.get_str("amount").map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        transactions.push((tx_id, recipient, amount));
    }

    Ok(transactions)
}

fn verify_signature(doge_address: &str, message_hash: &[u8], signature: &[u8]) -> bool {
    let secp = Secp256k1::new();
    let message = Message::from_slice(message_hash).expect("Invalid message hash");

    let recoverable_signature = match RecoverableSignature::from_compact(signature) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    let public_key = match recoverable_signature.recover(&message) {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    let derived_doge_address = match derive_doge_address(&public_key.serialize_uncompressed()) {
        Ok(addr) => addr,
        Err(_) => return false,
    };

    derived_doge_address == doge_address
}

fn derive_doge_address(public_key: &[u8]) -> Result<String, String> {
    if public_key.len() != 65 || public_key[0] != 0x04 {
        return Err("Invalid public key format".to_string());
    }

    let mut sha256 = Sha256::new();
    sha256.update(public_key);
    let sha256_hash = sha256.finalize();

    let mut ripemd160 = Ripemd160::new();
    ripemd160.update(sha256_hash);
    let public_key_hash = ripemd160.finalize();

    let version_byte: u8 = 0x1E;
    let mut payload = Vec::new();
    payload.push(version_byte);
    payload.extend_from_slice(&public_key_hash);

    let mut sha256_checksum = Sha256::new();
    sha256_checksum.update(&payload);
    let first_hash = sha256_checksum.finalize();

    let mut sha256_checksum = Sha256::new();
    sha256_checksum.update(first_hash);
    let checksum = sha256_checksum.finalize();

    let checksum_bytes = &checksum[..4];

    let mut address_bytes = payload.clone();
    address_bytes.extend_from_slice(checksum_bytes);

    let doge_address = address_bytes.to_base58();

    Ok(doge_address)
}

async fn create_doge_transaction(recipient: &str, amount: U256, node_url: &str) -> Result<String, String> {
    let client = Client::new();
    let request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        method: "createrawtransaction".to_string(),
        params: vec![
            serde_json::Value::Array(vec![]),
            serde_json::Value::Object({
                let mut map = serde_json::Map::new();
                map.insert(recipient.to_string(), serde_json::Value::String(amount.to_string()));
                map
            }),
        ],
        id: 1,
    };

    let response = client
        .post(node_url)
        .json(&request)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let response: JsonRpcResponse<String> = response
        .json()
        .await
        .map_err(|e| e.to_string())?;

    Ok(response.result)
}

async fn broadcast_doge_transaction(tx_hex: &str, node_url: &str) -> Result<String, String> {
    let client = Client::new();
    let request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        method: "sendrawtransaction".to_string(),
        params: vec![serde_json::Value::String(tx_hex.to_string())],
        id: 1,
    };

    let response = client
        .post(node_url)
        .json(&request)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let response: JsonRpcResponse<String> = response
        .json()
        .await
        .map_err(|e| e.to_string())?;

    Ok(response.result)
}

#[derive(Serialize, Deserialize, Debug)]
struct JsonRpcRequest {
    jsonrpc: String,
    method: String,
    params: Vec<serde_json::Value>,
    id: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct JsonRpcResponse<T> {
    result: T,
    error: Option<serde_json::Value>,
    id: u64,
}