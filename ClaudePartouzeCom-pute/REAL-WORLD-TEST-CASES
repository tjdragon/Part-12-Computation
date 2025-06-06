This document provides comprehensive test scenarios for the CryptoVault MPC system, covering enterprise, DeFi, gaming, and other real-world use cases. Each test case shows both **CLI commands** and **equivalent API calls**.

## 🏢 Corporate & Enterprise Scenarios

### 1. Startup Multi-Sig Treasury (2-of-3)

**Business Context**: A tech startup with three founders who need dual approval for significant expenses.

#### Create Startup Treasury Wallet

**CLI Command:**
```bash
python mpc_system.py create-wallet \
  --parties "founder_ceo,founder_cto,founder_coo" \
  --threshold 2
```

**Equivalent API Call:**
```bash
curl -X POST "http://localhost:8000/wallets" \
  -H "Authorization: Bearer demo_token" \
  -H "Content-Type: application/json" \
  -d '{
    "parties": ["founder_ceo", "founder_cto", "founder_coo"],
    "threshold": 2,
    "name": "startup_treasury"
  }'
```

**Expected Response:**
```json
{
  "key_id": "startup_abc123",
  "public_key": "02d5231e817436ddf1d3...",
  "threshold": 2,
  "parties": 3
}
```

#### Normal Business Expense (AWS Payment)

**CLI Command:**
```bash
python mpc_system.py sign \
  --key-id "startup_abc123" \
  --asset bitcoin \
  --to-address "btc_aws_hosting_payment" \
  --amount 2500000 \
  --participants "founder_ceo,founder_cto"
```

**Equivalent API Call:**
```bash
curl -X POST "http://localhost:8000/wallets/startup_abc123/sign" \
  -H "Authorization: Bearer demo_token" \
  -H "Content-Type: application/json" \
  -d '{
    "asset_type": "bitcoin",
    "to_address": "btc_aws_hosting_payment",
    "amount": 2500000,
    "participants": ["founder_ceo", "founder_cto"]
  }'
```

**Expected Result**: ✅ **SUCCESS** - Normal business expense within policy limits

#### Large Strategic Investment (Should Fail - Policy Violation)

**CLI Command:**
```bash
python mpc_system.py sign \
  --key-id "startup_abc123" \
  --asset bitcoin \
  --to-address "btc_acquisition_target" \
  --amount 50000000 \
  --participants "founder_ceo,founder_cto"
```

**Equivalent API Call:**
```bash
curl -X POST "http://localhost:8000/wallets/startup_abc123/sign" \
  -H "Authorization: Bearer demo_token" \
  -H "Content-Type: application/json" \
  -d '{
    "asset_type": "bitcoin",
    "to_address": "btc_acquisition_target", 
    "amount": 50000000,
    "participants": ["founder_ceo", "founder_cto"]
  }'
```

**Expected Result**: ❌ **POLICY VIOLATION** - Amount exceeds 0.1 BTC limit

#### Insufficient Signers (Should Fail - Threshold Violation)

**CLI Command:**
```bash
python mpc_system.py sign \
  --key-id "startup_abc123" \
  --asset bitcoin \
  --to-address "btc_emergency_payment" \
  --amount 1000000 \
  --participants "founder_ceo"
```

**Equivalent API Call:**
```bash
curl -X POST "http://localhost:8000/wallets/startup_abc123/sign" \
  -H "Authorization: Bearer demo_token" \
  -H "Content-Type: application/json" \
  -d '{
    "asset_type": "bitcoin",
    "to_address": "btc_emergency_payment",
    "amount": 1000000,
    "participants": ["founder_ceo"]
  }'
```

**Expected Result**: ❌ **INSUFFICIENT PARTICIPANTS** - Need 2 signatures, only 1 provided

---

### 2. Fortune 500 Board Approval (4-of-7)

**Business Context**: Large corporation requiring board-level approval for major transactions.

#### Create Board Treasury Wallet

**CLI Command:**
```bash
python mpc_system.py create-wallet \
  --parties "ceo,cfo,board_chair,audit_committee,risk_officer,general_counsel,chief_investment" \
  --threshold 4
```

**Equivalent API Call:**
```bash
curl -X POST "http://localhost:8000/wallets" \
  -H "Authorization: Bearer demo_token" \
  -H "Content-Type: application/json" \
  -d '{
    "parties": ["ceo", "cfo", "board_chair", "audit_committee", "risk_officer", "general_counsel", "chief_investment"],
    "threshold": 4,
    "name": "board_treasury"
  }'
```

#### Quarterly Dividend Payment (Ethereum)

**CLI Command:**
```bash
python mpc_system.py sign \
  --key-id "board_def456" \
  --asset ethereum \
  --to-address "0xdividend_distribution_contract" \
  --amount 50000000000000000000 \
  --participants "ceo,cfo,board_chair,chief_investment"
```

**Equivalent API Call:**
```bash
curl -X POST "http://localhost:8000/wallets/board_def456/sign" \
  -H "Authorization: Bearer demo_token" \
  -H "Content-Type: application/json" \
  -d '{
    "asset_type": "ethereum",
    "to_address": "0xdividend_distribution_contract",
    "amount": 50000000000000000000,
    "participants": ["ceo", "cfo", "board_chair", "chief_investment"]
  }'
```

**Expected Result**: ✅ **SUCCESS** - 50 ETH dividend payment with proper board approval

---

### 3. Department Budget Control (2-of-4)

**Business Context**: Cross-department shared resources requiring dual approval.

#### Create Shared Services Budget

**CLI Command:**
```bash
python mpc_system.py create-wallet \
  --parties "engineering_head,marketing_head,sales_head,operations_head" \
  --threshold 2
```

**Equivalent API Call:**
```bash
curl -X POST "http://localhost:8000/wallets" \
  -H "Authorization: Bearer demo_token" \
  -H "Content-Type: application/json" \
  -d '{
    "parties": ["engineering_head", "marketing_head", "sales_head", "operations_head"],
    "threshold": 2,
    "name": "shared_services_budget"
  }'
```

#### Conference Sponsorship Payment

**CLI Command:**
```bash
python mpc_system.py sign \
  --key-id "dept_ghi789" \
  --asset bitcoin \
  --to-address "btc_devcon_sponsorship" \
  --amount 5000000 \
  --participants "engineering_head,marketing_head"
```

**Equivalent API Call:**
```bash
curl -X POST "http://localhost:8000/wallets/dept_ghi789/sign" \
  -H "Authorization: Bearer demo_token" \
  -H "Content-Type: application/json" \
  -d '{
    "asset_type": "bitcoin",
    "to_address": "btc_devcon_sponsorship",
    "amount": 5000000,
    "participants": ["engineering_head", "marketing_head"]
  }'
```

**Expected Result**: ✅ **SUCCESS** - 0.05 BTC conference sponsorship

---

## 🏦 Financial Services & Banking

### 4. Investment Fund Management (3-of-5)

**Business Context**: Crypto hedge fund requiring investment committee approval.

#### Create Investment Fund Wallet

**CLI Command:**
```bash
python mpc_system.py create-wallet \
  --parties "fund_manager,risk_analyst,compliance_officer,portfolio_manager,senior_partner" \
  --threshold 3
```

**Equivalent API Call:**
```bash
curl -X POST "http://localhost:8000/wallets" \
  -H "Authorization: Bearer demo_token" \
  -H "Content-Type: application/json" \
  -d '{
    "parties": ["fund_manager", "risk_analyst", "compliance_officer", "portfolio_manager", "senior_partner"],
    "threshold": 3,
    "name": "crypto_hedge_fund"
  }'
```

#### DeFi Yield Farming Allocation

**CLI Command:**
```bash
python mpc_system.py sign \
  --key-id "fund_jkl012" \
  --asset ethereum \
  --to-address "0xcompound_usdc_pool" \
  --amount 25000000000000000000 \
  --participants "fund_manager,risk_analyst,portfolio_manager"
```

**Equivalent API Call:**
```bash
curl -X POST "http://localhost:8000/wallets/fund_jkl012/sign" \
  -H "Authorization: Bearer demo_token" \
  -H "Content-Type: application/json" \
  -d '{
    "asset_type": "ethereum",
    "to_address": "0xcompound_usdc_pool",
    "amount": 25000000000000000000,
    "participants": ["fund_manager", "risk_analyst", "portfolio_manager"]
  }'
```

**Expected Result**: ✅ **SUCCESS** - 25 ETH DeFi allocation

---

### 5. Bank Digital Asset Custody (5-of-9)

**Business Context**: Institutional bank with high-security custody requirements.

#### Create Institutional Custody Wallet

**CLI Command:**
```bash
python mpc_system.py create-wallet \
  --parties "custody_officer,vault_manager,compliance_head,risk_manager,ops_manager,security_officer,backup_key_1,backup_key_2,emergency_key" \
  --threshold 5
```

**Equivalent API Call:**
```bash
curl -X POST "http://localhost:8000/wallets" \
  -H "Authorization: Bearer demo_token" \
  -H "Content-Type: application/json" \
  -d '{
    "parties": ["custody_officer", "vault_manager", "compliance_head", "risk_manager", "ops_manager", "security_officer", "backup_key_1", "backup_key_2", "emergency_key"],
    "threshold": 5,
    "name": "institutional_custody"
  }'
```

#### Client Withdrawal Request

**CLI Command:**
```bash
python mpc_system.py sign \
  --key-id "bank_mno345" \
  --asset bitcoin \
  --to-address "btc_client_cold_storage" \
  --amount 8000000 \
  --participants "custody_officer,vault_manager,compliance_head,risk_manager,ops_manager"
```

**Equivalent API Call:**
```bash
curl -X POST "http://localhost:8000/wallets/bank_mno345/sign" \
  -H "Authorization: Bearer demo_token" \
  -H "Content-Type: application/json" \
  -d '{
    "asset_type": "bitcoin",
    "to_address": "btc_client_cold_storage",
    "amount": 8000000,
    "participants": ["custody_officer", "vault_manager", "compliance_head", "risk_manager", "ops_manager"]
  }'
```

**Expected Result**: ✅ **SUCCESS** - 0.08 BTC client withdrawal

---

## 🚀 DeFi & Protocol Management

### 6. DAO Treasury Management (7-of-12)

**Business Context**: Decentralized autonomous organization with community governance.

#### Create DAO Community Treasury

**CLI Command:**
```bash
python mpc_system.py create-wallet \
  --parties "core_dev_1,core_dev_2,community_lead,partnership_lead,security_auditor,economics_lead,governance_facilitator,legal_counsel,marketing_lead,ops_lead,treasury_committee,emergency_multisig" \
  --threshold 7
```

**Equivalent API Call:**
```bash
curl -X POST "http://localhost:8000/wallets" \
  -H "Authorization: Bearer demo_token" \
  -H "Content-Type: application/json" \
  -d '{
    "parties": ["core_dev_1", "core_dev_2", "community_lead", "partnership_lead", "security_auditor", "economics_lead", "governance_facilitator", "legal_counsel", "marketing_lead", "ops_lead", "treasury_committee", "emergency_multisig"],
    "threshold": 7,
    "name": "dao_community_treasury"
  }'
```

#### Protocol Upgrade Funding

**CLI Command:**
```bash
python mpc_system.py sign \
  --key-id "dao_pqr678" \
  --asset ethereum \
  --to-address "0xprotocol_development_fund" \
  --amount 100000000000000000000 \
  --participants "core_dev_1,core_dev_2,community_lead,partnership_lead,security_auditor,economics_lead,governance_facilitator"
```

**Equivalent API Call:**
```bash
curl -X POST "http://localhost:8000/wallets/dao_pqr678/sign" \
  -H "Authorization: Bearer demo_token" \
  -H "Content-Type: application/json" \
  -d '{
    "asset_type": "ethereum",
    "to_address": "0xprotocol_development_fund",
    "amount": 100000000000000000000,
    "participants": ["core_dev_1", "core_dev_2", "community_lead", "partnership_lead", "security_auditor", "economics_lead", "governance_facilitator"]
  }'
```

**Expected Result**: ✅ **SUCCESS** - 100 ETH protocol development funding

---

### 7. AMM Liquidity Management (2-of-3)

**Business Context**: Automated Market Maker liquidity providers.

#### Create Liquidity Provider Vault

**CLI Command:**
```bash
python mpc_system.py create-wallet \
  --parties "primary_lp,secondary_lp,strategy_manager" \
  --threshold 2
```

**Equivalent API Call:**
```bash
curl -X POST "http://localhost:8000/wallets" \
  -H "Authorization: Bearer demo_token" \
  -H "Content-Type: application/json" \
  -d '{
    "parties": ["primary_lp", "secondary_lp", "strategy_manager"],
    "threshold": 2,
    "name": "amm_liquidity_vault"
  }'
```

#### Add Liquidity to Uniswap

**CLI Command:**
```bash
python mpc_system.py sign \
  --key-id "amm_stu901" \
  --asset ethereum \
  --to-address "0xuniswap_v3_pool_manager" \
  --amount 10000000000000000000 \
  --participants "primary_lp,strategy_manager"
```

**Equivalent API Call:**
```bash
curl -X POST "http://localhost:8000/wallets/amm_stu901/sign" \
  -H "Authorization: Bearer demo_token" \
  -H "Content-Type: application/json" \
  -d '{
    "asset_type": "ethereum",
    "to_address": "0xuniswap_v3_pool_manager",
    "amount": 10000000000000000000,
    "participants": ["primary_lp", "strategy_manager"]
  }'
```

**Expected Result**: ✅ **SUCCESS** - 10 ETH liquidity provision

---

### 8. Cross-Chain Bridge Operations (4-of-6)

**Business Context**: Cross-chain bridge requiring validator consensus.

#### Create Bridge Validator Set

**CLI Command:**
```bash
python mpc_system.py create-wallet \
  --parties "validator_1,validator_2,validator_3,validator_4,validator_5,validator_6" \
  --threshold 4
```

**Equivalent API Call:**
```bash
curl -X POST "http://localhost:8000/wallets" \
  -H "Authorization: Bearer demo_token" \
  -H "Content-Type: application/json" \
  -d '{
    "parties": ["validator_1", "validator_2", "validator_3", "validator_4", "validator_5", "validator_6"],
    "threshold": 4,
    "name": "bridge_validator_set"
  }'
```

#### Cross-Chain Transfer Release

**CLI Command:**
```bash
python mpc_system.py sign \
  --key-id "bridge_vwx234" \
  --asset bitcoin \
  --to-address "btc_user_destination" \
  --amount 3500000 \
  --participants "validator_1,validator_2,validator_3,validator_4"
```

**Equivalent API Call:**
```bash
curl -X POST "http://localhost:8000/wallets/bridge_vwx234/sign" \
  -H "Authorization: Bearer demo_token" \
  -H "Content-Type: application/json" \
  -d '{
    "asset_type": "bitcoin",
    "to_address": "btc_user_destination",
    "amount": 3500000,
    "participants": ["validator_1", "validator_2", "validator_3", "validator_4"]
  }'
```

**Expected Result**: ✅ **SUCCESS** - 0.035 BTC cross-chain release

---

## 💎 Gaming & NFT Scenarios

### 9. Gaming Guild Treasury (3-of-5)

**Business Context**: Gaming guild managing shared assets and NFT investments.

#### Create Gaming Guild Wallet

**CLI Command:**
```bash
python mpc_system.py create-wallet \
  --parties "guild_master,strategy_lead,treasury_manager,community_manager,partnership_lead" \
  --threshold 3
```

**Equivalent API Call:**
```bash
curl -X POST "http://localhost:8000/wallets" \
  -H "Authorization: Bearer demo_token" \
  -H "Content-Type: application/json" \
  -d '{
    "parties": ["guild_master", "strategy_lead", "treasury_manager", "community_manager", "partnership_lead"],
    "threshold": 3,
    "name": "gaming_guild_treasury"
  }'
```

#### NFT Marketplace Purchase

**CLI Command:**
```bash
python mpc_system.py sign \
  --key-id "guild_yza567" \
  --asset ethereum \
  --to-address "0xopensea_marketplace" \
  --amount 5000000000000000000 \
  --participants "guild_master,strategy_lead,treasury_manager"
```

**Equivalent API Call:**
```bash
curl -X POST "http://localhost:8000/wallets/guild_yza567/sign" \
  -H "Authorization: Bearer demo_token" \
  -H "Content-Type: application/json" \
  -d '{
    "asset_type": "ethereum",
    "to_address": "0xopensea_marketplace",
    "amount": 5000000000000000000,
    "participants": ["guild_master", "strategy_lead", "treasury_manager"]
  }'
```

**Expected Result**: ✅ **SUCCESS** - 5 ETH NFT purchase

---

### 10. Metaverse Land Development (2-of-3)

**Business Context**: Metaverse development partnership for virtual real estate.

#### Create Development Partnership

**CLI Command:**
```bash
python mpc_system.py create-wallet \
  --parties "dev_studio,land_investor,creative_director" \
  --threshold 2
```

**Equivalent API Call:**
```bash
curl -X POST "http://localhost:8000/wallets" \
  -H "Authorization: Bearer demo_token" \
  -H "Content-Type: application/json" \
  -d '{
    "parties": ["dev_studio", "land_investor", "creative_director"],
    "threshold": 2,
    "name": "metaverse_development"
  }'
```

#### Virtual Real Estate Purchase

**CLI Command:**
```bash
python mpc_system.py sign \
  --key-id "meta_bcd890" \
  --asset ethereum \
  --to-address "0xdecentraland_estate" \
  --amount 20000000000000000000 \
  --participants "dev_studio,land_investor"
```

**Equivalent API Call:**
```bash
curl -X POST "http://localhost:8000/wallets/meta_bcd890/sign" \
  -H "Authorization: Bearer demo_token" \
  -H "Content-Type: application/json" \
  -d '{
    "asset_type": "ethereum",
    "to_address": "0xdecentraland_estate",
    "amount": 20000000000000000000,
    "participants": ["dev_studio", "land_investor"]
  }'
```

**Expected Result**: ✅ **SUCCESS** - 20 ETH metaverse land purchase

---

## 🤝 Partnership & Joint Ventures

### 11. Equal Technology Partnership (1-of-2)

**Business Context**: Two companies with equal partnership where either can act independently.

#### Create Technology Partnership

**CLI Command:**
```bash
python mpc_system.py create-wallet \
  --parties "tech_company_a,tech_company_b" \
  --threshold 1
```

**Equivalent API Call:**
```bash
curl -X POST "http://localhost:8000/wallets" \
  -H "Authorization: Bearer demo_token" \
  -H "Content-Type: application/json" \
  -d '{
    "parties": ["tech_company_a", "tech_company_b"],
    "threshold": 1,
    "name": "tech_partnership_operational"
  }'
```

#### Joint Marketing Campaign

**CLI Command:**
```bash
python mpc_system.py sign \
  --key-id "partner_efg123" \
  --asset bitcoin \
  --to-address "btc_marketing_agency" \
  --amount 1500000 \
  --participants "tech_company_a"
```

**Equivalent API Call:**
```bash
curl -X POST "http://localhost:8000/wallets/partner_efg123/sign" \
  -H "Authorization: Bearer demo_token" \
  -H "Content-Type: application/json" \
  -d '{
    "asset_type": "bitcoin",
    "to_address": "btc_marketing_agency",
    "amount": 1500000,
    "participants": ["tech_company_a"]
  }'
```

**Expected Result**: ✅ **SUCCESS** - 0.015 BTC marketing payment (single party can act)

---

### 12. Real Estate Investment Syndicate (6-of-10)

**Business Context**: Real estate investment group requiring majority approval.

#### Create Real Estate Syndicate

**CLI Command:**
```bash
python mpc_system.py create-wallet \
  --parties "investor_1,investor_2,investor_3,investor_4,investor_5,investor_6,investor_7,investor_8,property_manager,legal_representative" \
  --threshold 6
```

**Equivalent API Call:**
```bash
curl -X POST "http://localhost:8000/wallets" \
  -H "Authorization: Bearer demo_token" \
  -H "Content-Type: application/json" \
  -d '{
    "parties": ["investor_1", "investor_2", "investor_3", "investor_4", "investor_5", "investor_6", "investor_7", "investor_8", "property_manager", "legal_representative"],
    "threshold": 6,
    "name": "real_estate_syndicate"
  }'
```

#### Property Down Payment (Should Fail - Policy Violation)

**CLI Command:**
```bash
python mpc_system.py sign \
  --key-id "realestate_hij456" \
  --asset ethereum \
  --to-address "0xreal_estate_tokenization" \
  --amount 500000000000000000000 \
  --participants "investor_1,investor_2,investor_3,investor_4,investor_5,property_manager"
```

**Equivalent API Call:**
```bash
curl -X POST "http://localhost:8000/wallets/realestate_hij456/sign" \
  -H "Authorization: Bearer demo_token" \
  -H "Content-Type: application/json" \
  -d '{
    "asset_type": "ethereum",
    "to_address": "0xreal_estate_tokenization",
    "amount": 500000000000000000000,
    "participants": ["investor_1", "investor_2", "investor_3", "investor_4", "investor_5", "property_manager"]
  }'
```

**Expected Result**: ❌ **POLICY VIOLATION** - 500 ETH exceeds 100 ETH limit

---

## 🌐 Exchange & Trading

### 13. Crypto Exchange Hot Wallet (3-of-5)

**Business Context**: Cryptocurrency exchange operational wallet for customer withdrawals.

#### Create Exchange Hot Wallet

**CLI Command:**
```bash
python mpc_system.py create-wallet \
  --parties "server_instance_1,server_instance_2,server_instance_3,manual_operator,emergency_key" \
  --threshold 3
```

**Equivalent API Call:**
```bash
curl -X POST "http://localhost:8000/wallets" \
  -H "Authorization: Bearer demo_token" \
  -H "Content-Type: application/json" \
  -d '{
    "parties": ["server_instance_1", "server_instance_2", "server_instance_3", "manual_operator", "emergency_key"],
    "threshold": 3,
    "name": "exchange_hot_wallet"
  }'
```

#### Customer Withdrawal Processing

**CLI Command:**
```bash
python mpc_system.py sign \
  --key-id "exchange_klm789" \
  --asset bitcoin \
  --to-address "btc_customer_wallet" \
  --amount 750000 \
  --participants "server_instance_1,server_instance_2,manual_operator"
```

**Equivalent API Call:**
```bash
curl -X POST "http://localhost:8000/wallets/exchange_klm789/sign" \
  -H "Authorization: Bearer demo_token" \
  -H "Content-Type: application/json" \
  -d '{
    "asset_type": "bitcoin",
    "to_address": "btc_customer_wallet",
    "amount": 750000,
    "participants": ["server_instance_1", "server_instance_2", "manual_operator"]
  }'
```

**Expected Result**: ✅ **SUCCESS** - 0.0075 BTC customer withdrawal

---

### 14. Market Making Operation (2-of-3)

**Business Context**: Algorithmic trading with manual risk manager override.

#### Create Market Making Vault

**CLI Command:**
```bash
python mpc_system.py create-wallet \
  --parties "trading_algo_1,trading_algo_2,risk_manager" \
  --threshold 2
```

**Equivalent API Call:**
```bash
curl -X POST "http://localhost:8000/wallets" \
  -H "Authorization: Bearer demo_token" \
  -H "Content-Type: application/json" \
  -d '{
    "parties": ["trading_algo_1", "trading_algo_2", "risk_manager"],
    "threshold": 2,
    "name": "market_making_vault"
  }'
```

#### Arbitrage Opportunity Execution

**CLI Command:**
```bash
python mpc_system.py sign \
  --key-id "trading_nop012" \
  --asset ethereum \
  --to-address "0xdex_arbitrage_contract" \
  --amount 30000000000000000000 \
  --participants "trading_algo_1,risk_manager"
```

**Equivalent API Call:**
```bash
curl -X POST "http://localhost:8000/wallets/trading_nop012/sign" \
  -H "Authorization: Bearer demo_token" \
  -H "Content-Type: application/json" \
  -d '{
    "asset_type": "ethereum",
    "to_address": "0xdex_arbitrage_contract",
    "amount": 30000000000000000000,
    "participants": ["trading_algo_1", "risk_manager"]
  }'
```

**Expected Result**: ✅ **SUCCESS** - 30 ETH arbitrage trade

---

## 🛡️ Security & Emergency Scenarios

### 15. Emergency Fund Release (7-of-10)

**Business Context**: Corporate emergency fund for disaster recovery.

#### Create Emergency Fund

**CLI Command:**
```bash
python mpc_system.py create-wallet \
  --parties "ceo,cfo,cto,board_chair,legal_counsel,hr_director,ops_director,security_officer,emergency_contact_1,emergency_contact_2" \
  --threshold 7
```

**Equivalent API Call:**
```bash
curl -X POST "http://localhost:8000/wallets" \
  -H "Authorization: Bearer demo_token" \
  -H "Content-Type: application/json" \
  -d '{
    "parties": ["ceo", "cfo", "cto", "board_chair", "legal_counsel", "hr_director", "ops_director", "security_officer", "emergency_contact_1", "emergency_contact_2"],
    "threshold": 7,
    "name": "emergency_fund"
  }'
```

#### Employee Relief Distribution (Should Fail - Policy Violation)

**CLI Command:**
```bash
python mpc_system.py sign \
  --key-id "emergency_qrs345" \
  --asset ethereum \
  --to-address "0xemployee_relief_distribution" \
  --amount 200000000000000000000 \
  --participants "ceo,cfo,cto,board_chair,legal_counsel,hr_director,ops_director"
```

**Equivalent API Call:**
```bash
curl -X POST "http://localhost:8000/wallets/emergency_qrs345/sign" \
  -H "Authorization: Bearer demo_token" \
  -H "Content-Type: application/json" \
  -d '{
    "asset_type": "ethereum",
    "to_address": "0xemployee_relief_distribution",
    "amount": 200000000000000000000,
    "participants": ["ceo", "cfo", "cto", "board_chair", "legal_counsel", "hr_director", "ops_director"]
  }'
```

**Expected Result**: ❌ **POLICY VIOLATION** - 200 ETH exceeds 100 ETH limit

---

## 📊 Wallet Management & Analytics

### 16. Wallet Information Retrieval

#### List All Wallets

**CLI Command:**
```bash
python mpc_system.py list-wallets
```

**Equivalent API Call:**
```bash
curl -X GET "http://localhost:8000/wallets" \
  -H "Authorization: Bearer demo_token"
```

**Expected Response:**
```json
[
  {
    "key_id": "startup_abc123",
    "public_key": "02d5231e817436ddf1d3...",
    "threshold": 2,
    "parties": 3,
    "created_at": "2025-06-06T17:02:46.359000"
  },
  {
    "key_id": "board_def456", 
    "public_key": "03a8b7c6d5e4f3g2h1i0...",
    "threshold": 4,
    "parties": 7,
    "created_at": "2025-06-06T17:05:12.123000"
  }
]
```

#### Get Specific Wallet Information

**CLI Command:**
```bash
# No direct CLI equivalent - use API
```

**API Call:**
```bash
curl -X GET "http://localhost:8000/wallets/startup_abc123" \
  -H "Authorization: Bearer demo_token"
```

**Expected Response:**
```json
{
  "key_id": "startup_abc123",
  "public_key": "02d5231e817436ddf1d3...",
  "addresses": {
    "bitcoin": "btc_00304c22893d75e3c3c5b39bab8d170d68bb7338",
    "ethereum": "0xda9fdc7cc7849394bcc331c9e8a736763424c12f"
  }
}
```

#### Check Supported Assets

**CLI Command:**
```bash
# No direct CLI equivalent - use API
```

**API Call:**
```bash
curl -X GET "http://localhost:8000/assets" \
  -H "Authorization: Bearer demo_token"
```

**Expected Response:**
```json
{
  "assets": ["bitcoin", "ethereum"]
}
```

#### Health Check

**CLI Command:**
```bash
# No CLI equivalent - API only
```

**API Call:**
```bash
curl http://localhost:8000/health
```

**Expected Response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-06-06T17:15:23.527023"
}
```

---

## 🎯 Testing Strategy

### Test Categories

1. **✅ Happy Path Tests**: Normal operations with correct thresholds and amounts
2. **❌ Security Boundary Tests**: Policy violations and insufficient signatures
3. **🔄 Edge Case Tests**: Exactly at thresholds, maximum policy amounts
4. **💰 Multi-Asset Tests**: Both Bitcoin and Ethereum transactions
5. **📈 Scale Tests**: Various threshold configurations (1-of-2 to 7-of-12)

### Expected Results Summary

| Scenario | Expected Result | Reason |
|----------|----------------|---------|
| Startup AWS Payment (0.025 BTC) | ✅ SUCCESS | Within limits, proper threshold |
| Startup Acquisition (0.5 BTC) | ❌ POLICY VIOLATION | Exceeds 0.1 BTC limit |
| Startup Single Signer | ❌ THRESHOLD VIOLATION | Need 2 signatures, got 1 |
| Board Dividend (50 ETH) | ✅ SUCCESS | Within limits, proper threshold |
| Emergency Relief (200 ETH) | ❌ POLICY VIOLATION | Exceeds 100 ETH limit |
| Gaming NFT Purchase (5 ETH) | ✅ SUCCESS | Within limits, proper threshold |
| Exchange Withdrawal (0.0075 BTC) | ✅ SUCCESS | Normal operational transaction |

### Testing Commands

**Run all test scenarios:**
```bash
# Start server
python mpc_system.py server

# In separate terminal, run each scenario above
# Monitor logs for policy enforcement and signature validation
```

**Monitor server logs for:**
- Policy evaluation results
- Threshold enforcement
- Signature generation
- Error handling

This comprehensive test suite demonstrates the MPC system's ability to handle real-world enterprise scenarios while maintaining security through threshold cryptography and policy enforcement! 🚀
