# AI-Enhanced Threshold Signature System

This is an AI-powered version of the CGGMP21 threshold signature system where **Coordinator** and **Signer** nodes are enhanced with intelligent agents using Ollama for decision-making and natural language communication.

## Key Enhancements

- **AI-Powered Decision Making**: Agents use Ollama to reason about protocol operations
- **Natural Language Communication**: Agents log operations and decisions in human-readable format
- **Context Awareness**: Agents maintain memory of protocol states and past decisions
- **Security Intelligence**: AI reasoning about cryptographic operations and trust decisions
- **Enhanced Monitoring**: Agent status, memory, and decision history endpoints

## Prerequisites

1. **Python 3.8+** with required packages:
   ```bash
   pip install flask requests ecdsa aiohttp asyncio
   ```

2. **Ollama** running locally:
   ```bash
   # Install Ollama (https://ollama.ai)
   # Pull a lightweight model
   ollama pull llama3.2:1b
   
   # Verify Ollama is running on localhost:11434
   curl http://localhost:11434/api/generate
   ```

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   AI Coordinator Agent                       │
│              (coordinator_agent.py)                         │
│   • Orchestrates DKG and Signing protocols                  │
│   • AI reasoning for protocol decisions                     │
│   • Natural language logging and analysis                   │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  │ REST API Communication
                  │
┌─────────────────▼───────────────────────────────────────────┐
│              AI Signer Agents                               │
│           (signer_agent.py x3)                              │
│   • Individual MPC parties with AI capabilities             │
│   • Intelligent share verification and trust scoring        │
│   • Context-aware protocol participation                    │
│   • Memory of past protocol interactions                    │
└─────────────────────────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────┐
│                 Ollama AI Engine                            │
│              (localhost:11434)                              │
│   • Natural language reasoning                              │
│   • Decision support for crypto operations                  │
│   • Security assessment and recommendations                 │
└─────────────────────────────────────────────────────────────┘
```

## Setup and Testing

### 1. Start Ollama Service

```bash
# Ensure Ollama is running
ollama serve

# In another terminal, verify the model is available
ollama list
# Should show llama3.2:1b (or download it with: ollama pull llama3.2:1b)
```

### 2. Start the AI Signer Agents

Launch three AI-enhanced signer agents in separate terminals:

#### Terminal 1: AI Signer Agent 1 (Port 5001)
```bash
python signer_agent.py \
    --party_id 1 \
    --port 5001 \
    --num_parties 3 \
    --threshold 2 \
    --party_addresses "1:localhost:5001" "2:localhost:5002" "3:localhost:5003"
```

#### Terminal 2: AI Signer Agent 2 (Port 5002)
```bash
python signer_agent.py \
    --party_id 2 \
    --port 5002 \
    --num_parties 3 \
    --threshold 2 \
    --party_addresses "1:localhost:5001" "2:localhost:5002" "3:localhost:5003"
```

#### Terminal 3: AI Signer Agent 3 (Port 5003)
```bash
python signer_agent.py \
    --party_id 3 \
    --port 5003 \
    --num_parties 3 \
    --threshold 2 \
    --party_addresses "1:localhost:5001" "2:localhost:5002" "3:localhost:5003"
```

### 3. Start the AI Coordinator Agent

#### Terminal 4: AI Coordinator Agent (Port 6000)
```bash
python coordinator_agent.py
```

You should see enhanced logging with AI reasoning for each agent.

### 4. Testing Terminal

Use Terminal 5 for running the test commands.

---

## Testing the AI-Enhanced Protocol

The AI agents maintain the same REST API as the original system but add intelligent reasoning and enhanced logging.

### Phase 1: AI-Powered Distributed Key Generation (DKG)

The Coordinator Agent will use AI to reason about each step of the DKG process:

```bash
curl -X POST http://localhost:6000/dkg/start
```

#### Expected Enhanced Output
```json
{
  "status": "success",
  "message": "DKG OK",
  "aggregated_public_key": {
    "x": "0x...",
    "y": "0x..."
  },
  "ai_reasoning": "DKG completed successfully with all parties generating consistent cryptographic commitments. The threshold scheme ensures no single party can reconstruct the private key."
}
```

**Watch the AI reasoning in the terminal logs:**
- Coordinator Agent will reason about protocol initiation
- Signer Agents will assess trust and security of received shares
- Enhanced logging with natural language explanations

### Phase 2: AI-Enhanced Threshold Signing

The AI agents will reason about signature security and trust:

```bash
# Prepare message hash
echo -n "test message" | sha256sum | awk '{print $1}'
# Output: 3f0a377ba0a4a460ecb616f6507ce0d8cfa3e704025d4fda3ed0c5ca05468728

# Request signature with AI analysis
curl -X POST -H "Content-Type: application/json" \
     -d '{
         "message_hash_hex": "3f0a377ba0a4a460ecb616f6507ce0d8cfa3e704025d4fda3ed0c5ca05468728",
         "signing_party_ids": [1, 3]
     }' \
     http://localhost:6000/request-signature
```

#### Expected Enhanced Output
```json
{
  "status": "success",
  "signature": {
    "r": "0x...",
    "s": "0x..."
  },
  "ai_analysis": "Threshold signature completed successfully. Nonce aggregation and final share computation proceeded securely with proper cryptographic verification."
}
```

## AI Agent Monitoring

### Agent Status Endpoints

Check the AI state and reasoning of any agent:

```bash
# Coordinator Agent status
curl http://localhost:6000/agent/status

# Signer Agent status (example for agent 1)
curl http://localhost:5001/agent/status
```

**Sample Agent Status:**
```json
{
  "agent_id": "signer_agent_1",
  "party_id": 1,
  "protocol_state": "idle",
  "current_operation": null,
  "has_private_key_share": true,
  "memory_events": 15,
  "trust_scores": {
    "1": 1.0,
    "2": 1.0, 
    "3": 1.0
  },
  "recent_decisions": [
    {
      "timestamp": 1703123456.789,
      "situation": "Verifying secret share from party 2",
      "reasoning": "Share verification using commitment scheme is cryptographically sound. Proceeding with storage."
    }
  ]
}
```

### Agent Memory Endpoints

View the AI agent's memory and decision history:

```bash
# Coordinator memory
curl http://localhost:6000/agent/memory

# Signer memory (sensitive information is redacted)
curl http://localhost:5001/agent/memory
```

### Trust Scores

Signer agents maintain trust scores for other parties:

```bash
curl http://localhost:5001/agent/trust
```

```json
{
  "agent_id": "signer_agent_1",
  "party_id": 1,
  "trust_scores": {
    "1": 1.0,
    "2": 0.85,  // Slightly reduced trust due to minor protocol timing
    "3": 1.0
  },
  "decision_history_count": 8
}
```

## AI Reasoning Examples

### DKG Phase AI Reasoning

**Coordinator Agent:**
```
[INFO] [Coordinator Agent] AI Reasoning: Starting DKG with 3 parties using threshold-2 scheme. This ensures any 2 parties can sign while maintaining security against single-party compromise.
```

**Signer Agent:**
```
[INFO] [Signer Agent 1] AI Decision: Generating degree-1 polynomial for threshold scheme. Proceeding with cryptographically secure random coefficients.
[INFO] [Signer Agent 1] AI Security Assessment: Share verification using commitment scheme is mathematically sound. Trust maintained in party 2.
```

### Signing Phase AI Reasoning

**Coordinator Agent:**
```
[INFO] [Coordinator Agent] AI Reasoning: Initiating threshold signature with parties [1,3]. Both parties have verified key shares and can securely participate.
[INFO] [Coordinator Agent] AI Analysis: Signature verification successful. r and s values are cryptographically valid for the aggregated public key.
```

**Signer Agent:**
```
[INFO] [Signer Agent 1] AI Nonce Security Assessment: Generating cryptographically secure nonce using system randomness. Critical for signature uniqueness and security.
[INFO] [Signer Agent 1] AI Final Share Assessment: Computing Lagrange-weighted shares for threshold reconstruction. Safe to provide final shares to complete signature.
```

## AI Features

### 1. **Intelligent Decision Making**
- AI evaluates each protocol step for security and correctness
- Reasoning about trust levels and party behavior
- Natural language explanations of cryptographic operations

### 2. **Enhanced Security Monitoring**
- Trust scoring system for other parties
- Memory of past interactions and protocol violations
- AI-powered assessment of signature and verification operations

### 3. **Context Awareness**
- Agents remember protocol history and past decisions
- Contextual understanding of current protocol state
- Adaptive behavior based on previous interactions

### 4. **Natural Language Communication**
- Human-readable logs and decision explanations
- AI-generated summaries of protocol completion
- Technical explanations accessible to non-experts

## Security Considerations

### AI Safety Features

1. **Cryptographic Operations Unchanged**: All core MPC cryptography remains identical to the original implementation
2. **Sensitive Data Protection**: Private keys and shares are never sent to AI models
3. **Trust Score Isolation**: Trust scoring doesn't affect cryptographic security
4. **AI Reasoning Isolation**: AI failures don't compromise protocol execution

### What AI Does vs. Doesn't Do

**AI DOES:**
- ✅ Provide reasoning about protocol participation
- ✅ Generate natural language logs and explanations  
- ✅ Assess trust levels and party behavior
- ✅ Summarize protocol completion status

**AI DOES NOT:**
- ❌ Generate or handle private keys or shares
- ❌ Modify cryptographic operations
- ❌ Make security-critical decisions
- ❌ Access sensitive cryptographic material

## Troubleshooting

### Ollama Connection Issues
```bash
# Check if Ollama is running
curl http://localhost:11434/api/tags

# If not running, start it
ollama serve
```

### AI Reasoning Failures
The agents will fall back to standard protocol operation if AI reasoning fails:
```
[INFO] [Signer Agent 1] AI reasoning unavailable, following standard protocol
```

### Performance Considerations
- AI reasoning adds ~200-500ms per decision
- Use `llama3.2:1b` for fastest response times
- Larger models provide richer reasoning but slower response

## Stopping the System

Stop all agents by pressing `Ctrl+C` in each terminal (Terminals 1-4), then stop Ollama if desired.

---

## Comparison with Original System

| Feature | Original System | AI-Enhanced System |
|---------|----------------|-------------------|
| **Protocol Security** | CGGMP21 threshold ECDSA | ✅ Identical (unchanged) |
| **Communication** | REST API | ✅ Identical + AI status endpoints |
| **Logging** | Technical logs | ✅ Enhanced with AI reasoning |
| **Decision Making** | Deterministic | ✅ AI-assisted with fallbacks |
| **Monitoring** | Basic status | ✅ Enhanced with agent memory/trust |
| **Natural Language** | None | ✅ Human-readable explanations |

The AI enhancement preserves all security properties while adding intelligent monitoring and natural language understanding of the threshold signature protocol.
