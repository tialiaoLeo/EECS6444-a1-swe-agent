# EECS6444-A1 SWE-Agent

## 🧠 Overview
This project explores using **Large Language Model (LLM) agents** to autonomously resolve real-world software bugs from GitHub repositories, as part of the **EECS 6444: Mining Software Engineering Data** course at York University.

We replicate and extend the **[SWE-Agent](https://github.com/SWE-agent/SWE-agent)** system on a subset of the **SWE-Bench** dataset, integrating it with **Claude Sonnet 4** in a local environment.  
The goal is to evaluate how well agentic workflows can understand issue descriptions, edit code, and validate fixes through automated testing.

---

## Benchmark result
- **Baseline:** https://github.com/tialiaoLeo/EECS6444-a1-swe-agent/tree/master/tianpei/base_line 
- **Extension result:** https://github.com/tialiaoLeo/EECS6444-a1-swe-agent/tree/master/tianpei/middle_ware_result2 
---

## 🚀 Project Goals
- **Replication:** Reproduce SWE-Agent’s performance on selected SWE-Bench tasks.  
- **Extension:** Enhance SWE-Agent with additional middleware to analyze runtime and import errors during execution and feed them back to the model.  
- **Evaluation:** Compare baseline vs. modified agent in task-level success rate, safety signals, and runtime consistency.

---

## 🧩 System Architecture
The system follows an agentic **“Think → Act → Validate → Commit”** workflow:

1. **Thought** — The LLM interprets the issue and plans the next step.  
2. **Action** — Executes a tool (read, write, run tests) to apply the plan with middleware enhancement 
3. **Validation** — Runs unit tests from SWE-Bench to check correctness.  
4. **Commit** — Persists the fix if validation passes.

Our **middleware layer** injects real-time SWE test feedback into the LLM’s reasoning loop for better contextual understanding.

---

## ⚙️ Local Setup

### 1. Clone the repository
```bash
git clone https://github.com/tialiaoLeo/EECS6444-a1-swe-agent.git
cd EECS6444-a1-swe-agent
