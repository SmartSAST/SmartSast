# 🛡️ SmartSAST v2.3 - Colab Optimized with Full RAG Integration
![Open In Colab]([https://colab.research.google.com/assets/colab-badge.svg])(https://colab.research.google.com/drive/1FLn_i1Ln23pR7Sr25mafutaicASZa6LE?usp=sharing)
![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)

> **Version:** 2.3 (Hardened) | **Last Updated:** April 2026

**SmartSAST** is an innovative *Static Application Security Testing* (SAST) tool that leverages **Large Language Models (LLMs)** to identify security vulnerabilities directly in your source code. Designed for privacy and ease of use, SmartSAST delivers AI-powered precise analysis **without sending your code to external servers**.

---

## 🚀 What's New in Version 2.3

| Feature | Description | Benefit |
|---------|-------------|---------|
| 🔍 **Optimized RAG** | On-demand loading + semantic expansion of related CWEs | Lower memory usage, higher contextual precision |
| 📊 **Live Progress Reporting** | Real-time progress bars with statistics | Better UX and monitoring during analysis |
| 🧹 **Memory Management** | Configurable automatic GPU/RAM cleanup | Prevents disconnections on Colab Free Tier |
| ⚡ **Colab Optimizations** | Skip unnecessary analysis, AST caching, quantized models | Up to 3x faster on resource-limited environments |
| 🔄 **Progressive Saving** | Auto-save every X seconds during analysis | Protects your work against unexpected disconnections |
| 🎯 **Smart Pre-filtering** | Semantic pre-filtering based on code patterns | Reduces unnecessary LLM calls |

---

## 📋 What Does SmartSAST Do?

SmartSAST is a Python-based SAST tool that:

1. 🔎 **Scans code** with Semgrep for initial rule-based findings
2. 🧠 **Verifies with LLM** each finding to reduce false positives
3. 🔗 **Analyzes taint flows** (intra and inter-procedural) to detect injection vulnerabilities
4. 🎯 **Performs semantic analysis** to find business logic vulnerabilities
5. 🧩 **Merges results** with AST verification for maximum precision
6. 📄 **Generates structured JSON reports** with CWE, CWSS, and remediation guidance

---

## 🛠️ Prerequisites

### Recommended Environment
- ✅ **Google Colab** (Free/Pro/Pro+) with GPU or TPU
- ✅ Internet connection for downloading models and dependencies
- ✅ Google Drive account with available storage

### RAG Dataset (Optional but Recommended)
```bash
# Download the CWE-top25 dataset
# URL: https://github.com/NLPSaST/SmartSast/raw/main/CWE-top25-20250705T164339Z-1-001.zip
```

## 🚀 How to Use SmartSAST in Google Colab
### Step 1: Open the Notebook

### Step 2: Save a Copy
In Colab: File → Save a copy in Drive

### Step 3: Configure Paths (Optional)
At the top of the notebook, adjust paths according to your structure:

```bash
output_filepath = "/content/gdrive/MyDrive/"           # Where reports will be saved
rag_folder      = "/content/gdrive/MyDrive/CWE-top25"   # Folder with RAG dataset
INTERIM_SAVE_PATH = "/content/gdrive/MyDrive/.smart_sast_interim"  # Temporary saves
```
### Step 4: Run the Notebook
- Execute cells in order. The system will:
- Mount your Google Drive automatically
- Install required dependencies
- Download the quantized LLM model (~1GB)
- Prompt you for the file/directory path to analyze

### Step 5: Analyze Your Code
Enter the path to a file or directory in Google Drive:
```bash
➡️  Enter a Google Drive file or directory path (or 'q' to quit): 
/content/gdrive/MyDrive/my_project/vulnerable.py
```
### Step 6: Review Results
Reports will be saved to your output_filepath:
```bash
📁 /content/gdrive/MyDrive/
├── 20260421120000-smart_sast_2_0_5-final-cuda-RAG-vulnerable.py.json  ← Clean report
└── 20260421120000-smart_sast_2_0_5-all-cuda-RAG-vulnerable.py.json    ← All findings
```
## 📊 Output Report Structure
Final Report (*-final-*.json)
```bash
{
  "file_info": {
    "date": "20260421120000",
    "file_name": "vulnerable",
    "file_extension": ".py",
    "path_file": "/content/gdrive/MyDrive/my_project",
    "analysis duration": 342.15,
    "risk_level [in progress]": "High",
    "cwss_average [in progress]": 7.2
  },
  "cleaned_vulnerabilities": [
    {
      "CWE": "CWE-89",
      "CWSS": 8.5,
      "lines_range": [45],
      "Description": "SQL injection vulnerability detected...",
      "Solution": "Use parameterized queries...",
      "found_by": "semgrep + llm",
      "ast_passed": true
    }
  ],
  "stats": {
    "total_vulnerabilities": 3,
    "unique_cwe_ids": 2,
    "clean_vulnerabilities_count": 2
  }
}
```
### Full Report (*-all-*.json)
Includes all intermediate findings: verified, alternative, rejected, taint flows, and semantic analysis results.

## ⚙️ Configuration Parameters - Complete Reference

📁 Paths and Storage

|Parameter|Type|Default Value|Function|
|---|---|---|---|
|output_filepath|str|"/content/gdrive/MyDrive/"|Base directory in Google Drive where final JSON reports will be saved|
|rag_folder|str|"/content/gdrive/MyDrive/CWE-top25"|Path to the folder containing CWE JSON files for RAG|
|INTERIM_SAVE_PATH|str|"/content/gdrive/MyDrive/.smart_sast_interim"|Directory for progressive saves during analysis (protects against disconnections)|

🎯 LLM Confidence Thresholds

|Parameter|Type|Default Value|Function|
|---|---|---|---|
|SEMGREP_VERIFY_THRESHOLD|int|70|Minimum confidence percentage the LLM must report to confirm a Semgrep finding as a true positive|
|SEMANTIC_CONFIRM_THRESHOLD|int|70|Minimum confidence percentage for a semantic analysis finding to be included in the final report|

🔗 Taint Analysis Configuration

|Parameter|Type|Default Value|Function|
|---|---|---|---|
|TAINT_MAX_HOPS|int|5|Maximum depth for inter-procedural taint flow analysis (how many "hops" between functions to trace)|
|SEMANTIC_PREFILTER_ENABLED|bool|True|Enables smart pre-filtering that skips semantic analysis on code chunks without relevant patterns|

🧹 Google Colab Optimizations

|Parameter|Type|Default Value|Function|
|---|---|---|---|
|ENABLE_MEMORY_CLEANUP|bool|True|Enables automatic memory cleanup (GC + GPU cache) to prevent OOM on Colab Free Tier|
|MEMORY_CLEANUP_INTERVAL|int|5|How many processed chunks trigger a memory cleanup cycle|
|USE_QUANTIZED_MODEL|bool|True|Uses the Q4_K_M quantized model (~1GB) instead of Q8_0 (~2GB); faster with minimal precision loss|
|SKIP_SEMANTIC_FOR_SMALL_FILES|bool|True|Skips semantic analysis (more expensive) on files with few lines if no prior findings exist|
|SMALL_FILE_THRESHOLD|int|500|Line count below which a file is considered "small" for the above optimizations
|SKIP_TAINT_IF_NO_INPUT|bool|True|Skips taint analysis if no user input sources are detected (input(), request.args, etc.)|
|ENABLE_AST_CACHE|bool|True|Enables caching of parsed AST trees to avoid re-processing the same code|
|_AST_CACHE_MAX_SIZE|int|10|Maximum number of AST trees to keep in cache (LRU eviction)|

💾 Progressive Saving and Recovery

|Parameter|Type|Default Value|Function|
|---|---|---|---|
|ENABLE_INTERIM_SAVE|bool|True|Enables automatic partial progress saving every X seconds|
|INTERIM_SAVE_INTERVAL|int|180|Interval in seconds between progressive saves (recommended: 180s for Colab Free)|

📚 RAG (Retrieval Augmented Generation) Optimizations

|Parameter|Type|Default Value|Function|
|---|---|---|---|
|LOAD_RAG_ON_DEMAND|bool|True|Loads only relevant CWE files (found by Semgrep + related) instead of the entire dataset|
|RAG_EXPANSION_RADIUS|int|1|How many levels of "related CWEs" to include beyond directly found ones (0 = exact only, 1 = +direct relatives)|

📡 Reporting and Processing

|Parameter|Type|Default Value|Function|
|---|---|---|---|
|ENABLE_LIVE_REPORTING|bool|True|Displays progress bars and real-time statistics during execution|
|ENABLE_PARALLEL_CHUNKS|bool|False|Processes code chunks in parallel (⚠️ disabled by default to avoid saturation on Colab Free)|
|MAX_LLM_WORKERS|int|2|Maximum concurrent workers for LLM inference (adjust based on available VRAM)|

----------------------------------------------------
**Next Step v.2.4**
* SARIF format output

# Where can users get help?

❓ You can open an issue on GitHub

📖 Documentation and a wiki are planned

💬 Discord (link coming soon)

📧 Email (coming soon)


