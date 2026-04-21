# 🛡️ SmartSAST v2.3 - Colab Optimized with Full RAG Integration

![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)
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
###Step 1: Open the Notebook

###Step 2: Save a Copy
In Colab: File → Save a copy in Drive

###Step 3: Configure Paths (Optional)
At the top of the notebook, adjust paths according to your structure:

```bash
output_filepath = "/content/gdrive/MyDrive/"           # Where reports will be saved
rag_folder      = "/content/gdrive/MyDrive/CWE-top25"   # Folder with RAG dataset
INTERIM_SAVE_PATH = "/content/gdrive/MyDrive/.smart_sast_interim"  # Temporary saves
```
###Step 4: Run the Notebook
- Execute cells in order. The system will:
- Mount your Google Drive automatically
- Install required dependencies
- Download the quantized LLM model (~1GB)
- Prompt you for the file/directory path to analyze

###Step 5: Analyze Your Code
Enter the path to a file or directory in Google Drive:
```bash
➡️  Enter a Google Drive file or directory path (or 'q' to quit): 
/content/gdrive/MyDrive/my_project/vulnerable.py
```
###Step 6: Review Results
Reports will be saved to your output_filepath:
```bash
📁 /content/gdrive/MyDrive/
├── 20260421120000-smart_sast_2_0_5-final-cuda-RAG-vulnerable.py.json  ← Clean report
└── 20260421120000-smart_sast_2_0_5-all-cuda-RAG-vulnerable.py.json    ← All findings
```



## 🛠️ Requisitos Previos

### Entorno Recomendado
- ✅ **Google Colab** (Free/Pro/Pro+) con GPU o TPU
- ✅ Conexión a Internet para descargar modelos y dependencias
- ✅ Cuenta de Google Drive con espacio disponible

### Dataset RAG (Opcional pero Recomendado)
```bash
# Descargar el dataset CWE-top25
# URL: https://github.com/NLPSaST/SmartSast/raw/main/CWE-top25-20250705T164339Z-1-001.zip





------------------------------------------------------------------------------------
# SmartSast: AI-Powered SAST for Local, Private Code Scanning
[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/drive/1FLn_i1Ln23pR7Sr25mafutaicASZa6LE?usp=sharing)
SmartSast is an innovative Static Application Security Testing (SAST) tool that uses **Large Language Models (LLMs)** to identify security vulnerabilities directly in your source code. Designed for privacy and ease of use, SmartSast provides **accurate, AI-driven analysis without sending your code to external servers.**

## What does the project do?
SmartSast is a **Static Application Security Testing (SAST) tool** built with Python and powered by **Large Language Models (LLMs)**. It analyzes your source code to detect potential security vulnerabilities, identifying risks based on **CWE (Common Weakness Enumeration) patterns.**. Using AI to provide **smarter and more accurate** results than traditional static scanners.

## Why is the project useful?
Unlike many SAST tools that run in the cloud or rely on static rules, SmartSast uses LLMs locally in Google Colab, giving developers and students a private, flexible, and AI-powered way to scan their code. It’s ideal for learning, testing, or working in secure environments where sending code to external servers is not an option. There's no need for complex setup or API keys — just open the Colab notebook and run it.

Traditional SAST tools often require complex setups, rely on fixed rule sets, or process your code on external servers. SmartSast offers a refreshing alternative:

+ **Privacy-First Scanning:** Run LLM-powered analysis directly in Google Colab, keeping your sensitive code secure and private.

+ **No Complex Setup:** Forget about installations, API keys, or lengthy configurations. Just open the Colab notebook and start scanning.

+ **AI-Powered Accuracy:** Leverage the intelligence of LLMs to detect vulnerabilities with greater precision than static, rule-based scanners.

+ **Ideal for Learning & Development:** Perfect for students, developers, and security enthusiasts looking to learn about SAST or integrate robust security checks into their local workflows.

## Features
+ **LLM-Powered Analysis:** Utilizes Large Language Models for intelligent vulnerability detection.

+ **CWE-Based Identification:** Maps identified vulnerabilities to Common Weakness Enumeration (CWE) patterns.

+ **Local Execution in Google Colab:** Ensures code privacy by running entirely within your Colab environment.

+ **Multi-Language Support:** (List the supported languages here, e.g., Python, Java, JavaScript, C++).

+ **JSON Output:** Provides structured vulnerability analysis in a standard format.

+ **Sample Code Included:** Get started quickly with example files in the \sample/` folder.

+ **No Installation or API Keys Required:** Streamlined setup for immediate use.

+ **RAG Dataset Integration (Recommended):** Enhances accuracy with a Retrieval Augmented Generation dataset (note on GPU/TPU usage).


## Quick Start: Using SmartSast in Google Colab
Getting started with SmartSast is straightforward. No installation or API keys are required! Simply open the Colab notebook and follow these steps:

**Ready to start? Click the badge below!**
[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/drive/1FLn_i1Ln23pR7Sr25mafutaicASZa6LE?usp=sharing)

https://github.com/user-attachments/assets/f5be83c2-f83e-4c6c-bf01-0f30d6cbabc2

1.  **Open the Notebook:** Click the "Open in Colab" badge above or at the top of this page.
2.  Save a Copy: In Colab, go to File > Save a copy in Drive to create your editable version.
3.  Prepare Your Data (Optional, but Recommended for Accuracy):
* Upload your RAR zip file (presumably containing the RAG dataset) to your Google Drive.(**latest version: CWE-top25-20250705T164339Z-1-001.zip**)
* Unzip this file to a specific folder in your Google Drive. This will be your `RAG_FOLDER` path.
4.  Configure Paths: At the beginning of the Colab notebook, define two paths:
* RAG_FOLDER: The path to the folder where you unzipped your RAG dataset.
* OUTPUT_FOLDER: The folder where the vulnerability analysis (.json) file will be saved.
5.  Run the Code: Execute the cells in the Colab notebook and follow any on-screen instructions. You can use the provided code samples in the sample/ folder to test it out.
6.  Review Results: Examine the detailed vulnerability analysis generated in your specified OUTPUT_FOLDER.

> **Pro Tip:** For optimal code accuracy and performance, it's highly recommended to use the RAG dataset and leverage Google Colab's GPU/TPU resources.

**Report**
```json
{
    "file_info": {
        "date": "20250820025121",
        "file_name": "test",
        "file_extension": ".java",
        "path_file": "/home/examples",
        "analysis duration": 765.55,
        "risk_level [in progress]": "Critical",
        "cwss_average [in progress]": 89.0
    },
    "cleaned_vulnerabilities": [
        {
            "Vulnerability_name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
            "CWE": "CWE-89",
            "CWSS": 89.0,
            "Description": "The product constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component. Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.",
            "Vulnerable_code": "String query = \"insert into users (status) values ('updated') where name='\" + data + \"'\";",
            "lines_range": "[88, 65]",
            "Solution": "Use parameterized queries or prepared statements to prevent SQL injection. For example:\nString query = \"insert into users (status) values ('updated') where name=?\";\nPreparedStatement ps = dbConnection.prepareStatement(query);\nps.setString(1, data);",
            "text1": "        String data = goodSource_SQL(); // Use good source to demonstrate good practice\n        try (Connection dbConnection = IO.getDBConnection();\n             Statement sqlStatement = dbConnection.createStatement()) {\n            String query = \"insert into users (status) values ('updated') where name='\" + data + \"'\";\n            sqlStatement.execute(query); // Safe usage as data is hardcoded\n        } catch (SQLException exceptSql) {\n            IO.logger.log(Level.WARNING, \"Database error\", exceptSql);",
            "text2": "        String data = badSource_SQL();\n        try (Connection dbConnection = IO.getDBConnection();\n             Statement sqlStatement = dbConnection.createStatement()) {\n            String query = \"insert into users (status) values ('updated') where name='\" + data + \"'\";\n            sqlStatement.execute(query); // POTENTIAL FLAW: SQL Injection\n        } catch (SQLException exceptSql) {\n            IO.logger.log(Level.WARNING, \"Database error\", exceptSql);"
        }
    ],
    "stats": {
        "total_vulnerabilities": 1,
        "unique_cwe_ids": 1,
        "exact_duplicates": 0,
        "name_duplicates": 0,
        "clean_vulnerabilities_count": 1
    },
    "exact_duplicates": {},
    "name_duplicates": {}
}
```
**Next Step**
* Add a way to identify code progress
* LLM performance measurement
  * Improve performace
  * Improve RAG database
* CWSS/Risk measurement

# Where can users get help?

❓ You can open an issue on GitHub

📖 Documentation and a wiki are planned

💬 Discord (link coming soon)

📧 Email (coming soon)


