import sys
import os
import json
from typing import List
from model import Chonk

from llm_openai import ProcessUpload_openai, openai_init
from llm_gemini import ProcessUpload_gemini, gemini_init


PROMPT = r"""
Objective:
Extract and structure the procedures used by the threat actor in the provided CTI report. The focus should be on command lines, executed programs, tools, and attack techniques, enabling a red team to emulate the attack. Do not include IOCs such as IP addresses, domains, or file hashes.

Instructions:

    Identify command-line executions, including CLI syntax, parameters, and options used by the threat actor.
    Extract executed programs and tools used for reconnaissance, privilege escalation, lateral movement, persistence, or impact.
    Preserve the sequence and context of actions where possible to maintain logical attack flow.
    Exclude passive indicators (IOCs) such as file hashes, domain names, or IP addresses—focus only on tactics, techniques, and procedures (TTPs).
    If the CTI report lacks explicit command lines, infer likely commands based on described behavior and known attack methodologies.
    Structure the output in a clear format to facilitate red team emulation.

Example Output Format:

## Phase: Initial Access
- **Technique:** Phishing via Malicious Document  
- **Procedure:** The attacker sends a spear-phishing email containing a malicious Word document with VBA macros.  

## Phase: Execution
- **Technique:** PowerShell Execution  
- **Command:** `powershell -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -EncodedCommand <Base64 Payload>`  

## Phase: Persistence
- **Technique:** Scheduled Task for Persistence  
- **Command:** `schtasks /create /tn "Updater" /tr "C:\Users\Public\update.bat" /sc daily /st 12:00`  

## Phase: Lateral Movement
- **Technique:** Remote Service Execution (PsExec)  
- **Command:** `psexec \\target -u admin -p password cmd.exe /c C:\temp\payload.exe`  

## Phase: Credential Dumping
- **Technique:** Mimikatz Usage  
- **Command:** `mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit`  
"""


def init():
    openai_init()
    gemini_init() 


def ProcessUpload(filename: str, details: bool):
    print("Processing file:", filename)
    print("  OpenAI...")
    ProcessUpload_openai(filename, PROMPT, details=details)
    print("  Gemini 2.0...")
    ProcessUpload_gemini(filename, PROMPT, type="gemini20")
    print("  Gemini 2.5...")
    ProcessUpload_gemini(filename, PROMPT, type="gemini25")
    print("Processing complete.")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python ttpextractor.py <filename> openai/gemini")
        print("  <filename> needs to exist in input/")
        sys.exit(1)

    type = sys.argv[2].lower()
    if type == "openai":
        print("Using OpenAI for processing")
        ProcessUpload_openai(sys.argv[1], PROMPT, details=True)
    elif type == "gemini20":
        print("Using Gemini 2.0 for processing")
        ProcessUpload_gemini(sys.argv[1], PROMPT, type="gemini20")
    elif type == "gemini25":
        print("Using Gemini 2.5 for processing")
        ProcessUpload_gemini(sys.argv[1], PROMPT, type="gemini25")
    elif type == "all":
        print("Using OpenAI and Gemini2.0 & 2.5 for processing")
        ProcessUpload(sys.argv[1], details=True)
