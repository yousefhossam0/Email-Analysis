"""
SOC Mail Spoof & Phishing Analysis Tool - Legacy Wrapper
=========================================================
This file now serves as a wrapper directing execution to the new,
highly modular and comprehensive SOC Email Forensic Analyzer (`main.py`).
"""
import sys
import os

# Add directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import main

if __name__ == "__main__":
    main.main()