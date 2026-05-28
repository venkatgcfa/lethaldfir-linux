#!/usr/bin/env python3
"""
===============================================================================
 LethalDFIR Linux Forensics — Standalone Runner
===============================================================================

 Run directly without pip install:

   python3 run.py -i /var/log -o ./output
   python3 run.py -i /mnt/evidence -o ./output --case-name web01
   python3 run.py -i Collection.zip -o ./output
   sudo python3 run.py -i / -o ./output --case-name myhost

 This is equivalent to:

   python3 -m lethaldfir_linux -i /var/log -o ./output

 For full installation (creates the 'lethaldfir-linux' command):

   pip install -e .
   lethaldfir-linux -i /var/log -o ./output
===============================================================================
"""

import sys
import os

# Ensure the package directory is on the Python path so imports work
# even when running from outside the project directory.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lethaldfir_linux.cli import main

if __name__ == "__main__":
    main()
