#!/usr/bin/env python3
import sys
import os
import json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from phoenix.core.setup import PhoenixSetup

if __name__ == "__main__":
    print("running phoenix key generation...")
    setup = PhoenixSetup()
    state = setup.setup()
    print("setup complete.")
    print(f"bfv poly modulus degree: {state['bfv_context'].poly_modulus_degree()}")