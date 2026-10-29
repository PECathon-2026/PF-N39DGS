import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.detect import regex_layer, dom_layer, ocr_layer, face_layer, fusion

print("Ablation script placeholder: run per-scenario recall with layers disabled.")
PY