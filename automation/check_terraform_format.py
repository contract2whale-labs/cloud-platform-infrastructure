#!/usr/bin/env python3
import subprocess
from pathlib import Path

if __name__=='__main__':
 root=Path(__file__).resolve().parents[1]
 for directory in ['terraform','modules']:
  if (root/directory).exists():subprocess.run(['terraform','fmt','-check','-recursive',directory],cwd=root,check=True)
