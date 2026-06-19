"""
Configuration partagée pour la suite de tests ChocoScan.

Ajoute la racine du projet au sys.path pour que `from modules.xxx import ...`
fonctionne quel que soit le répertoire depuis lequel pytest est lancé.
"""

import sys
from pathlib import Path

# Permet `import modules.xxx` depuis tests/ sans installer le package
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
