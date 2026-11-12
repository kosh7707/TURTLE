"""현재 실험 프로필을 만드는 시험 보조 함수입니다."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from profile_config import experiment_profile, flatten_experiment
