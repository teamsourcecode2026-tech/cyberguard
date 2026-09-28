import sys
from models import get_audio_pipeline

pipe = get_audio_pipeline()
result = pipe(sys.argv[1])
print(result)