# ml_deepfake/test_image.py
import sys
from models import get_image_pipeline

pipe = get_image_pipeline()
result = pipe(sys.argv[1])
print(result)