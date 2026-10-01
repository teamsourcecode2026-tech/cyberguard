# ml_deepfake/models.py
import torch
from transformers import pipeline

_DEVICE = 0 if torch.cuda.is_available() else -1  # transformers pipeline convention: 0=GPU, -1=CPU

_image_pipe = None
_audio_pipe = None

def get_image_pipeline():
    """Lazily load and cache the ViT deepfake-image classifier."""
    global _image_pipe
    if _image_pipe is None:
        _image_pipe = pipeline(
            task="image-classification",
           model="dima806/deepfake_vs_real_image_detection",
            device=_DEVICE,
        )
    return _image_pipe

def get_audio_pipeline():
    """Lazily load and cache the Wav2Vec2 deepfake-audio classifier."""
    global _audio_pipe
    if _audio_pipe is None:
        _audio_pipe = pipeline(
            task="audio-classification",
            model="mo-thecreator/Deepfake-audio-detection",
            device=_DEVICE,
        )
    return _audio_pipe