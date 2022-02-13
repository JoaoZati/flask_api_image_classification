import tensorflow as tf
import numpy as np
from tensorflow.keras.applications.imagenet_utils import decode_predictions
from PIL import Image

from io import BytesIO

model = None

def load_model():
    model = tf.keras.applications.MobileNetV2(weights="imagenet")
    print("Model loaded")
    return model

def predict(file_path: str):
    global model
    if model is None:
        model = load_model()

    image = Image.open(file_path)

    image = np.asarray(image.resize((224, 224)))[..., :3]
    image = np.expand_dims(image, 0)
    image = image / 127.5 - 1.0

    result = decode_predictions(model.predict(image), 2)[0]

    response = {}
    for i, res in enumerate(result):
        resp = {}
        resp["class"] = res[1]
        resp["confidence"] = f"{res[2]*100:0.2f} %"

        response[i] = resp

    return response


def read_imagefile(file_path) -> Image.Image:
    image = Image.open(file_path)
    return image
