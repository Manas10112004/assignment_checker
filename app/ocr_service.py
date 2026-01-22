import pytesseract
from PIL import Image, ImageEnhance, ImageFilter
import io


def preprocess_image(image):
    """
    Cleans up the image to make handwriting easier to read.
    """
    # 1. Convert to Grayscale (removes color noise)
    image = image.convert('L')

    # 2. Increase Contrast (makes ink darker, paper whiter)
    enhancer = ImageEnhance.Contrast(image)
    image = enhancer.enhance(2.0)

    # 3. Sharpen (makes edges of letters crisp)
    image = image.filter(ImageFilter.SHARPEN)

    return image


def extract_text_local(image_bytes):
    """
    The main engine function. Takes raw bytes, returns string.
    """
    try:
        # Load image from memory
        image = Image.open(io.BytesIO(image_bytes))

        # Clean it up
        clean_image = preprocess_image(image)

        # Run Tesseract OCR
        # config='--psm 6' assumes a block of text
        text = pytesseract.image_to_string(clean_image, config='--psm 6')

        return text.strip()
    except Exception as e:
        print(f"OCR Engine Error: {e}")
        return ""