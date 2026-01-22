import os
import json
import base64
from groq import Groq


def get_groq_client():
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key: return None
    return Groq(api_key=api_key)


# --- 1. VISION ENGINE (Uses Llama 4 Scout) ---
def extract_text_from_image(image_bytes):
    client = get_groq_client()
    if not client: return ""

    # Encode image to base64
    base64_image = base64.b64encode(image_bytes).decode('utf-8')

    try:
        completion = client.chat.completions.create(
            messages=[
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "Transcribe the text in this image exactly. Do not add commentary."},
                        {
                            "type": "image_url",
                            "image_url": {
                                # Llama 4 standard format
                                "url": f"data:image/jpeg;base64,{base64_image}"
                            }
                        }
                    ]
                }
            ],
            # FAST MODEL for Vision
            model="meta-llama/llama-4-scout-17b-16e-instruct",
        )
        return completion.choices[0].message.content
    except Exception as e:
        print(f"Vision Error: {e}")
        return ""


# --- 2. REASONING ENGINE (Uses Llama 4 Maverick) ---
def generate_answer_key(question_text):
    client = get_groq_client()
    if not client: return "Error: Server AI is not configured."
    prompt = f"Solve and create an Answer Key for:\n{question_text}"
    try:
        completion = client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            # SMART MODEL for Logic
            model="meta-llama/llama-4-maverick-17b-128e-instruct",
        )
        return completion.choices[0].message.content
    except Exception as e:
        return f"Error: {str(e)}"


def compute_score(student_text, answer_key):
    client = get_groq_client()
    if not client: return 0, {"Error": "AI unavailable"}

    if not student_text or not student_text.strip():
        return 0, {"Error": "Empty text. Could not read file."}

    prompt = f"""
    Compare Student Answer to Answer Key.
    Key: {answer_key}
    Student: {student_text}
    Return STRICT JSON: {{"score": 0-100, "feedback": {{"Accuracy": "...", "Clarity": "..."}}}}
    """
    try:
        completion = client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            # SMART MODEL for Grading
            model="meta-llama/llama-4-maverick-17b-128e-instruct",
            response_format={"type": "json_object"}
        )
        data = json.loads(completion.choices[0].message.content)
        return data.get("score", 0), data.get("feedback", {})
    except:
        return 0, {"Error": "Grading failed"}