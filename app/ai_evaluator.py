import os
import json
from groq import Groq
# Import our new local engine
from app.ocr_service import extract_text_local


def get_groq_client():
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key: return None
    return Groq(api_key=api_key)


def generate_answer_key(question_text):
    client = get_groq_client()
    if not client: return "Error: Server AI is not configured."
    prompt = f"Solve and create an Answer Key for:\n{question_text}"
    try:
        completion = client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model="llama-3.3-70b-versatile",
        )
        return completion.choices[0].message.content
    except Exception as e:
        return f"Error: {str(e)}"


def compute_score(student_input, answer_key, is_image=False):
    """
    Grading Logic:
    1. If input is an image, use Local OCR to get text.
    2. If input is text, use it directly.
    3. Send TEXT to Llama 3 for grading.
    """
    client = get_groq_client()
    if not client: return 0, {"Error": "AI unavailable"}

    student_text = ""

    if is_image:
        # --- THE FIX: USE LOCAL OCR ---
        print("Using Local OCR Engine...")
        student_text = extract_text_local(student_input)
        if not student_text.strip():
            return 0, {"Error": "OCR failed. Could not read handwriting."}
    else:
        student_text = student_input

    # Now we just grade the text (No Rate Limits!)
    prompt = f"""
    Compare Student Answer to Answer Key.
    Key: {answer_key}
    Student: {student_text}
    Return STRICT JSON: {{"score": 0-100, "feedback": {{"Accuracy": "...", "Clarity": "..."}}}}
    """
    try:
        completion = client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model="llama-3.3-70b-versatile",
            response_format={"type": "json_object"}
        )
        data = json.loads(completion.choices[0].message.content)
        return data.get("score", 0), data.get("feedback", {})
    except Exception as e:
        print(f"AI Grading Error: {e}")
        return 0, {"Error": "Grading failed"}